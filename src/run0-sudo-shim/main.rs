// SPDX-License-Identifier: BSD-3-Clause

use std::{
    env,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::{fs::OpenOptionsExt as _, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio, exit},
};

use clap::Parser;
use users::get_current_uid;

mod args;
mod common;
mod sudo;

use crate::args::*;
use crate::common::*;

impl Cli {
    pub fn parse_to_run0_cli(
        self,
        cwd: Option<String>,
        current_uid: users::uid_t,
        current_env: Vec<String>,
    ) -> Run0Cli {
        match self.command {
            crate::Commands::Sudo(args) => Run0Cli::new(
                sudo::parse_to_run0_cli(args, cwd, current_uid, current_env),
                clap::Command::new("sudo"),
            ),
        }
    }
}

/// Resolve a path to an absolute path.
///
/// Directory components are canonicalized (symlinks resolved), but the final
/// component is left as-is so that a subsequent `reject_symlink` check is
/// meaningful.
fn resolve_path(path: &str) -> Result<PathBuf, String> {
    let p = Path::new(path);
    let parent = p.parent().unwrap_or_else(|| Path::new("."));
    let filename = p
        .file_name()
        .ok_or_else(|| format!("invalid path: {path}"))?;

    let parent_resolved = if parent.as_os_str().is_empty() {
        env::current_dir().map_err(|e| format!("failed to get current directory: {e}"))?
    } else {
        parent
            .canonicalize()
            .map_err(|e| format!("failed to resolve {}: {e}", parent.display()))?
    };

    Ok(parent_resolved.join(filename))
}

/// Refuse to operate on symlinks to prevent symlink-target redirection attacks.
fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_symlink() => Err(format!(
            "{}: editing symbolic links is not permitted",
            path.display()
        )),
        _ => Ok(()),
    }
}

/// Create a temporary file with a random name, atomically (`O_CREAT|O_EXCL`)
/// and with mode 0600 from the start.
fn create_temp_file(dir: &str, prefix: &str) -> Result<(File, PathBuf), String> {
    let mut rand_bytes = [0_u8; 8];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut rand_bytes))
        .map_err(|e| format!("failed to generate random name: {e}"))?;

    let suffix = rand_bytes
        .iter()
        .fold(String::with_capacity(16), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    let path = PathBuf::from(format!("{dir}/sudoedit-{prefix}.{suffix}"));

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("failed to create temp file: {e}"))?;

    Ok((file, path))
}

/// Read a file, falling back to `run0 cat` when permission is denied.
/// Returns an empty Vec for non-existent files (new file being created).
fn read_file_content(path: &Path) -> Result<Vec<u8>, String> {
    match fs::read(path) {
        Ok(content) => Ok(content),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            let output = Command::new(RUN0_CMD)
                .args(["--", "cat", "--"])
                .arg(path)
                .output()
                .map_err(|e| format!("failed to run run0: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "failed to read {}: {}",
                    path.display(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Ok(output.stdout)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("failed to read {}: {e}", path.display())),
    }
}

/// Write content to a privileged path via `run0 tee`.
fn write_file_privileged(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut child = Command::new(RUN0_CMD)
        .args(["--", "tee", "--"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to run run0: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(content)
            .map_err(|e| format!("failed to write to run0 tee: {e}"))?;
    }

    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for run0: {e}"))?;
    if !status.success() {
        return Err(format!(
            "failed to write {}: run0 tee exited with {status}",
            path.display()
        ));
    }

    Ok(())
}

struct EditEntry {
    original: PathBuf,
    tmppath: PathBuf,
    content: Vec<u8>,
}

fn sudoedit(files: &[String], editor: &str) -> Result<(), String> {
    let tmpdir = env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());

    let mut entries: Vec<EditEntry> = Vec::new();
    for file in files {
        let original = resolve_path(file)?;
        reject_symlink(&original)?;

        let prefix = original
            .file_name()
            .map_or_else(|| "sudoedit".to_owned(), |s| s.to_string_lossy().into_owned());

        let content = read_file_content(&original)?;

        let (mut tmpfile, tmppath) = create_temp_file(&tmpdir, &prefix)?;
        tmpfile
            .write_all(&content)
            .map_err(|e| format!("failed to write temp file: {e}"))?;
        drop(tmpfile);

        entries.push(EditEntry {
            original,
            tmppath,
            content,
        });
    }

    // Use sh -c so $EDITOR values containing arguments (e.g. "code --wait") are handled.
    let editor_cmd = format!("{editor} \"$@\"");
    let status = Command::new("sh")
        .args(["-c", &editor_cmd, "--"])
        .args(entries.iter().map(|e| &e.tmppath))
        .status()
        .map_err(|e| format!("failed to launch editor: {e}"))?;

    if !status.success() {
        for entry in &entries {
            let _ = fs::remove_file(&entry.tmppath);
        }
        return Err(format!("editor exited with status: {status}"));
    }

    let mut had_error = false;
    for entry in &entries {
        let edited = match fs::read(&entry.tmppath) {
            Ok(data) => data,
            Err(e) => {
                eprintln!(
                    "sudoedit: failed to read back {}: {e}",
                    entry.tmppath.display()
                );
                had_error = true;
                continue;
            }
        };

        if edited == entry.content {
            let _ = fs::remove_file(&entry.tmppath);
            continue;
        }

        // Re-check for symlink before writing back (defense in depth).
        if let Err(e) = reject_symlink(&entry.original) {
            eprintln!("sudoedit: {e}");
            eprintln!(
                "sudoedit: contents of edit session left in {}",
                entry.tmppath.display()
            );
            had_error = true;
            continue;
        }

        if let Err(e) = write_file_privileged(&entry.original, &edited) {
            eprintln!("sudoedit: {}: {e}", entry.original.display());
            eprintln!(
                "sudoedit: contents of edit session left in {}",
                entry.tmppath.display()
            );
            had_error = true;
            continue;
        }

        let _ = fs::remove_file(&entry.tmppath);
    }

    if had_error {
        return Err("some files could not be written back".to_owned());
    }

    Ok(())
}

fn is_sudoedit() -> bool {
    env::args_os()
        .next()
        .and_then(|a| Path::new(&a).file_name().map(OsStr::to_os_string))
        .is_some_and(|name| name == "sudoedit")
}

fn main() {
    let cli = Cli::parse();

    let crate::Commands::Sudo(sudo_args) = &cli.command;
    if sudo_args.edit || is_sudoedit() {
        let files = sudo_args.command.as_deref().unwrap_or_default();
        if files.is_empty() {
            die("sudoedit: no files specified");
        }

        let editor = env::var("SUDO_EDITOR")
            .or_else(|_| env::var("VISUAL"))
            .or_else(|_| env::var("EDITOR"))
            .unwrap_or_else(|_| String::from("vi"));

        if let Err(e) = sudoedit(files, &editor) {
            die(&format!("sudoedit: {e}"));
        }

        exit(0);
    }

    let cwd = env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .ok();

    let env = env::vars().map(|(key, _)| key).collect();

    let mut cli = cli
        .parse_to_run0_cli(cwd, get_current_uid(), env)
        .finalize()
        .into_iter();

    let program = cli.next().unwrap_or_else(|| die("unable to construct cli"));

    let error = Command::new(program).args(cli).exec();

    die(&format!("failed to execute run0: {error}"));
}
