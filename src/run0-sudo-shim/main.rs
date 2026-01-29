mod args;
use std::{
    env,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::{fs::OpenOptionsExt as _, process::CommandExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio, exit},
};

use crate::args::Cli;
use clap::Parser as _;

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
        .create_new(true) // O_CREAT | O_EXCL: atomic, fails if path already exists
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
            let output = Command::new("run0")
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
///
/// `tee` opens the existing file for writing, preserving ownership and
/// permissions.  stdout is discarded since we only care about the file write.
fn write_file_privileged(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut child = Command::new("run0")
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

/// Entry representing one file being edited: the original path, its temp copy,
/// and the content read before editing.
struct EditEntry {
    original: PathBuf,
    tmppath: PathBuf,
    content: Vec<u8>,
}

fn sudoedit(files: &[String], editor: &str) -> Result<(), String> {
    let tmpdir = env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());

    // Phase 1: validate paths, read originals, create temp copies.
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

    // Phase 2: launch editor on all temp files at once.
    // Use sh -c so that $EDITOR values containing arguments (e.g. "code --wait")
    // are handled correctly.
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

    // Phase 3: write back changed files.
    // On write failure, leave the temp file so the user can recover their edits.
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
        .and_then(|a| {
            Path::new(&a)
                .file_name()
                .map(OsStr::to_os_string)
        })
        .is_some_and(|name| name == "sudoedit")
}

fn main() {
    let cli = Cli::parse();

    if cli.edit || is_sudoedit() {
        let files: Vec<String> = cli.command;
        if files.is_empty() {
            eprintln!("sudoedit: no files specified");
            exit(1);
        }

        let editor = env::var("SUDO_EDITOR")
            .or_else(|_| env::var("VISUAL"))
            .or_else(|_| env::var("EDITOR"))
            .unwrap_or_else(|_| String::from("vi"));

        if let Err(e) = sudoedit(&files, &editor) {
            eprintln!("sudoedit: {e}");
            exit(1);
        }

        exit(0);
    }

    assert!(
        !(cli.list > 0 || cli.other_user.is_some()),
        "`list` mode is currently unsupported!"
    );

    assert!(cli.chroot.is_none(), "`chroot` is currently unsupported!");

    assert!(
        !cli.stdin,
        "passwords via `stdin` are currently unsupported!"
    );

    let command = if cli.validate {
        vec![String::from("true")]
    } else {
        cli.command
    };

    let chdir = cli.working_directory.map(|wd| format!("--chdir={wd}"));

    let non_interactive = cli.non_interactive.then_some("--no-ask-password");

    let group = cli
        .group
        .map(|g| format!("--group={}", g.trim_start_matches('#')));
    let user = cli
        .user
        .map(|u| format!("--user={}", u.trim_start_matches('#')));

    let env_flags = cli.preserve_env.map_or_else(Vec::new, |vars| {
        let vars = if vars.is_empty() {
            env::vars().map(|(key, _)| key).collect()
        } else {
            vars
        };

        vars.iter()
            .filter(|e| !(cli.set_home && *e == "HOME"))
            .map(|e| format!("--setenv={e}"))
            .collect()
    });

    let nofile = cli
        .file_descriptor_limit
        .map(|limit_nofile| format!("--property=LimitNOFILE={limit_nofile}"));

    if command.is_empty() && !cli.login {
        let mut cmd = clap::Command::new(env!("CARGO_PKG_NAME"));
        cmd.print_help().expect("help should not panic");
        exit(0);
    }

    if cli.bell && !cli.non_interactive {
        print!("\x07");
    }

    let error = Command::new("run0")
        .args(chdir.iter())
        .args(non_interactive.iter())
        .args(group.iter())
        .args(user.iter())
        .args(nofile.iter())
        .args(env_flags)
        .args(command)
        .exec();

    panic!("{error}");
}
