use crate::error::Error;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};

/// Generate a passwordless self-signed certificate in the `"tls"` subdirectory
/// of the specified directory.
pub fn generate_tls_data(
    temp_dir: &(String, PathBuf),
) -> Result<((String, PathBuf), String), Error> {
    fn err<M: fmt::Display>(which: bool, op: &'static str, more: M) -> Error {
        Error(format!(
            "{} {}: {}",
            op,
            if which {
                "TLS key generation process"
            } else {
                "TLS identity generation process"
            },
            more
        ))
    }

    fn exit_err(which: bool, process: &mut Child, exitc: &ExitStatus) -> Error {
        let mut stdout = String::new();
        let mut stderr = String::new();
        if process
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut stdout)
            .is_err()
        {
            stdout = "<error getting process stdout>".to_string();
        }
        if process
            .stderr
            .as_mut()
            .unwrap()
            .read_to_string(&mut stderr)
            .is_err()
        {
            stderr = "<error getting process stderr>".to_string();
        }

        err(
            which,
            "Exiting",
            format_args!(
                "{};\nstdout: ```\n{}```;\nstderr: ```\n{}```",
                exitc, stdout, stderr
            ),
        )
    }

    let tls_dir = temp_dir.1.join("tls");
    fs::create_dir_all(&tls_dir)
        .map_err(|err| Error(format!("Creating temporary directory: {}", err)))?;

    // Generate key + cert
    let mut child = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:4096", "-nodes", "-keyout", "tls.key", "-out",
            "tls.crt", "-days", "3650", "-utf8",
        ])
        .current_dir(&tls_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| err(true, "Spawning", error))?;

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            concat!(
                "PL\nhpip\n",
                env!("CARGO_PKG_VERSION"),
                "\nhpip\nhpip\nhpip/",
                env!("CARGO_PKG_VERSION"),
                "\nhpip@localhost\n"
            )
            .as_bytes(),
        )
        .map_err(|error| err(true, "Piping", error))?;

    let es = child.wait().map_err(|error| err(true, "Waiting", error))?;
    if !es.success() {
        return Err(exit_err(true, &mut child, &es));
    }

    // Convert to PKCS12
    let mut child = Command::new("openssl")
        .args([
            "pkcs12",
            "-export",
            "-out",
            "tls.p12",
            "-inkey",
            "tls.key",
            "-in",
            "tls.crt",
            "-passin",
            "pass:",
            "-passout",
            if cfg!(target_os = "macos") {
                "pass:password"
            } else {
                "pass:"
            },
        ])
        .current_dir(&tls_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| err(false, "Spawning", error))?;

    let es = child.wait().map_err(|error| err(false, "Waiting", error))?;
    if !es.success() {
        return Err(exit_err(false, &mut child, &es));
    }

    Ok((
        (
            format!("{}/tls/tls.p12", temp_dir.0),
            tls_dir.join("tls.p12"),
        ),
        if cfg!(target_os = "macos") {
            "password"
        } else {
            ""
        }
        .to_string(),
    ))
}

use std::io::Write;
