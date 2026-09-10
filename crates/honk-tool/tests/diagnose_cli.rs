use std::os::unix::fs::PermissionsExt;
use std::process::Output;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

fn diagnose(api: &str) -> (tempfile::TempDir, Command) {
    let dir = tempfile::tempdir().unwrap();
    let ip = dir.path().join("ip");
    std::fs::write(
        &ip,
        "#!/bin/sh\nprintf '100: fwmark 0x8000000 lookup 100\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(&ip, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_honk-tool"));
    command
        .args(["diagnose", "--api", api, "--pin-root"])
        .arg(dir.path().join("missing-pins"))
        .env("PATH", dir.path())
        .env_remove("HONK_API_SECRET");
    (dir, command)
}

async fn api_check(required_secret: Option<&str>, flag: Option<&str>, env: Option<&str>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let authorization = required_secret.map(|secret| format!("Bearer {secret}"));
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut authorized = authorization.is_none();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("Authorization")
                && authorization.as_deref() == Some(value.trim())
            {
                authorized = true;
            }
        }
        let (status, body) = if authorized {
            ("200 OK", r#"{"version":"diagnose-fixture"}"#)
        } else {
            ("401 Unauthorized", "unauthorized")
        };
        reader
            .get_mut()
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let (_dir, mut command) = diagnose(&api);
    if let Some(secret) = flag {
        command.args(["--secret", secret]);
    }
    if let Some(secret) = env {
        command.env("HONK_API_SECRET", secret);
    }
    let out = command.output().await.unwrap();
    server.abort();
    String::from_utf8(out.stdout)
        .unwrap()
        .replace(&api, "<api>")
}

#[tokio::test]
async fn api_authentication_and_secret_precedence() {
    let mut lines = Vec::new();
    for (flag, env) in [
        (None, None),
        (Some("expected"), None),
        (None, Some("expected")),
        (Some("expected"), Some("wrong")),
    ] {
        let stdout = api_check(Some("expected"), flag, env).await;
        lines.push(
            stdout
                .lines()
                .find(|line| line.contains("clash API"))
                .unwrap_or("API check not reached")
                .to_owned(),
        );
    }
    assert!(lines[0].starts_with("[FAIL] clash API <api>:"), "{lines:?}");
    assert!(lines[0].contains("401 Unauthorized"), "{lines:?}");
    for line in &lines[1..] {
        assert_eq!(
            line,
            "[ok] clash API <api>: {\"version\":\"diagnose-fixture\"}"
        );
    }
}

#[tokio::test]
async fn unauthenticated_api_success() {
    let stdout = api_check(None, None, None).await;
    assert!(stdout.contains("[ok] clash API <api>:"), "{stdout}");
    assert!(
        stdout.contains(r#"{"version":"diagnose-fixture"}"#),
        "{stdout}"
    );
}

#[tokio::test]
async fn failed_checks_print_summary_and_exit_one() {
    let (_dir, mut command) = diagnose("");
    let Output {
        status,
        stdout,
        stderr,
    } = command.output().await.unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    let stderr = String::from_utf8(stderr).unwrap();
    let summary = stderr.trim_end();
    let count: usize = summary
        .strip_prefix("Error: diagnose: ")
        .unwrap()
        .strip_suffix(" issue(s) found")
        .unwrap()
        .parse()
        .unwrap();
    assert!(count > 0, "{stderr}");
    assert_eq!(status.code(), Some(1), "{stdout}");
    assert_eq!(
        format!("{stdout}{stderr}")
            .matches("issue(s) found")
            .count(),
        1,
        "{stdout}{stderr}"
    );
}
