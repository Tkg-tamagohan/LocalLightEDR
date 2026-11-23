use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use ledr_auth_helper::{
    inspect_authenticode, read_framed_json, write_framed_json, AuthVerifyRequest,
    AuthVerifyResponse, DEFAULT_IDLE_TIMEOUT_MS,
};

fn parse_idle_timeout_ms<I, S>(args: I) -> Result<u64, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter().skip(1);
    let mut idle_ms = DEFAULT_IDLE_TIMEOUT_MS;
    while let Some(arg) = iter.next() {
        let s = arg.as_ref();
        if s == "--idle-timeout-ms" {
            let val = iter
                .next()
                .ok_or_else(|| "--idle-timeout-ms requires a value".to_string())?;
            let parsed: u64 = val
                .as_ref()
                .parse()
                .map_err(|err| format!("invalid --idle-timeout-ms: {err}"))?;
            idle_ms = parsed.max(50);
        } else {
            return Err(format!("unknown argument: {s}"));
        }
    }
    Ok(idle_ms)
}

fn log_stderr(msg: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "ledr-auth-helper: {msg}");
}

fn main() {
    let idle_ms = match parse_idle_timeout_ms(std::env::args()) {
        Ok(ms) => ms,
        Err(err) => {
            log_stderr(&err);
            std::process::exit(2);
        }
    };
    let idle_timeout = Duration::from_millis(idle_ms);

    let (tx, rx) = mpsc::sync_channel::<io::Result<AuthVerifyRequest>>(1);
    std::thread::Builder::new()
        .name("auth-helper-stdin".to_string())
        .spawn(move || {
            let mut stdin = io::stdin().lock();
            loop {
                let res = read_framed_json::<_, AuthVerifyRequest>(&mut stdin);
                let is_err = res.is_err();
                if tx.send(res).is_err() || is_err {
                    break;
                }
            }
        })
        .expect("spawn auth-helper-stdin thread");

    let mut stdout = io::stdout().lock();
    loop {
        match rx.recv_timeout(idle_timeout) {
            Ok(Ok(req)) => {
                let authenticode = inspect_authenticode(Path::new(&req.exe_path));
                let resp = AuthVerifyResponse {
                    id: req.id,
                    authenticode,
                };
                if let Err(err) = write_framed_json(&mut stdout, &resp) {
                    if err.kind() != io::ErrorKind::BrokenPipe {
                        log_stderr(&format!("stdout write failed: {err}"));
                    }
                    std::process::exit(0);
                }
            }
            Ok(Err(err)) => {
                if err.kind() != io::ErrorKind::UnexpectedEof
                    && err.kind() != io::ErrorKind::BrokenPipe
                {
                    log_stderr(&format!("stdin read failed: {err}"));
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
                std::process::exit(0);
            }
        }
    }
}
