//! Chrome Native Messaging host bridge (`AUTO-11`) and setup/status CLI (`AUTO-14`).

mod cli;
mod extension_id;
mod manifest;
mod pipe_client;
mod relay;
mod setup;
#[cfg(test)]
mod tests;

use std::io;
use std::process;

use cli::Command;
use pipe_client::{verify_browser_relay_caller, PipeClient};

fn run() -> anyhow::Result<()> {
    match cli::parse_args()? {
        Command::Relay(args) => {
            verify_browser_relay_caller(&args)?;
            // In relay mode Chrome treats any byte on stdout as a 4-byte LE frame header;
            // keep all diagnostic logging strictly on stderr.
            let stdin = io::stdin();
            let stdout = io::stdout();
            let stderr = io::stderr();
            let mut stdin_lock = stdin.lock();
            let mut stdout_lock = stdout.lock();
            let mut stderr_lock = stderr.lock();
            let client = PipeClient::new(&args.pipe_name);
            let _stats = relay::run_relay_loop(
                &mut stdin_lock,
                &mut stdout_lock,
                &mut stderr_lock,
                &client,
            )?;
            Ok(())
        }
        Command::Setup(args) => {
            let outcome = setup::run_setup(&args)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                println!("{}", setup::format_setup_text(&outcome));
            }
            Ok(())
        }
        Command::Unregister(args) => {
            let outcome = setup::run_unregister(&args)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                println!("{}", setup::format_unregister_text(&outcome));
            }
            Ok(())
        }
        Command::Status(args) => {
            let report = setup::run_status(&args)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", setup::format_status_text(&report));
            }
            Ok(())
        }
        Command::Help => {
            print!("{}", cli::usage_text());
            Ok(())
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[ledr-bridge-nm] error: {err:#}");
        process::exit(1);
    }
}
