/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
 */
use anyhow::Context;
use clap::{crate_name, crate_version};
use vsmtp::{Args, Commands};
use vsmtp_common::libc_abstraction::{daemon, initgroups};
use vsmtp_config::Config;
use vsmtp_server::{socket_bind_anyhow, start_runtime};

fn main() {
    if let Err(err) = try_main() {
        let error = format!("vSMTP terminating error: '{err}'");

        eprintln!("{error}");
        tracing::error!(error);
        err.chain().skip(1).for_each(|cause| {
            let reason = format!("because: {cause}");

            eprintln!("{reason}");
            tracing::error!(reason);
        });
        std::process::exit(1);
    }
}

fn bind_sockets(addr: &[std::net::SocketAddr]) -> anyhow::Result<Vec<std::net::TcpListener>> {
    addr.iter()
        .cloned()
        .map(socket_bind_anyhow)
        .collect::<anyhow::Result<Vec<std::net::TcpListener>>>()
}

fn try_main() -> anyhow::Result<()> {
    let args = <Args as clap::StructOpt>::parse();

    if args.version {
        println!(
            "{} v{}\ncommit: {}",
            crate_name!(),
            crate_version!(),
            env!("GIT_HASH")
        );
        return Ok(());
    }

    let config = args.config.as_ref().map_or_else(
        || Ok(Config::default()),
        |config| {
            std::fs::read_to_string(&config)
                .context(format!("Cannot read file '{}'", config))
                .and_then(|f| Config::from_toml(&f).context("File contains format error"))
                .context("Cannot parse the configuration")
        },
    )?;

    if let Some(command) = args.command {
        match command {
            Commands::ConfigShow => {
                let stringified = serde_json::to_string_pretty(&config)?;
                println!("Loaded configuration: {}", stringified);
                return Ok(());
            }
            Commands::ConfigDiff => {
                let loaded_config = serde_json::to_string_pretty(&config)?;
                let default_config = serde_json::to_string_pretty(&Config::default())?;
                for diff in diff::lines(&default_config, &loaded_config) {
                    match diff {
                        diff::Result::Left(left) => println!("-\x1b[0;31m{left}\x1b[0m"),
                        diff::Result::Both(same, _) => println!(" {same}"),
                        diff::Result::Right(right) => println!("+\x1b[0;32m{right}\x1b[0m"),
                    }
                }
                return Ok(());
            }
        }
    }

    vsmtp::tracing_subscriber::initialize(&args, &config)?;

    tracing::info!(
        server = ?config.server.logs.filepath,
        app = ?config.app.logs.filepath,
        syslog = config
        .server
        .logs
        .system
        .as_ref()
        .map(|sys| sys.to_string())
        .unwrap_or_else(|| "None".to_string()),
        "vSMTP logs initialized: ",
    );

    let sockets = (
        bind_sockets(&config.server.interfaces.addr)?,
        bind_sockets(&config.server.interfaces.addr_submission)?,
        bind_sockets(&config.server.interfaces.addr_submissions)?,
    );

    if !args.no_daemon {
        daemon(false, false)?;
        initgroups(
            config.server.system.user.name().to_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "user '{:?}' is not UTF-8 valid",
                    config.server.system.user.name()
                )
            })?,
            config.server.system.group.gid(),
        )?;
        // setresgid ?
        // setgid(config.server.system.group.gid())?;
        // setresuid ?
        // setuid(config.server.system.user.uid())?;
    }

    start_runtime(config, sockets, args.timeout.map(|t| t.0))
}
