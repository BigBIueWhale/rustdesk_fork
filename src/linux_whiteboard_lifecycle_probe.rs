//! Native fixture, compiled only for the isolated same-image CLI/helper probe.
use crate::ipc::{self, WhiteboardHelperHandshake, WhiteboardIpcCommand, WhiteboardOwnerHandshake};
use hbb_common::{anyhow::{bail, ensure}, tokio, ResultType};
use std::{io::{Read, Write}, process::{Child, Command, Stdio}, time::Duration};

async fn spawn_role(role: &'static str, envs: Vec<(&'static str, String)>) -> ResultType<Child> {
    tokio::task::spawn_blocking(move || -> ResultType<Child> {
        let mut command = Command::new(std::env::current_exe()?);
        command.env_clear().arg(role).stdin(Stdio::null()).stdout(Stdio::null());
        for key in ["PATH", "LC_ALL", "HOME", "DISPLAY", "XDG_SESSION_TYPE", "XKB_CONFIG_ROOT", "LD_LIBRARY_PATH"] {
            command.env(key, std::env::var_os(key).ok_or_else(|| hbb_common::anyhow::anyhow!("fixture environment lacks {key}"))?);
        }
        command.envs(envs);
        crate::platform::linux::configure_command_kill_on_parent_death(&mut command)?;
        hbb_common::platform::linux::configure_command_close_nonstdio_on_exec(&mut command)?;
        Ok(command.spawn()?)
    }).await?
}

async fn wait_normal_exit(child: &mut Child) -> ResultType<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "owned child exited with {status}");
            return Ok(());
        }
        ensure!(tokio::time::Instant::now() < deadline, "owned child did not exit normally");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn reap(mut child: Child, result: ResultType<()>) -> ResultType<()> {
    // Retain ownership across errors. Forced cleanup never turns a failed case into a pass.
    tokio::task::spawn_blocking(move || -> ResultType<()> {
        let state = child.try_wait();
        let termination = match &state {
            Ok(Some(_)) => Ok(()),
            _ => child.kill(),
        };
        let joined = child.wait();
        state?;
        termination?;
        joined?;
        result
    }).await??;
    Ok(())
}

async fn require_listener_refused(address: &str) -> ResultType<()> {
    match tokio::time::timeout(Duration::from_secs(1), tokio::net::UnixStream::connect(address)).await? {
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
        _ => bail!("admitted helper retained its listener"),
    }
}

async fn wrong_parent() -> ResultType<()> {
    use tokio::io::AsyncReadExt;
    let postfix = ipc::whiteboard_endpoint_postfix_from_env()?;
    let address = ipc::linux_whiteboard_endpoint_address(&postfix)?;
    let mut stream = tokio::net::UnixStream::connect(address).await?;
    let expected_helper: i32 = std::env::var("WHITEBOARD_PROBE_HELPER_PID")?.parse()?;
    let peer = stream.peer_cred()?;
    ensure!(peer.uid() == 1000 && peer.pid() == Some(expected_helper), "wrong-parent fixture reached another helper");
    let mut byte = [0];
    ensure!(tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await?? == 0,
        "copied-token wrong parent received proof bytes");
    Ok(())
}

async fn exercise(child: &mut Child, case: &str, token: &str, postfix: &str, address: &str) -> ResultType<()> {
    println!("WHITEBOARD_HELPER_READY case={case} pid={} address_hex={}", child.id(), hex::encode(address));
    std::io::stdout().flush()?;
    let acknowledgement = tokio::task::spawn_blocking(|| -> std::io::Result<[u8; 3]> {
        let mut bytes = [0; 3];
        std::io::stdin().read_exact(&mut bytes)?;
        Ok(bytes)
    }).await??;
    ensure!(&acknowledgement == b"go\n", "native window observer did not acknowledge readiness");

    if case == "shutdown" {
        let mut peer = spawn_role("--server", vec![
            (crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV, token.to_owned()),
            (crate::common::WHITEBOARD_LAUNCH_PARENT_ENV, std::process::id().to_string()),
            ("WHITEBOARD_PROBE_HELPER_PID", child.id().to_string()),
        ]).await?;
        let result = wait_normal_exit(&mut peer).await;
        reap(peer, result).await?;
        println!("WHITEBOARD_HELPER_WRONG_PARENT=pass same_image=true role=server copied_token=true outcome=preproof-eof child=joined");
    }

    let mut stream = ipc::connect(1000, postfix).await?;
    ensure!(stream.peer_pid() == Some(child.id()), "owner reached another helper");
    match case {
        "shutdown" | "stream-close" => {
            ipc::authenticate_whiteboard_endpoint_launch_proof(&mut stream, token).await?;
            require_listener_refused(address).await?;
            if case == "shutdown" {
                stream.send_whiteboard_command_timeout(&WhiteboardIpcCommand::Shutdown, 1000).await?;
            } else {
                drop(stream);
            }
        }
        "bad-proof" | "proof-timeout" | "proof-close" => {
            ensure!(matches!(stream.next_whiteboard_helper_handshake_timeout(1000).await?,
                WhiteboardHelperHandshake::ServerChallenge { .. }), "kernel-admitted owner did not receive a challenge");
            require_listener_refused(address).await?;
            if case == "bad-proof" {
                stream.send_whiteboard_owner_handshake_timeout(&WhiteboardOwnerHandshake::ServerProof {
                    proof: crate::encode64(&[0; 32]),
                }, 1000).await?;
            } else if case == "proof-close" {
                drop(stream);
            }
        }
        _ => bail!("unknown whiteboard lifecycle case"),
    }
    // Keep a stalled proof stream alive through its deadline; EOF is a separate case.
    wait_normal_exit(child).await
}

pub async fn run() -> ResultType<()> {
    ensure!(unsafe { hbb_common::libc::geteuid() } == 1000, "native fixture requires UID 1000");
    if std::env::var_os("WHITEBOARD_PROBE_HELPER_PID").is_some() {
        return wrong_parent().await;
    }
    for (index, case) in ["shutdown", "bad-proof", "proof-timeout", "proof-close", "stream-close"].into_iter().enumerate() {
        // Public fixture data, unique to each launch; this is never a product credential.
        let token = crate::encode64(&[index as u8 + 1; 32]);
        let postfix = ipc::whiteboard_endpoint_postfix(&token)?;
        let address = ipc::linux_whiteboard_endpoint_address(&postfix)?;
        let mut child = spawn_role("--whiteboard", vec![
            (crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV, token.clone()),
            (crate::common::WHITEBOARD_LAUNCH_PARENT_ENV, std::process::id().to_string()),
        ]).await?;
        let pid = child.id();
        let result = exercise(&mut child, case, &token, &postfix, &address).await;
        reap(child, result).await?;
        require_listener_refused(&address).await?;
        println!("WHITEBOARD_HELPER_DONE case={case} pid={pid} status=0");
        std::io::stdout().flush()?;
    }
    Ok(())
}
