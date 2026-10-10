//! Native fixture, compiled only for the isolated same-image CLI/helper probe.
use crate::ipc::{self, WhiteboardHelperHandshake, WhiteboardIpcCommand, WhiteboardOwnerHandshake};
use hbb_common::{anyhow::{bail, ensure}, tokio, ResultType};
use std::{io::{Read, Write}, process::{Child, Command, Stdio}, time::Duration};

fn spawn_role_command(role: &'static str, envs: Vec<(&'static str, String)>, inherited_io: bool) -> ResultType<Child> {
    let mut command = if role == "--whiteboard" {
        let token = envs.iter().find(|(key, _)| *key == crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("fixture launch token is absent"))?;
        crate::whiteboard::whiteboard_helper_command(&token.1)?
    } else {
        let mut command = Command::new(std::env::current_exe()?);
        command.arg(role);
        crate::platform::linux::configure_command_kill_on_parent_death(&mut command)?;
        hbb_common::platform::linux::configure_command_close_nonstdio_on_exec(&mut command)?;
        command
    };
    command.env_clear().stdin(Stdio::null()).stdout(Stdio::null());
    if role == "--whiteboard" {
        if inherited_io {
            command.stdin(Stdio::inherit()).stdout(Stdio::inherit());
        } else {
            command.stdin(Stdio::piped()).stdout(Stdio::piped());
        }
    }
    for key in ["PATH", "LC_ALL", "HOME", "DISPLAY", "XDG_SESSION_TYPE", "XKB_CONFIG_ROOT", "LD_LIBRARY_PATH"] {
        command.env(key, std::env::var_os(key).ok_or_else(|| hbb_common::anyhow::anyhow!("fixture environment lacks {key}"))?);
    }
    command.envs(envs);
    Ok(command.spawn()?)
}

async fn spawn_role(role: &'static str, envs: Vec<(&'static str, String)>) -> ResultType<Child> {
    tokio::task::spawn_blocking(move || spawn_role_command(role, envs, false)).await?
}

async fn spawn_from_retired_thread(envs: Vec<(&'static str, String)>) -> ResultType<Child> {
    tokio::task::spawn_blocking(move || -> ResultType<Child> {
        let creator = std::thread::Builder::new().name("whiteboard-probe-creator".to_owned())
            .spawn(move || spawn_role_command("--whiteboard", envs, false))?;
        creator.join().map_err(|_| hbb_common::anyhow::anyhow!("fixture creator thread panicked"))?
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

async fn observer_ack(expected: &'static [u8]) -> ResultType<()> {
    tokio::task::spawn_blocking(move || -> ResultType<()> {
        let mut bytes = vec![0; expected.len()];
        std::io::stdin().read_exact(&mut bytes)?;
        ensure!(bytes == expected, "native window observer acknowledgment differs");
        Ok(())
    }).await??;
    Ok(())
}

async fn wait_cli_return(child: &mut Child) -> ResultType<()> {
    let mut output = child.stdout.take().ok_or_else(|| hbb_common::anyhow::anyhow!("helper output pipe is absent"))?;
    let mut reader = tokio::task::spawn_blocking(move || -> ResultType<()> {
        let mut bytes = [0; 9];
        output.read_exact(&mut bytes)?;
        ensure!(&bytes == b"returned\n", "helper did not report core CLI return");
        Ok(())
    });
    match tokio::time::timeout(Duration::from_secs(5), &mut reader).await {
        Ok(result) => result??,
        Err(_) => {
            let termination = child.kill();
            let joined = reader.await;
            termination?;
            bail!("helper CLI return timed out; joined reader: {joined:?}");
        }
    }
    ensure!(child.try_wait()?.is_none(), "helper died before its resources were observed");
    Ok(())
}

async fn overlay_phase(phase: &str, acknowledgement: &'static [u8]) -> ResultType<()> {
    println!("WHITEBOARD_HELPER_OVERLAY phase={phase}");
    std::io::stdout().flush()?;
    observer_ack(acknowledgement).await
}

async fn exercise(child: &mut Child, case: &str, token: &str, postfix: &str, address: &str) -> ResultType<()> {
    if let Some(status) = child.try_wait()? {
        bail!("helper exited after its creating thread joined: {status}");
    }
    println!("WHITEBOARD_HELPER_READY case={case} pid={} address_hex={}", child.id(), hex::encode(address));
    std::io::stdout().flush()?;
    observer_ack(b"go\n").await?;

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
        "shutdown" | "stream-close" | "window-close" | "creator-thread" => {
            ipc::authenticate_whiteboard_endpoint_launch_proof(&mut stream, token).await?;
            require_listener_refused(address).await?;
            if case == "shutdown" {
                stream.send_whiteboard_command_timeout(&WhiteboardIpcCommand::Shutdown, 1000).await?;
            } else if matches!(case, "window-close" | "creator-thread") {
                for (conn_id, x, y, argb) in [(7, 32.0, 32.0, 0xff00ff00), (8, 128.0, 96.0, 0xff0000ff)] {
                    let token = crate::encode64(&[conn_id as u8; 32]);
                    stream.send_whiteboard_command_timeout(&WhiteboardIpcCommand::Bind {
                        conn_id, token: token.clone(),
                    }, 1000).await?;
                    stream.send_whiteboard_command_timeout(&WhiteboardIpcCommand::Cursor {
                        conn_id, token, cursor: crate::whiteboard::Cursor {
                            x, y, argb, btns: 0, text: String::new(),
                        },
                    }, 1000).await?;
                }
                overlay_phase("draw", b"drawn\n").await?;
                stream.send_whiteboard_command_timeout(&WhiteboardIpcCommand::Close {
                    conn_id: 7, token: crate::encode64(&[7; 32]),
                }, 1000).await?;
                overlay_phase("clear", b"cleared\n").await?;
                if case == "window-close" {
                    overlay_phase("cancel", b"cancelled\n").await?;
                } else {
                    ensure!(child.try_wait()?.is_none(), "helper died after creator retirement and authenticated drawing");
                    println!("WHITEBOARD_HELPER_CREATOR=pass thread=joined owner=alive helper=live proof=mutual pixels=two-owner-clear");
                    stream.send_whiteboard_command_timeout(&WhiteboardIpcCommand::Close {
                        conn_id: 8, token: crate::encode64(&[8; 32]),
                    }, 1000).await?;
                    stream.send_whiteboard_command_timeout(&WhiteboardIpcCommand::Shutdown, 1000).await?;
                }
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
            }
        }
        _ => bail!("unknown whiteboard lifecycle case"),
    }
    // Keep proof-timeout and window-close streams alive until the real helper returns.
    let mut stream = if matches!(case, "proof-close" | "stream-close") {
        drop(stream);
        None
    } else {
        Some(stream)
    };
    wait_cli_return(child).await?;
    if let Some(stream) = stream.as_mut() {
        tokio::time::timeout(Duration::from_secs(1), stream.probe_whiteboard_eof()).await??;
    }
    require_listener_refused(address).await?;
    println!("WHITEBOARD_HELPER_RETURNED case={case} pid={} alive=true worker=absent stream=retired", child.id());
    std::io::stdout().flush()?;
    observer_ack(b"retired\n").await?;
    ensure!(child.try_wait()?.is_none(), "helper died before resource retirement acknowledgment");
    let mut input = child.stdin.take().ok_or_else(|| hbb_common::anyhow::anyhow!("helper input pipe is absent"))?;
    tokio::task::spawn_blocking(move || input.write_all(b"finish\n")).await??;
    wait_normal_exit(child).await
}

async fn client_generation() -> ResultType<()> {
    use crate::whiteboard::{probe_whiteboard_client_state, probe_whiteboard_helper, probe_whiteboard_helper_exit,
        register_whiteboard, unregister_whiteboard, update_whiteboard_cursor, WhiteboardClientOwner, Cursor};
    let case = std::env::var("WHITEBOARD_PROBE_CLIENT_GENERATION")?;
    ensure!(matches!(case.as_str(), "shutdown" | "replacement" | "withdrawal"), "invalid client case");
    let generations = if case == "shutdown" { 1 } else { 2 };
    ensure!(probe_whiteboard_client_state() == ("Idle", 0, false, 0)
        && probe_whiteboard_helper() == (None, false), "client fixture is not initially empty");
    let mut owner = WhiteboardClientOwner::new()?;
    let mut inspect = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    register_whiteboard(7);
    register_whiteboard(7);
    register_whiteboard(8);
    let exercise = async {
        let mut last_pid = 0;
        for expected_generation in 1..=generations {
            let ids = if expected_generation == 1 { [7, 8] }
                else if case == "replacement" { [9, 10] } else { [11, 12] };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let (phase, generation, task, connections) = probe_whiteboard_client_state();
                if phase == "Running" {
                    ensure!(generation == expected_generation && task && connections == 2,
                        "duplicate client demand did not retain one task/two connections");
                    break;
                }
                ensure!(phase == "Starting" && generation == expected_generation
                    && tokio::time::Instant::now() < deadline, "global client failed startup: {phase}/{generation}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let pid = probe_whiteboard_helper().0
                .ok_or_else(|| hbb_common::anyhow::anyhow!("global client lost its retained helper"))?;
            last_pid = pid;
            for id in ids { register_whiteboard(id); register_whiteboard(id); }
            println!("WHITEBOARD_CLIENT_READY case={case} generation={expected_generation} pid={pid} connections=2 task=retained");
            std::io::stdout().flush()?;
            observer_ack(b"go\n").await?;
            for (conn_id, x, y, argb) in [(ids[0], 32.0, 32.0, 0xff00ff00), (ids[1], 128.0, 96.0, 0xff0000ff)] {
                for _ in 0..4 {
                    update_whiteboard_cursor(conn_id, Cursor { x, y, argb, btns: 0, text: String::new() });
                }
            }
            overlay_phase("draw", b"drawn\n").await?;
            unregister_whiteboard(ids[0]);
            overlay_phase("clear", b"cleared\n").await?;
            unregister_whiteboard(ids[1]);
            // The helper owns inherited stdin until its CLI-return barrier is released.
            ensure!(tokio::time::timeout(Duration::from_secs(5), inspect.recv()).await?.is_some(),
                "client inspection signal ended");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            while !probe_whiteboard_helper().1 {
                ensure!(tokio::time::Instant::now() < deadline, "production owner did not join its command task");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if expected_generation == 1 && case != "shutdown" {
                for id in [9, 10] { register_whiteboard(id); register_whiteboard(id); }
                if case == "withdrawal" {
                    unregister_whiteboard(9);
                    unregister_whiteboard(10);
                }
                // Let the real owner run while the old helper remains behind its barrier.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let (phase, current, task, connections) = probe_whiteboard_client_state();
            let (helper, task_joined) = probe_whiteboard_helper();
            let expected_connections = if expected_generation == 1 && case == "replacement" { 2 } else { 0 };
            ensure!(phase == "Stopping" && current == expected_generation && !task
                && connections == expected_connections && helper == Some(pid) && task_joined,
                "committed stop lost its exact generation/helper or latched demand");
            println!("WHITEBOARD_CLIENT_STATE case={case} generation={current} phase={phase} task={task} connections={connections} expected_generation={expected_generation} pid={pid} task_joined={task_joined} helper_owned=true");
            std::io::stdout().flush()?;
            ensure!(tokio::time::timeout(Duration::from_secs(5), inspect.recv()).await?.is_some(),
                "client cleanup signal ended");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while probe_whiteboard_helper_exit() != Some((expected_generation, true)) {
                ensure!(tokio::time::Instant::now() < deadline, "production helper normal reap did not complete");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            println!("WHITEBOARD_CLIENT_REAPED case={case} generation={expected_generation} pid={pid} status=0 owner=production task=joined");
            std::io::stdout().flush()?;
            if expected_generation == 1 && case == "withdrawal" {
                let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
                while tokio::time::Instant::now() < deadline {
                    ensure!(probe_whiteboard_client_state() == ("Idle", 0, false, 0)
                        && probe_whiteboard_helper() == (None, false), "withdrawn demand started a successor");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                println!("WHITEBOARD_CLIENT_IDLE case=withdrawal retired_generation=1 observation_ms=500");
                std::io::stdout().flush()?;
                observer_ack(b"idle\n").await?;
                for id in [11, 12] { register_whiteboard(id); register_whiteboard(id); }
            }
        }
        Ok(last_pid)
    };
    let result = tokio::select! {
        result = exercise => result,
        _ = owner.run() => Err(hbb_common::anyhow::anyhow!("production whiteboard root ended unexpectedly")),
    };
    for id in [7, 8, 9, 10, 11, 12] { unregister_whiteboard(id); }
    owner.stop_and_join().await;
    let pid = result?;
    ensure!(probe_whiteboard_client_state() == ("Idle", 0, false, 0)
        && probe_whiteboard_helper() == (None, false)
        && probe_whiteboard_helper_exit() == Some((generations, true)), "production owner did not normally reap its helper");
    println!("WHITEBOARD_CLIENT_CLEANUP case={case} generation={generations} pid={pid} status=0 owner=production child=normal-exit-reaped task=joined");
    std::io::stdout().flush()?;
    Ok(())
}

pub async fn run() -> ResultType<()> {
    ensure!(unsafe { hbb_common::libc::geteuid() } == 1000, "native fixture requires UID 1000");
    if std::env::var_os("WHITEBOARD_PROBE_HELPER_PID").is_some() {
        return wrong_parent().await;
    }
    if std::env::var_os("WHITEBOARD_PROBE_CLIENT_GENERATION").is_some() {
        return client_generation().await;
    }
    if std::env::var_os("WHITEBOARD_PROBE_PARENT_EXIT").is_some() {
        let token = crate::encode64(&[8; 32]);
        let postfix = ipc::whiteboard_endpoint_postfix(&token)?;
        let address = ipc::linux_whiteboard_endpoint_address(&postfix)?;
        let mut child = tokio::task::spawn_blocking(move || spawn_role_command("--whiteboard", vec![
            (crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV, token),
            (crate::common::WHITEBOARD_LAUNCH_PARENT_ENV, std::process::id().to_string()),
            ("WHITEBOARD_PROBE_PARENT_EXIT", "1".to_owned()),
        ], true)).await??;
        println!("WHITEBOARD_HELPER_READY case=parent-exit pid={} address_hex={}", child.id(), hex::encode(address));
        std::io::stdout().flush()?;
        if let Err(err) = observer_ack(b"go\n").await {
            return reap(child, Err(err)).await;
        }
        if child.try_wait()?.is_some() {
            return reap(child, Err(hbb_common::anyhow::anyhow!("helper exited before its parent"))).await;
        }
        // Deliberate fixture parent-process exit. The observer becomes this child's subreaper.
        return Ok(());
    }
    for (index, case) in ["creator-thread", "shutdown", "bad-proof", "proof-timeout", "proof-close", "stream-close", "window-close"].into_iter().enumerate() {
        // Public fixture data, unique to each launch; this is never a product credential.
        let token = crate::encode64(&[index as u8 + 1; 32]);
        let postfix = ipc::whiteboard_endpoint_postfix(&token)?;
        let address = ipc::linux_whiteboard_endpoint_address(&postfix)?;
        let envs = vec![
            (crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV, token.clone()),
            (crate::common::WHITEBOARD_LAUNCH_PARENT_ENV, std::process::id().to_string()),
        ];
        let mut child = if case == "creator-thread" {
            spawn_from_retired_thread(envs).await?
        } else {
            spawn_role("--whiteboard", envs).await?
        };
        let pid = child.id();
        let result = exercise(&mut child, case, &token, &postfix, &address).await;
        reap(child, result).await?;
        require_listener_refused(&address).await?;
        println!("WHITEBOARD_HELPER_DONE case={case} pid={pid} status=0");
        std::io::stdout().flush()?;
    }
    Ok(())
}
