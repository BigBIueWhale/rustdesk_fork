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
        tokio::time::timeout(Duration::from_secs(1), stream.wait_whiteboard_helper_eof()).await??;
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

async fn launch_owner_loss(mut owner: crate::whiteboard::WhiteboardClientController) -> ResultType<()> {
    use crate::whiteboard::{probe_whiteboard_client_state, probe_whiteboard_helper,
        probe_whiteboard_helper_endpoint, probe_whiteboard_launch_state, probe_release_whiteboard_launch,
        probe_whiteboard_owner_loss, register_whiteboard, WhiteboardClientRoot};
    struct LaunchGate;
    impl Drop for LaunchGate {
        fn drop(&mut self) { probe_release_whiteboard_launch(); }
    }
    let _release = LaunchGate;
    register_whiteboard(7);
    register_whiteboard(8);
    let waiting = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let (Some(pid), false) = probe_whiteboard_launch_state() { return Ok(pid); }
            ensure!(tokio::time::Instant::now() < deadline, "real whiteboard launch did not reach its barrier");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let result: ResultType<u32> = waiting.await;
    if result.is_err() {
        probe_release_whiteboard_launch();
        owner.stop_and_join().await;
    }
    let pid = result?;
    ensure!(probe_whiteboard_client_state() == ("Starting", 1, false, 2)
        && probe_whiteboard_helper() == (None, false), "launch was handed off before the owner-loss barrier");
    println!("WHITEBOARD_CLIENT_LAUNCH_BLOCKED generation=1 pid={pid} address_hex={}",
        hex::encode(probe_whiteboard_helper_endpoint()?));
    std::io::stdout().flush()?;
    let result = observer_ack(b"drop\n").await;
    if result.is_err() {
        probe_release_whiteboard_launch();
        owner.stop_and_join().await;
    }
    result?;
    drop(owner);
    register_whiteboard(9);
    register_whiteboard(10);
    ensure!(probe_whiteboard_client_state() == ("Stopping", 1, false, 0)
        && probe_whiteboard_helper() == (None, false)
        && probe_whiteboard_launch_state() == (Some(pid), false)
        && WhiteboardClientRoot::new().is_err(), "dropped launch owner admitted replacement or lost its job");
    println!("WHITEBOARD_CLIENT_LAUNCH_DROPPED generation=1 pid={pid} phase=Stopping launch=retained helper=unpublished replacement=refused");
    std::io::stdout().flush()?;
    let result = observer_ack(b"release\n").await;
    probe_release_whiteboard_launch();
    result?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while probe_whiteboard_client_state() != ("Idle", 0, false, 0) {
        ensure!(tokio::time::Instant::now() < deadline, "cancelled real launch did not finish retirement");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ensure!(probe_whiteboard_owner_loss().1
        && probe_whiteboard_helper() == (None, false) && WhiteboardClientRoot::new().is_err(),
        "late launch publication escaped orphaned ownership");
    println!("WHITEBOARD_CLIENT_LAUNCH_FINISHED generation=1 pid={pid} phase=Idle task=false launch=joined helper=unpublished replacement=refused");
    std::io::stdout().flush()?;
    observer_ack(b"observed\n").await?;
    println!("WHITEBOARD_CLIENT_LAUNCH_OWNER_LOSS_DONE generation=1 pid={pid} parent=alive launch=joined admission=refused");
    std::io::stdout().flush()?;
    observer_ack(b"done\n").await?;
    Ok(())
}

async fn published_owner_loss(mut owner: crate::whiteboard::WhiteboardClientController) -> ResultType<()> {
    use crate::whiteboard::{probe_whiteboard_client_state, probe_whiteboard_helper,
        probe_whiteboard_helper_endpoint, probe_whiteboard_owner_loss, register_whiteboard,
        probe_whiteboard_helper_exit, update_whiteboard_cursor, Cursor, WhiteboardClientRoot};
    register_whiteboard(7);
    register_whiteboard(8);
    let exercise = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while probe_whiteboard_client_state() != ("Running", 1, true, 2) {
            ensure!(tokio::time::Instant::now() < deadline, "published owner-loss helper did not start");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid = probe_whiteboard_helper().0
            .ok_or_else(|| hbb_common::anyhow::anyhow!("published owner-loss helper is absent"))?;
        println!("WHITEBOARD_CLIENT_READY case=owner-loss generation=1 pid={pid} connections=2 task=retained");
        std::io::stdout().flush()?;
        observer_ack(b"go\n").await?;
        for (conn_id, x, y, argb) in [(7, 32.0, 32.0, 0xff00ff00), (8, 128.0, 96.0, 0xff0000ff)] {
            update_whiteboard_cursor(conn_id, Cursor { x, y, argb, btns: 0, text: String::new() });
        }
        overlay_phase("draw", b"drawn\n").await?;
        ensure!(probe_whiteboard_client_state() == ("Running", 1, true, 2)
            && probe_whiteboard_helper() == (Some(pid), false), "owner loss missed its published Running helper");
        println!("WHITEBOARD_CLIENT_OWNER_LOSS_READY generation=1 pid={pid} address_hex={}",
            hex::encode(probe_whiteboard_helper_endpoint()?));
        std::io::stdout().flush()?;
        observer_ack(b"drop\n").await?;
        Ok::<u32, hbb_common::anyhow::Error>(pid)
    };
    let result = exercise.await;
    if result.is_err() { owner.stop_and_join().await; }
    let pid = result?;
    drop(owner);
    register_whiteboard(9);
    register_whiteboard(10);
    ensure!(probe_whiteboard_owner_loss().2 && WhiteboardClientRoot::new().is_err(),
        "dropped owner admitted registrations or a replacement controller");
    println!("WHITEBOARD_CLIENT_OWNER_LOSS_DROPPED generation=1 pid={pid} admission=refused replacement=refused");
    std::io::stdout().flush()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while probe_whiteboard_client_state() != ("Idle", 0, false, 0) {
        ensure!(tokio::time::Instant::now() < deadline, "retained process owner did not join/reap after controller loss");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_, joined, refused) = probe_whiteboard_owner_loss();
    ensure!(joined && refused && WhiteboardClientRoot::new().is_err()
        && probe_whiteboard_helper_exit() == Some((1, false)), "owner-loss completion lost retirement or reopened admission");
    println!("WHITEBOARD_CLIENT_OWNER_LOSS_FINISHED generation=1 pid={pid} task_finished=true task_joined={joined}");
    std::io::stdout().flush()?;
    observer_ack(b"observed\n").await?;
    println!("WHITEBOARD_CLIENT_OWNER_LOSS_DONE generation=1 pid={pid} parent=alive admission=refused replacement=refused");
    std::io::stdout().flush()?;
    observer_ack(b"done\n").await?;
    Ok(())
}

async fn exercise_client_generation(mut owner: crate::whiteboard::WhiteboardClientController, case: String) -> ResultType<()> {
    use crate::whiteboard::{probe_whiteboard_client_state, probe_whiteboard_helper, probe_whiteboard_helper_exit, probe_whiteboard_helper_endpoint,
        register_whiteboard, unregister_whiteboard, update_whiteboard_cursor, Cursor};
    if case == "launch-owner-loss" { return launch_owner_loss(owner).await; }
    if case == "owner-loss" { return published_owner_loss(owner).await; }
    ensure!(matches!(case.as_str(), "shutdown" | "replacement" | "withdrawal" | "helper-close" | "helper-crash" | "root-shutdown" | "parent-loss"), "invalid client case");
    let generations = if matches!(case.as_str(), "shutdown" | "root-shutdown" | "parent-loss") { 1 } else { 2 };
    ensure!(probe_whiteboard_client_state() == ("Idle", 0, false, 0)
        && probe_whiteboard_helper() == (None, false), "client fixture is not initially empty");
    let mut inspect = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let root_shutdown = tokio::sync::Notify::new();
    register_whiteboard(7);
    register_whiteboard(7);
    register_whiteboard(8);
    let exercise = async {
        let mut last_pid = 0;
        for expected_generation in 1..=generations {
            let ids = if expected_generation == 1 || matches!(case.as_str(), "helper-close" | "helper-crash") { [7, 8] }
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
            if case == "parent-loss" {
                ensure!(probe_whiteboard_client_state() == ("Running", expected_generation, true, 2)
                    && probe_whiteboard_helper() == (Some(pid), false),
                    "parent loss missed its active Running generation");
                println!("WHITEBOARD_CLIENT_PARENT_LOSS_READY generation=1 pid={pid} address_hex={}",
                    hex::encode(probe_whiteboard_helper_endpoint()?));
                std::io::stdout().flush()?;
                tokio::time::sleep(Duration::from_secs(10)).await;
                bail!("observer did not terminate the exact active parent");
            } else if expected_generation == 1 && case == "helper-crash" {
                ensure!(probe_whiteboard_client_state() == ("Running", expected_generation, true, 2)
                    && probe_whiteboard_helper() == (Some(pid), false),
                    "helper crash missed its active Running generation");
                println!("WHITEBOARD_CLIENT_HELPER_LOSS_READY generation=1 pid={pid} address_hex={}",
                    hex::encode(probe_whiteboard_helper_endpoint()?));
                std::io::stdout().flush()?;
                observer_ack(b"killed\n").await?;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if probe_whiteboard_client_state() == ("Idle", 0, false, 2)
                        && probe_whiteboard_helper() == (None, false)
                        && probe_whiteboard_helper_exit() == Some((expected_generation, false)) { break; }
                    ensure!(tokio::time::Instant::now() < deadline,
                        "production owner did not join/reap its failed helper: state={:?} helper={:?}",
                        probe_whiteboard_client_state(), probe_whiteboard_helper());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                println!("WHITEBOARD_CLIENT_CRASH_REAPED generation=1 pid={pid} status=failed owner=production phase=Idle task=joined connections=2");
                std::io::stdout().flush()?;
                let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
                while tokio::time::Instant::now() < deadline {
                    ensure!(probe_whiteboard_client_state() == ("Idle", 0, false, 2)
                        && probe_whiteboard_helper() == (None, false),
                        "retained crash demand started an unsolicited successor");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                println!("WHITEBOARD_CLIENT_IDLE case=helper-crash retired_generation=1 observation_ms=500 connections=2");
                std::io::stdout().flush()?;
                observer_ack(b"idle\n").await?;
                for id in ids { register_whiteboard(id); register_whiteboard(id); }
                continue;
            } else if expected_generation == 1 && case == "helper-close" {
                // Four moves above leave no pending cursor; observe transport loss without another write.
                tokio::time::sleep(Duration::from_millis(350)).await;
                println!("WHITEBOARD_CLIENT_WINDOW_CLOSE case=helper-close generation=1 pid={pid}");
                std::io::stdout().flush()?;
            } else if case == "root-shutdown" {
                ensure!(probe_whiteboard_client_state() == ("Running", expected_generation, true, 2)
                    && probe_whiteboard_helper() == (Some(pid), false),
                    "root shutdown missed its active Running generation");
                println!("WHITEBOARD_CLIENT_ROOT_STOP case=root-shutdown generation=1 pid={pid}");
                std::io::stdout().flush()?;
                root_shutdown.notify_one();
            } else {
                unregister_whiteboard(ids[0]);
                overlay_phase("clear", b"cleared\n").await?;
                unregister_whiteboard(ids[1]);
            }
            // The helper owns inherited stdin until its CLI-return barrier is released.
            ensure!(tokio::time::timeout(Duration::from_secs(5), inspect.recv()).await?.is_some(),
                "client inspection signal ended");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            while !probe_whiteboard_helper().1 {
                ensure!(tokio::time::Instant::now() < deadline,
                    "production owner did not join its command task: state={:?} helper={:?}",
                    probe_whiteboard_client_state(), probe_whiteboard_helper());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if expected_generation == 1 && case != "shutdown" {
                if case != "helper-close" {
                    for id in [9, 10] { register_whiteboard(id); register_whiteboard(id); }
                }
                if case == "withdrawal" {
                    unregister_whiteboard(9);
                    unregister_whiteboard(10);
                }
                // Let the real owner run while the old helper remains behind its barrier.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let (phase, current, task, connections) = probe_whiteboard_client_state();
            let (helper, task_joined) = probe_whiteboard_helper();
            let expected_connections = if expected_generation == 1 && matches!(case.as_str(), "replacement" | "helper-close") { 2 } else { 0 };
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
            if expected_generation == 1 && matches!(case.as_str(), "withdrawal" | "helper-close" | "root-shutdown") {
                let idle_connections = if case == "helper-close" { 2 } else { 0 };
                if case == "root-shutdown" {
                    for id in [7, 8, 11, 12] { register_whiteboard(id); }
                }
                let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
                while tokio::time::Instant::now() < deadline {
                    ensure!(probe_whiteboard_client_state() == ("Idle", 0, false, idle_connections)
                        && probe_whiteboard_helper() == (None, false), "retired demand started an unsolicited successor");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                println!("WHITEBOARD_CLIENT_IDLE case={case} retired_generation=1 observation_ms=500 connections={idle_connections}");
                std::io::stdout().flush()?;
                observer_ack(b"idle\n").await?;
                if case != "root-shutdown" {
                    let ids = if case == "helper-close" { [7, 8] } else { [11, 12] };
                    for id in ids { register_whiteboard(id); register_whiteboard(id); }
                }
            }
        }
        Ok(last_pid)
    };
    let result = if case == "root-shutdown" {
        let (result, root_result) = tokio::join!(
            async {
                let result = exercise.await;
                // Error paths also request production drain; neither branch may be detached.
                root_shutdown.notify_one();
                result
            },
            async {
                root_shutdown.notified().await;
                owner.stop_and_join().await;
                ensure!(probe_whiteboard_client_state() == ("Idle", 0, false, 0)
                    && probe_whiteboard_helper() == (None, false), "production root drain returned before retirement");
                println!("WHITEBOARD_CLIENT_ROOT_JOIN case=root-shutdown generation=1 phase=Idle connections=0 task=joined helper=reaped");
                std::io::stdout().flush()?;
                Ok::<(), hbb_common::anyhow::Error>(())
            },
        );
        root_result.and(result)
    } else {
        exercise.await
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

async fn client_generation() -> ResultType<()> {
    let case = std::env::var("WHITEBOARD_PROBE_CLIENT_GENERATION")?;
    let mut worker = crate::ipc::spawn_desktop_ipc_worker()?;
    let (readiness, completion) = worker.startup_receivers();
    let (startup, completed) = tokio::select! {
        ready = readiness => (ready.map_err(|_| "desktop IPC readiness disappeared".to_owned())
            .and_then(|ready| ready), None),
        outcome = completion => (Err("desktop IPC ended before fixture readiness".to_owned()),
            Some(outcome.unwrap_or_else(|_| Err("desktop IPC outcome disappeared".to_owned())))),
    };
    let result = match startup {
        Ok(controller) => {
            async {
                println!("WHITEBOARD_CLIENT_PROCESS_ROOT_READY worker=desktop-ipc controller=retained");
                std::io::stdout().flush()?;
                exercise_client_generation(controller, case).await
            }.await
        }
        Err(err) => Err(hbb_common::anyhow::anyhow!(err)),
    };
    crate::server::request_graceful_shutdown();
    let completion = match completed {
        Some(outcome) => outcome,
        None => worker.wait_for_completion().await,
    };
    let joined = worker.join().await;
    result?;
    completion.map_err(|err| hbb_common::anyhow::anyhow!(err))?;
    joined.map_err(|err| hbb_common::anyhow::anyhow!(err))?;
    println!("WHITEBOARD_CLIENT_PROCESS_ROOT_JOINED worker=desktop-ipc outcome=ok thread=joined");
    std::io::stdout().flush()?;
    observer_ack(b"ipc-joined\n").await
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
