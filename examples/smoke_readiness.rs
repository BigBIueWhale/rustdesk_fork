//! Test-only typed IPC readiness probe for the loopback runtime smoke test.

use librustdesk::ipc;

fn prove_ipc_state(
    expected: &str,
    expected_pid: u32,
    expected_start_time: &str,
    timeout_ms: u64,
) -> Result<(), String> {
    let runtime = hbb_common::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("runtime creation failed: {err}"))?;
    let snapshot = runtime
        .block_on(ipc::get_main_readiness_snapshot_for_process(
            expected_pid,
            expected_start_time,
            timeout_ms,
        ))
        .map_err(|err| format!("typed status snapshot failed: {err}"))?;
    drop(runtime);

    let expected_values = match expected {
        "parked" => (false, false, None),
        "server" => (true, true, None),
        "user-server" => (true, true, Some(true)),
        _ => return Err(format!("unknown readiness state: {expected}")),
    };
    let actual_values = (
        snapshot.permanent_password_set,
        snapshot.direct_listener_bound,
        Some(snapshot.user_owned_permanent_password_writable),
    );
    if actual_values.0 != expected_values.0
        || actual_values.1 != expected_values.1
        || expected_values
            .2
            .is_some_and(|expected_writable| actual_values.2 != Some(expected_writable))
    {
        return Err(format!(
            "state is {actual_values:?}, expected {expected_values:?}"
        ));
    }
    println!("SMOKE_TYPED_IPC_READY state={expected}");
    Ok(())
}

fn run() -> Result<(), String> {
    let mut args = std::env::args();
    let _program = args.next();
    let operation = args
        .next()
        .ok_or_else(|| "expected one readiness operation".to_owned())?;
    if operation == "password-recovery-seconds" {
        if args.next().is_some() {
            return Err("password-recovery-seconds accepts no arguments".to_owned());
        }
        println!("{}", ipc::PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS);
        return Ok(());
    }
    let expected_pid = args
        .next()
        .ok_or_else(|| "readiness operation requires an expected pid".to_owned())?
        .parse::<u32>()
        .map_err(|_| "readiness pid is not an unsigned integer".to_owned())?;
    if expected_pid == 0 {
        return Err("readiness pid must be nonzero".to_owned());
    }
    let expected_start_time = args
        .next()
        .ok_or_else(|| "readiness operation requires a process start identity".to_owned())?;
    let timeout_ms = args
        .next()
        .ok_or_else(|| "readiness operation requires a timeout in milliseconds".to_owned())?
        .parse::<u64>()
        .map_err(|_| "readiness timeout is not an unsigned integer".to_owned())?;
    if timeout_ms == 0 {
        return Err("readiness timeout must be nonzero".to_owned());
    }
    if args.next().is_some() {
        return Err(
            "readiness operation accepts exactly one pid, start identity, and timeout".to_owned(),
        );
    }
    prove_ipc_state(&operation, expected_pid, &expected_start_time, timeout_ms)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("smoke_readiness: {err}");
        std::process::exit(1);
    }
}
