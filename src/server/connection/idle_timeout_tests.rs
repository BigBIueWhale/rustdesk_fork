use super::*;

#[test]
fn stored_timeout_is_bounded_before_timer_admission() {
    const ROOT_ENV: &str = "RUSTDESK_IDLE_TIMEOUT_TEST_ROOT";
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        let root = std::env::temp_dir().join(format!(
            "idle-timeout-{}",
            hbb_common::uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "server::connection::idle_timeout_tests::stored_timeout_is_bounded_before_timer_admission",
                "--exact", "--color", "never", "--test-threads=1", "--nocapture",
            ])
            .env(ROOT_ENV, &root)
            .env("XDG_CONFIG_HOME", &root)
            .output()
            .unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(output.stdout.len() + output.stderr.len() <= 16_384);
        for line in String::from_utf8(output.stdout).unwrap().lines() {
            if let Some(start) = line.find("IDLE_TIMEOUT_CASE=") {
                println!("{}", &line[start..]);
            }
        }
        assert!(output.status.success(), "timer worker failed: {}", String::from_utf8_lossy(&output.stderr));
        return;
    };
    let root = std::path::PathBuf::from(root);
    let file = config::Config2::file();
    assert!(file.starts_with(&root));
    let cases = [
        ("", 10), ("0", 10), ("1", 1), ("9", 9), ("10", 10),
        ("65534", 65534), ("65535", 65535), ("01", 1), ("+2", 2),
        ("65536", 10), ("4294967295", 10),
        ("307445734561825860", 10), ("307445734561825861", 10),
        ("18446744073709551615", 10), ("18446744073709551616", 10),
        ("-1", 10), ("1.5", 10), (" 10", 10), ("10 ", 10), ("invalid", 10),
    ];
    let mut failures = Vec::new();
    for (value, expected) in cases {
        Config::set_option(keys::OPTION_AUTO_DISCONNECT_TIMEOUT.into(), value.into()).unwrap();
        Config::set_option(keys::OPTION_ALLOW_AUTO_DISCONNECT.into(), "Y".into()).unwrap();
        let stored = std::fs::read(&file).unwrap();
        let before = Instant::now();
        let (started, minutes) = Connection::get_auto_disconenct_timer().unwrap();
        let minutes = u64::from(minutes);
        assert!(started >= before && started <= Instant::now());
        assert_eq!(Config::get_option(keys::OPTION_AUTO_DISCONNECT_TIMEOUT), value);
        assert_eq!(std::fs::read(&file).unwrap(), stored);
        let seconds = minutes.checked_mul(60);
        let valid = minutes == expected && seconds == Some(expected * 60);
        println!("IDLE_TIMEOUT_CASE=value:{value:?} expected:{expected} actual:{minutes} seconds:{seconds:?} valid:{valid}");
        if !valid {
            failures.push((value, expected, minutes));
        }
        for disabled in ["N", ""] {
            Config::set_option(keys::OPTION_ALLOW_AUTO_DISCONNECT.into(), disabled.into()).unwrap();
            let stored = std::fs::read(&file).unwrap();
            assert!(Connection::get_auto_disconenct_timer().is_none());
            assert_eq!(std::fs::read(&file).unwrap(), stored);
        }
    }
    assert!(failures.is_empty(), "out-of-range timer admissions: {failures:?}");
}
