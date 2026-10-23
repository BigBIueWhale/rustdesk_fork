mod linux_process_identity_tests {
    use super::*;
    use std::{
        ffi::OsString,
        io::{Read, Write},
        os::unix::ffi::OsStringExt,
        os::unix::{fs::DirBuilderExt, io::AsRawFd, net::{UnixListener, UnixStream}},
        os::unix::process::CommandExt,
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, Instant},
    };

    extern "C" {
        fn geteuid() -> u32;
        fn kill(pid: i32, signal: i32) -> i32;
        fn getsockopt(fd: i32, level: i32, option: i32, value: *mut u8, len: *mut u32) -> i32;
    }

    #[repr(C)]
    struct PeerCred { pid: i32, uid: u32, gid: u32 }

    struct Owner { child: Option<Child>, root: PathBuf, peer: Option<UnixStream> }

    impl Owner {
        fn spawn(dumpable: u32, leader_exit: bool) -> Self {
            Self::spawn_with_argv(dumpable, leader_exit, None)
        }

        fn spawn_with_argv(dumpable: u32, leader_exit: bool, argv: Option<&[OsString]>) -> Self {
            Self::spawn_with_environment(dumpable, leader_exit, argv, &[])
        }

        fn spawn_with_environment(dumpable: u32, leader_exit: bool, argv: Option<&[OsString]>,
                                  environment: &[(&str, OsString)]) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!("linux-identity-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let listener = UnixListener::bind(root.join("peer")).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut command = Command::new(std::env::var_os("LINUX_IDENTITY_PEER_PROBE").unwrap());
            command.env_remove(crate::common::CM_LAUNCH_TOKEN_ENV)
                .env_remove(crate::common::CM_LAUNCH_PARENT_ENV)
                .envs(environment.iter().map(|(key, value)| (*key, value)));
            if let Some(argv) = argv {
                command.arg0(&argv[0]).args(&argv[1..])
                    .env("LINUX_IDENTITY_ARGV_SOCKET", root.join("peer"));
            } else {
                command.arg(root.join("peer")).arg(dumpable.to_string())
                    .arg(if leader_exit { "leader-exit" } else { "normal" });
            }
            let child = command
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::inherit())
                .spawn().unwrap();
            let mut owner = Self { child: Some(child), root, peer: None };
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((peer, _)) => { owner.peer = Some(peer); break; }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("native child accept failed: {error}"),
                }
                assert!(Instant::now() < deadline, "native child did not connect");
                std::thread::sleep(Duration::from_millis(1));
            }
            owner
        }

        fn pid(&self) -> u32 { self.child.as_ref().unwrap().id() }

        fn credentials(&self) -> PeerCred {
            let mut value = PeerCred { pid: 0, uid: 0, gid: 0 };
            let mut length = std::mem::size_of::<PeerCred>() as u32;
            assert_eq!(unsafe { getsockopt(self.peer.as_ref().unwrap().as_raw_fd(), 1, 17,
                &mut value as *mut _ as *mut u8, &mut length) }, 0);
            assert_eq!(length as usize, std::mem::size_of::<PeerCred>());
            assert_eq!(value.pid as u32, self.pid());
            value
        }

        fn signal(&self, signal: i32) { assert_eq!(unsafe { kill(self.pid() as i32, signal) }, 0); }

        fn state(&self) -> char {
            let status = fs::read_to_string(format!("/proc/{}/status", self.pid())).unwrap();
            status.lines().find_map(|line| line.strip_prefix("State:"))
                .unwrap().trim_start().chars().next().unwrap()
        }

        fn await_state(&self, expected: char) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.state() != expected {
                assert!(Instant::now() < deadline, "child did not reach {expected}");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn request_exit(&mut self) {
            self.child.as_mut().unwrap().stdin.take().unwrap().write_all(b"x").unwrap();
        }

        fn mutate_argument(&mut self) {
            self.mutate(b'm');
        }

        fn mutate(&mut self, command: u8) {
            self.child.as_mut().unwrap().stdin.as_mut().unwrap().write_all(&[command]).unwrap();
            let peer = self.peer.as_mut().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut acknowledgement = [0];
            peer.read_exact(&mut acknowledgement).unwrap();
            assert_eq!(acknowledgement, [command]);
        }

        fn join(&mut self) {
            assert!(self.child.take().unwrap().wait().unwrap().success());
        }
    }

    impl Drop for Owner {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                if child.try_wait().unwrap().is_none() {
                    child.kill().unwrap();
                    child.wait().unwrap();
                }
            }
            drop(self.peer.take());
            fs::remove_file(self.root.join("peer")).unwrap();
            fs::remove_dir(&self.root).unwrap();
        }
    }

    #[test]
    fn kernel_task_name_bytes_do_not_change_process_identity() {
        let names: &[(&str, &[u8])] = &[
            ("ascii", b"renamed-peer"),
            ("parentheses", b"space ) ) name"),
            ("newline", b"line\nname"),
            ("unicode", "name-\u{e9}".as_bytes()),
            ("invalid-ff", b"name-\xff"),
            ("invalid-80", b"name-\x80"),
            ("incomplete", b"name-\xc3"),
            ("unicode-truncated", "abcdefghijklmn\u{e9}".as_bytes()),
        ];
        let mut failures = 0;
        let mut invalid_names = 0;
        for &(kind, name) in names {
            let mut owner = Owner::spawn_with_environment(1, false, None, &[
                ("LINUX_IDENTITY_NEXT_COMM", OsString::from_vec(name.to_vec())),
            ]);
            let principal = linux_kernel_process_identity_by_pid(owner.pid()).unwrap();
            assert_eq!(principal.uid, owner.credentials().uid);
            let snapshot = linux_process_identity_fields_by_pid(owner.pid()).unwrap();
            let parent = linux_proc_parent_pid(owner.pid()).unwrap();
            assert_eq!(parent, std::process::id());
            owner.mutate(b'n');
            let kernel_name = &name[..name.len().min(15)];
            let invalid = std::str::from_utf8(kernel_name).is_err();
            invalid_names += usize::from(invalid);
            let raw = fs::read(format!("/proc/{}/stat", owner.pid())).unwrap();
            let mut prefix = format!("{} (", owner.pid()).into_bytes();
            prefix.extend_from_slice(kernel_name);
            prefix.extend_from_slice(b") ");
            assert!(raw.starts_with(&prefix), "actual kernel task name differs: {kind}");
            let identity_preserved = matches!(linux_kernel_process_identity_by_pid(owner.pid()),
                Ok(actual) if actual == principal);
            let snapshot_preserved = matches!(linux_process_identity_fields_by_pid(owner.pid()),
                Ok(actual) if actual == snapshot);
            let parent_preserved = matches!(linux_proc_parent_pid(owner.pid()), Ok(actual) if actual == parent);
            let live = linux_process_identity_is_live(&principal);
            assert_eq!(owner.credentials().uid, principal.uid);
            let correct = identity_preserved && snapshot_preserved && parent_preserved && live;
            println!("LINUX_KERNEL_COMM_CASE=observed kind={kind} kernel_name_exact=true invalid_utf8={invalid} identity_preserved={identity_preserved} snapshot_preserved={snapshot_preserved} parent_preserved={parent_preserved} live={live} correct={correct}");
            owner.request_exit();
            owner.join();
            failures += usize::from(!correct);
        }
        assert_eq!(names.len(), 8);
        assert_eq!(invalid_names, 4);
        assert_eq!(failures, 0, "numeric process identity must be independent of task-name encoding");
        println!("LINUX_KERNEL_COMM=pass cases=8 healthy=4 invalid_utf8=4 unicode_truncation=observed identity=preserved parent=preserved children=joined");
    }

    #[test]
    fn kernel_cmdline_preserves_empty_argument_positions() {
        fn roles(args: &[String]) -> [bool; 6] {
            [
                user_owned_main_server_argv_is_expected(args),
                linux_service_owned_server_argv_is_expected(args),
                linux_service_owned_password_client_argv_is_expected(args),
                cm_process_argv_is_expected(args, "--cm"),
                cm_process_argv_is_expected(args, "--cm-no-ui"),
                helper_server_argv_is_expected(args),
            ]
        }
        let layouts: &[&[&str]] = &[
            &[], &["--password"], &["--password-stdin"], &["--server"],
            &["--server", crate::common::SERVICE_OWNED_SERVER_ARG],
            &["--cm"], &["--cm-no-ui"],
        ];
        let mut cases = 0;
        let mut failures = 0;
        for (layout, tail) in layouts.iter().enumerate() {
            let base: Vec<String> = std::iter::once("/kernel/argv-probe")
                .chain(tail.iter().copied()).map(str::to_owned).collect();
            let expected_roles = roles(&base);
            assert!(expected_roles.iter().any(|&allowed| allowed));
            let mut variants = vec![("ordinary", None, base.clone())];
            let mut empty_name = base.clone();
            empty_name[0].clear();
            variants.push(("empty-name", None, empty_name));
            for position in 0..=base.len() {
                let mut extra = base.clone();
                extra.insert(position, String::new());
                variants.push(("extra-empty", Some(position), extra));
            }
            for (kind, position, expected) in variants {
                let argv: Vec<_> = expected.iter().map(OsString::from).collect();
                let mut owner = Owner::spawn_with_argv(1, false, Some(&argv));
                assert_eq!(owner.credentials().uid, unsafe { geteuid() });
                let kernel = fs::read(format!("/proc/{}/cmdline", owner.pid())).unwrap();
                let mut expected_bytes = Vec::new();
                for argument in &expected {
                    expected_bytes.extend_from_slice(argument.as_bytes());
                    expected_bytes.push(0);
                }
                assert_eq!(kernel, expected_bytes, "exec argv and actual kernel data differ");
                let actual: Vec<String> = linux_proc_cmdline_args(owner.pid()).unwrap()
                    .into_iter().map(String::from_utf8).collect::<Result<_, _>>().unwrap();
                let admitted = roles(&actual);
                let expected_admission = if kind == "extra-empty" { [false; 6] } else { expected_roles };
                let correct = actual == expected && admitted == expected_admission;
                println!("LINUX_KERNEL_ARGV_CASE=observed layout={layout} kind={kind} position={position:?} kernel_argc={} parsed_argc={} expected={expected_admission:?} actual={admitted:?} correct={correct}", expected.len(), actual.len());
                owner.request_exit();
                owner.join();
                failures += usize::from(!correct);
                cases += 1;
            }
        }
        assert_eq!(cases, 35);
        assert_eq!(failures, 0, "empty arguments must not disappear before exact role admission");
        println!("LINUX_KERNEL_ARGV=pass cases=35 layouts=7 ordinary=7 empty_name=7 extra_empty=21 source=procfs children=joined");
    }

    #[test]
    fn kernel_process_identity_preserves_non_utf8_argv_bytes() {
        let layouts: &[&[&str]] = &[
            &[], &["--password"], &["--password-stdin"], &["--server"],
            &["--server", crate::common::SERVICE_OWNED_SERVER_ARG],
            &["--cm"], &["--cm-no-ui"],
        ];
        let mut failures = 0;
        for (layout, tail) in layouts.iter().enumerate() {
            let mut initial = vec![b"/kernel/argv-\x80".to_vec()];
            initial.extend(tail.iter().map(|argument| argument.as_bytes().to_vec()));
            let argv: Vec<_> = initial.iter().cloned().map(OsString::from_vec).collect();
            let mut owner = Owner::spawn_with_argv(1, false, Some(&argv));
            assert_eq!(owner.credentials().uid, unsafe { geteuid() });
            let before = linux_process_identity_fields_by_pid(owner.pid()).unwrap();
            owner.mutate_argument();
            let after = linux_process_identity_fields_by_pid(owner.pid()).unwrap();
            let mut changed = initial.clone();
            changed[0] = b"/kernel/argv-\x81".to_vec();
            let kernel = fs::read(format!("/proc/{}/cmdline", owner.pid())).unwrap();
            let expected_kernel: Vec<_> = changed.iter().flat_map(|argument|
                argument.iter().copied().chain(std::iter::once(0))).collect();
            assert_eq!(kernel, expected_kernel);
            assert_eq!((before.pid, before.uid, &before.start_time, &before.cm_launch_token, before.cm_launch_parent),
                (after.pid, after.uid, &after.start_time, &after.cm_launch_token, after.cm_launch_parent));
            let correct = before.argv == initial && after.argv == changed && before != after;
            println!("LINUX_KERNEL_ARGV_BYTES_CASE=observed layout={layout} kind=mutation first_preserved={} second_preserved={} identity_changed={} correct={correct}",
                before.argv == initial, after.argv == changed, before != after);
            owner.request_exit();
            owner.join();
            failures += usize::from(!correct);

            let mut unicode = initial;
            unicode[0] = "/kernel/argv-\u{fffd}".as_bytes().to_vec();
            let argv: Vec<_> = unicode.iter().cloned().map(OsString::from_vec).collect();
            let mut control = Owner::spawn_with_argv(1, false, Some(&argv));
            let identity = linux_process_identity_fields_by_pid(control.pid()).unwrap();
            let correct = identity.argv == unicode && before.argv != identity.argv && after.argv != identity.argv;
            println!("LINUX_KERNEL_ARGV_BYTES_CASE=observed layout={layout} kind=utf8_control preserved={} distinct_from_invalid={} correct={correct}",
                identity.argv == unicode, before.argv != identity.argv && after.argv != identity.argv);
            control.request_exit();
            control.join();
            failures += usize::from(!correct);
        }
        assert_eq!(failures, 0, "argv identity must preserve raw bytes and detect same-process changes");
        println!("LINUX_KERNEL_ARGV_BYTES=pass layouts=7 children=14 mutations=7 snapshots=21 invalid_bytes=preserved unicode=distinct children_state=joined");
    }

    #[test]
    fn kernel_service_child_role_preserves_exact_argument_positions() {
        let base: Vec<String> = ["/kernel/service-child", "--server", crate::common::SERVICE_OWNED_SERVER_ARG]
            .into_iter().map(str::to_owned).collect();
        let mut variants = vec![("ordinary", None, base.clone(), true)];
        let mut empty_name = base.clone();
        empty_name[0].clear();
        variants.push(("empty-name", None, empty_name, true));
        for position in 0..=base.len() {
            let mut extra = base.clone();
            extra.insert(position, String::new());
            variants.push(("extra-empty", Some(position), extra, false));
        }
        let mut wrong_role = base.clone();
        wrong_role[2].push_str("-extra");
        variants.push(("wrong-marker", None, wrong_role, false));
        let mut extra = base;
        extra.push("extra".to_owned());
        variants.push(("extra-argument", None, extra, false));
        let mut failures = 0;
        for (kind, position, expected_argv, expected) in variants {
            let argv: Vec<_> = expected_argv.iter().map(OsString::from).collect();
            let mut owner = Owner::spawn_with_argv(1, false, Some(&argv));
            assert_eq!(owner.credentials().uid, unsafe { geteuid() });
            let kernel = fs::read(format!("/proc/{}/cmdline", owner.pid())).unwrap();
            let expected_kernel: Vec<_> = expected_argv.iter().flat_map(|argument|
                argument.as_bytes().iter().copied().chain(std::iter::once(0))).collect();
            assert_eq!(kernel, expected_kernel);
            let actual = service_child_cmdline_has_exact_role(&kernel);
            let correct = actual == expected;
            println!("LINUX_KERNEL_CHILD_ROLE_CASE=observed kind={kind} position={position:?} argc={} expected={expected} actual={actual} correct={correct}", expected_argv.len());
            owner.request_exit();
            owner.join();
            failures += usize::from(!correct);
        }
        assert_eq!(failures, 0, "service supervisor role checks must preserve every argument position");
        println!("LINUX_KERNEL_CHILD_ROLE=pass cases=8 ordinary=1 empty_name=1 extra_empty=4 wrong_role=2 children=joined");
    }

    #[test]
    fn kernel_role_environment_rejects_duplicate_keys() {
        let mut failures = 0;
        for (label, key, first, second) in [
            ("cm", crate::common::CM_LAUNCH_TOKEN_ENV,
                format!("{}=", "A".repeat(43)), format!("{}A=", "B".repeat(42))),
            ("generation", crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
                "11111111-1111-4111-8111-111111111111".to_owned(),
                "22222222-2222-4222-8222-222222222222".to_owned()),
        ] {
            let prefix = format!("{key}=");
            let mut healthy = Owner::spawn_with_environment(1, false, None, &[(key, OsString::from(&first))]);
            assert_eq!(healthy.credentials().uid, unsafe { geteuid() });
            let raw = fs::read(format!("/proc/{}/environ", healthy.pid())).unwrap();
            let values: Vec<_> = raw.split(|byte| *byte == 0)
                .filter_map(|entry| entry.strip_prefix(prefix.as_bytes())).collect();
            assert_eq!(values, [first.as_bytes()]);
            assert_eq!(linux_proc_environ_value(healthy.pid(), key).unwrap(), first);
            assert!(linux_process_identity_fields_by_pid(healthy.pid()).is_ok());
            if label == "generation" { assert!(service_child_environment_has_generation(&raw, &first)); }
            healthy.request_exit();
            healthy.join();
            println!("LINUX_KERNEL_ENV_DUP_CASE=observed key={label} kind=unique entries=1 exact=true snapshot=accepted correct=true");
            for (kind, left, right) in [
                ("same", first.as_str(), first.as_str()),
                ("conflict", first.as_str(), second.as_str()),
                ("reversed", second.as_str(), first.as_str()),
                ("empty", "", ""), ("empty-first", "", first.as_str()),
            ] {
                let mut owner = Owner::spawn_with_environment(1, false, None, &[
                    (key, OsString::from(left)),
                    ("LINUX_IDENTITY_DUP_ENV_KEY", OsString::from(key)),
                    ("LINUX_IDENTITY_DUP_ENV_VALUE", OsString::from(right)),
                ]);
                assert_eq!(owner.credentials().uid, unsafe { geteuid() });
                let raw = fs::read(format!("/proc/{}/environ", owner.pid())).unwrap();
                let values: Vec<_> = raw.split(|byte| *byte == 0)
                    .filter_map(|entry| entry.strip_prefix(prefix.as_bytes())).collect();
                assert_eq!(values, [left.as_bytes(), right.as_bytes()]);
                let refused = linux_proc_environ_value(owner.pid(), key).is_err();
                let snapshot = linux_process_identity_fields_by_pid(owner.pid());
                let snapshot_expected = if label == "cm" { snapshot.is_err() } else { snapshot.is_ok() };
                let supervisor_refused = label != "generation" || !service_child_environment_has_generation(&raw, &first);
                let correct = refused && snapshot_expected && supervisor_refused;
                println!("LINUX_KERNEL_ENV_DUP_CASE=observed key={label} kind={kind} entries=2 value_refused={refused} snapshot_expected={snapshot_expected} supervisor_consistent={supervisor_refused} correct={correct}");
                owner.request_exit();
                owner.join();
                failures += usize::from(!correct);
            }
        }
        assert_eq!(failures, 0, "selected authority environment keys must be unique");
        println!("LINUX_KERNEL_ENV_DUP=pass duplicate_cases=10 healthy=2 children=12 entries=kernel-observed selected_only=true children_state=joined");
    }

    #[test]
    fn kernel_role_environment_rejects_invalid_utf8_without_rewriting_values() {
        let key = crate::common::CM_LAUNCH_TOKEN_ENV;
        let raw_value = |pid| {
            let raw = fs::read(format!("/proc/{pid}/environ")).unwrap();
            let prefix = format!("{key}=");
            let values: Vec<_> = raw.split(|byte| *byte == 0)
                .filter_map(|entry| entry.strip_prefix(prefix.as_bytes())).collect();
            assert!(values.len() <= 1);
            values.first().map(|value| value.to_vec())
        };
        let mut invalid = Owner::spawn_with_environment(1, false, None, &[
            (key, OsString::from_vec(b"role-\x80".to_vec())),
            ("LINUX_IDENTITY_ENV_KEY", OsString::from(key)),
        ]);
        let principal = linux_kernel_process_identity_by_pid(invalid.pid()).unwrap();
        assert_eq!(principal.uid, invalid.credentials().uid);
        let argv = linux_proc_cmdline_args(invalid.pid()).unwrap();
        assert_eq!(raw_value(invalid.pid()), Some(b"role-\x80".to_vec()));
        let first = linux_proc_environ_value(invalid.pid(), key);
        let first_snapshot = linux_process_identity_fields_by_pid(invalid.pid());
        invalid.mutate(b'e');
        assert_eq!(raw_value(invalid.pid()), Some(b"role-\x81".to_vec()));
        let second = linux_proc_environ_value(invalid.pid(), key);
        let second_snapshot = linux_process_identity_fields_by_pid(invalid.pid());
        assert_eq!(linux_kernel_process_identity_by_pid(invalid.pid()).unwrap(), principal);
        assert_eq!(linux_proc_cmdline_args(invalid.pid()).unwrap(), argv);
        let correct = first.is_err() && second.is_err()
            && first_snapshot.is_err() && second_snapshot.is_err();
        let aliases = matches!((&first, &second), (Ok(a), Ok(b)) if a == b);
        println!("LINUX_KERNEL_ENV_CASE=observed kind=invalid-mutation first_refused={} second_refused={} snapshots_refused={} rewritten_values_alias={aliases} kernel_changed=true principal=preserved correct={correct}",
            first.is_err(), second.is_err(), first_snapshot.is_err() && second_snapshot.is_err());
        invalid.request_exit();
        invalid.join();
        let mut failures = usize::from(!correct);
        let ascii = format!("{}=", "A".repeat(43));
        let unicode = "role-\u{fffd}".to_owned();
        for (kind, value) in [
            ("ascii", Some(ascii.as_str())), ("unicode", Some(unicode.as_str())),
            ("empty", Some("")), ("missing", None), ("unrelated-invalid", Some(ascii.as_str())),
        ] {
            let mut environment = Vec::new();
            if let Some(value) = value { environment.push((key, OsString::from(value))); }
            if kind == "unrelated-invalid" {
                environment.push(("LINUX_IDENTITY_OTHER_RAW", OsString::from_vec(vec![0xff])));
            }
            let mut control = Owner::spawn_with_environment(1, false, None, &environment);
            assert_eq!(control.credentials().uid, principal.uid);
            assert_eq!(raw_value(control.pid()), value.map(|value| value.as_bytes().to_vec()));
            if kind == "unrelated-invalid" {
                let raw = fs::read(format!("/proc/{}/environ", control.pid())).unwrap();
                assert!(raw.split(|byte| *byte == 0).any(|entry| entry == b"LINUX_IDENTITY_OTHER_RAW=\xff"));
            }
            let actual = linux_proc_environ_value(control.pid(), key).unwrap();
            let snapshot = linux_process_identity_fields_by_pid(control.pid()).unwrap();
            let correct = actual == value.unwrap_or_default() && snapshot.cm_launch_token == actual;
            if kind == "unicode" {
                assert_ne!(actual.as_bytes(), b"role-\x80");
                assert_ne!(actual.as_bytes(), b"role-\x81");
            }
            println!("LINUX_KERNEL_ENV_CASE=observed kind={kind} exact_value={} snapshot=accepted correct={correct}", actual == value.unwrap_or_default());
            control.request_exit();
            control.join();
            failures += usize::from(!correct);
        }
        assert_eq!(failures, 0, "role environment values must be validated before entering identity snapshots");
        println!("LINUX_KERNEL_ENV=pass invalid_reads=2 snapshots_refused=2 controls=5 children=6 mutation=kernel-observed children_state=joined");
    }

    #[test]
    fn nondumpable_peer_keeps_its_effective_uid() {
        let mut all_correct = true;
        for dumpable in [1, 0] {
            let mut owner = Owner::spawn(dumpable, false);
            let peer = owner.credentials();
            assert_eq!(peer.uid, unsafe { geteuid() });
            let inode_uid = fs::metadata(format!("/proc/{}", owner.pid())).unwrap().uid();
            assert_eq!(inode_uid, peer.uid);
            let file_uid = fs::metadata(format!("/proc/{}/status", owner.pid())).unwrap().uid();
            assert_eq!(file_uid, if dumpable == 1 { peer.uid } else { 0 });
            let identity = linux_kernel_process_identity_by_pid(owner.pid()).unwrap();
            let correct = identity.uid == peer.uid;
            println!("LINUX_KERNEL_UID_CASE=observed dumpable={dumpable} socket_uid={} inode_uid={inode_uid} file_uid={file_uid} identity_uid={} correct={correct}", peer.uid, identity.uid);
            all_correct &= correct;
            owner.request_exit();
            owner.join();
        }
        assert!(all_correct, "procfs inode ownership is not the process principal");
        println!("LINUX_KERNEL_UID=pass cases=2 children=joined principal=effective");
    }

    #[test]
    fn exited_unreaped_peer_is_not_live() {
        let mut owner = Owner::spawn(1, false);
        let identity = linux_kernel_process_identity_by_pid(owner.pid()).unwrap();
        assert_eq!(identity.uid, owner.credentials().uid);
        assert!(linux_process_identity_is_live(&identity));
        let mut wrong_uid = identity.clone(); wrong_uid.uid ^= 1;
        let mut wrong_start = identity.clone(); wrong_start.start_time.push('0');
        assert!(!linux_process_identity_is_live(&wrong_uid));
        assert!(!linux_process_identity_is_live(&wrong_start));
        owner.signal(19);
        owner.await_state('T');
        assert!(linux_process_identity_is_live(&identity));
        println!("LINUX_KERNEL_LIFETIME_CASE=observed stage=stopped live=true");
        owner.signal(18);
        owner.await_state('S');
        assert!(linux_process_identity_is_live(&identity));
        owner.request_exit();
        owner.await_state('Z');
        assert_eq!(linux_proc_start_time(owner.pid()).unwrap(), identity.start_time);
        let socket_uid = owner.credentials().uid;
        let admitted = linux_kernel_process_identity_by_pid(owner.pid()).is_ok();
        let live = linux_process_identity_is_live(&identity);
        println!("LINUX_KERNEL_LIFETIME_CASE=observed stage=zombie socket_uid={socket_uid} identity_admitted={admitted} live={live}");
        owner.join();
        assert!(!linux_process_identity_is_live(&identity));
        println!("LINUX_KERNEL_LIFETIME_CASE=observed stage=reaped live=false children=joined");
        assert!(!admitted && !live, "an unreaped exited peer cannot supply live identity");
        println!("LINUX_KERNEL_LIFETIME=pass live=preserved stopped=preserved zombie=refused reaped=refused children=joined");
    }

    #[test]
    fn exited_leader_with_live_worker_keeps_process_identity() {
        fn descriptors() -> usize {
            fs::read_dir("/proc/thread-self/fd").unwrap().map(Result::unwrap).count()
        }
        let mut owner = Owner::spawn(1, true);
        owner.await_state('Z');
        let identity = linux_kernel_process_identity_by_pid(owner.pid()).unwrap();
        assert_eq!(identity.uid, owner.credentials().uid);
        let before = descriptors();
        for _ in 0..128 { assert!(linux_process_identity_is_live(&identity)); }
        let after_live = descriptors();
        assert_eq!(before, after_live);
        println!("LINUX_KERNEL_GROUP_CASE=observed leader=Z worker=alive live=true reads=128 fds_before={before} fds_after={after_live}");
        owner.request_exit();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = fs::read_to_string(format!("/proc/{}/status", owner.pid())).unwrap();
            if status.lines().find_map(|line| line.strip_prefix("Threads:")).unwrap().trim() == "1" { break; }
            assert!(Instant::now() < deadline, "worker did not retire");
            std::thread::sleep(Duration::from_millis(1));
        }
        let retired = linux_process_identity_is_live(&identity);
        let terminal_before = descriptors();
        for _ in 0..128 { assert_eq!(linux_process_identity_is_live(&identity), retired); }
        let terminal_after = descriptors();
        assert_eq!(terminal_before, terminal_after);
        println!("LINUX_KERNEL_GROUP_CASE=observed leader=Z worker=exited live={retired} reads=128 fds_before={terminal_before} fds_after={terminal_after}");
        owner.join();
        assert!(!retired, "an exited thread group is not live");
        println!("LINUX_KERNEL_GROUP=pass exited_leader=preserved exited_group=refused children=joined descriptors=retired");
    }
}
