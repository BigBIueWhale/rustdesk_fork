mod linux_process_identity_tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::{fs::DirBuilderExt, io::AsRawFd, net::{UnixListener, UnixStream}},
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, Instant},
    };

    extern "C" {
        fn prctl(option: i32, ...) -> i32;
        fn geteuid() -> u32;
        fn kill(pid: i32, signal: i32) -> i32;
        fn getsockopt(fd: i32, level: i32, option: i32, value: *mut u8, len: *mut u32) -> i32;
    }

    #[repr(C)]
    struct PeerCred { pid: i32, uid: u32, gid: u32 }

    struct Owner { child: Option<Child>, root: PathBuf, peer: Option<UnixStream> }

    impl Owner {
        fn spawn(dumpable: u32) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!("linux-identity-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let listener = UnixListener::bind(root.join("peer")).unwrap();
            listener.set_nonblocking(true).unwrap();
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "linux_process_identity_tests::nondumpable_peer_keeps_its_effective_uid", "--nocapture"])
                .env("LINUX_IDENTITY_CHILD", &root)
                .env("LINUX_IDENTITY_DUMPABLE", dumpable.to_string())
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
    fn nondumpable_peer_keeps_its_effective_uid() {
        if let Some(root) = std::env::var_os("LINUX_IDENTITY_CHILD") {
            let dumpable: usize = std::env::var("LINUX_IDENTITY_DUMPABLE").unwrap().parse().unwrap();
            assert_eq!(unsafe { prctl(4, dumpable, 0usize, 0usize, 0usize) }, 0);
            let _peer = UnixStream::connect(PathBuf::from(root).join("peer")).unwrap();
            let mut command = [0];
            std::io::stdin().read_exact(&mut command).unwrap();
            return;
        }
        let mut all_correct = true;
        for dumpable in [1, 0] {
            let mut owner = Owner::spawn(dumpable);
            let peer = owner.credentials();
            assert_eq!(peer.uid, unsafe { geteuid() });
            let inode_uid = fs::metadata(format!("/proc/{}", owner.pid())).unwrap().uid();
            assert_eq!(inode_uid, if dumpable == 1 { peer.uid } else { 0 });
            let identity = linux_kernel_process_identity_by_pid(owner.pid()).unwrap();
            let correct = identity.uid == peer.uid;
            println!("LINUX_KERNEL_UID_CASE=observed dumpable={dumpable} socket_uid={} inode_uid={inode_uid} identity_uid={} correct={correct}", peer.uid, identity.uid);
            all_correct &= correct;
            owner.request_exit();
            owner.join();
        }
        assert!(all_correct, "procfs inode ownership is not the process principal");
        println!("LINUX_KERNEL_UID=pass cases=2 children=joined principal=effective");
    }

    #[test]
    fn exited_unreaped_peer_is_not_live() {
        let mut owner = Owner::spawn(1);
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
    fn status_uid_requires_one_complete_canonical_record() {
        let valid = [("Uid:\t1\t2\t3\t4\n", 2), ("Uid: 0 0 0 0\n", 0),
            ("Name:\tpeer\nUid: 7 1000 8 9\nState: S\n", 1000),
            ("Uid: 1 4294967295 2 3\n", u32::MAX)];
        let invalid = ["", "Uid= 1 2 3 4\n", "Uid: 1 2 3\n", "Uid: 1 2 3 4 5\n",
            "Uid: 1 2 3 4\nUid: 1 2 3 4\n", "Uid: x 2 3 4\n", "Uid: 1 +2 3 4\n",
            "Uid: 1 02 3 4\n", "Uid: 1 -2 3 4\n", "Uid: 1 4294967296 3 4\n"];
        for (status, expected) in valid { assert_eq!(linux_proc_status_uid(123, status).unwrap(), expected); }
        for status in invalid { assert!(linux_proc_status_uid(123, status).is_err(), "admitted {status:?}"); }
        println!("LINUX_KERNEL_UID_PARSE=pass valid=4 invalid=10");
    }

    #[test]
    fn stat_liveness_preserves_stopped_and_rejects_terminal_states() {
        let stat = |state: &str| {
            let mut fields = vec!["0"; 20]; fields[0] = state; fields[19] = "1234";
            format!("123 (peer ) with spaces) {}", fields.join(" "))
        };
        for state in ["R", "S", "D", "T", "t", "K", "W", "P", "I"] {
            assert_eq!(linux_proc_live_stat_start_time(123, &stat(state)).unwrap(), "1234");
        }
        for state in ["Z", "X", "x", "?", "RR", ""] {
            assert!(linux_proc_live_stat_start_time(123, &stat(state)).is_err());
        }
        assert!(linux_proc_live_stat_start_time(123, "123 (peer) S 1").is_err());
        assert!(linux_proc_live_stat_start_time(123, "malformed").is_err());
        println!("LINUX_KERNEL_STATE_PARSE=pass live=9 refused=8");
    }
}
