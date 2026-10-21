mod trusted_executable_tests {
    use std::{fs, os::unix::fs::{symlink, MetadataExt, PermissionsExt}, path::{Path, PathBuf}, process::Command};

    type Selector = fn(&Path) -> Option<PathBuf>;
    const SELECTORS: [(&str, Selector); 4] = [
        ("shared", super::shared::select),
        ("system", super::system::select),
        ("authorization", super::authorization::select),
        ("terminal", super::terminal::select),
    ];

    #[test]
    fn normal_system_images_and_aliases_remain_executable() {
        for (name, select) in SELECTORS {
            for path in ["/usr/bin/true", "/bin/sh"] {
                let selected = select(Path::new(path)).unwrap();
                assert_eq!(selected, fs::canonicalize(path).unwrap());
                let metadata = fs::metadata(&selected).unwrap();
                assert_eq!(metadata.uid(), 0);
                assert_eq!(metadata.mode() & 0o022, 0);
                let mut command = Command::new(&selected);
                if path.ends_with("/sh") { command.args(["-c", "exit 0"]); }
                assert!(command.status().unwrap().success());
                println!("TRUSTED_EXECUTABLE_CASE=pass module={name} kind=system path={path} executed=true");
            }
        }
    }

    #[test]
    fn malformed_missing_directory_and_nonexecutable_paths_refuse() {
        for (name, select) in SELECTORS {
            for path in ["true", "/usr/bin/../bin/true", "/rustdesk-no-such-helper",
                         "/usr/bin", "/etc/passwd"] {
                assert!(select(Path::new(path)).is_none(), "{name} admitted {path}");
            }
            println!("TRUSTED_EXECUTABLE_CASE=pass module={name} kind=invalid cases=5");
        }
    }

    #[test]
    fn user_owned_ancestry_cannot_select_a_root_owned_image() {
        let base = std::env::temp_dir().join(format!("rustdesk-helper-ancestry-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let alias = base.join("bin");
        symlink("/usr/bin", &alias).unwrap();
        let path = alias.join("true");
        assert_eq!(fs::metadata(&base).unwrap().uid(), 1000);
        assert_eq!(fs::metadata(&alias).unwrap().uid(), 0);
        assert_eq!(fs::metadata(&path).unwrap().uid(), 0);
        let mut refused = true;
        for (name, select) in SELECTORS {
            let result = select(&path);
            println!("TRUSTED_EXECUTABLE_CASE=observed module={name} kind=user-ancestor refused={}", result.is_none());
            refused &= result.is_none();
        }
        fs::remove_file(alias).unwrap();
        fs::remove_dir(base).unwrap();
        assert!(refused, "a user-controlled ancestor selected a root-owned executable");
    }

    fn fixture(name: &str) -> PathBuf {
        Path::new("/trusted-executable-fixture").join(name)
    }

    fn identity(path: &Path) -> (u64, u64, u32, u32) {
        let meta = fs::symlink_metadata(path).unwrap();
        (meta.dev(), meta.ino(), meta.uid(), meta.mode())
    }

    #[test]
    fn writable_canonical_ancestors_refuse_before_path_replacement() {
        for kind in ["owner", "group", "world"] {
            for (name, select) in SELECTORS {
                let parent = fixture(&format!("{kind}/{name}"));
                let bin = parent.join("bin");
                let held = parent.join("held");
                let path = bin.join("helper");
                let original = identity(&path);
                assert_eq!(original.2, 0);
                assert_eq!(fs::metadata(&bin).unwrap().uid(), 0);
                let admitted = super::before::select(&path).unwrap();
                assert_eq!(admitted, path);
                let refused = select(&path).is_none();
                fs::rename(&bin, &held).unwrap();
                fs::create_dir(&bin).unwrap();
                fs::write(&path, b"#!/bin/sh\nprintf 'attacker:'\n/usr/bin/id -u\n").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                let output = Command::new(&admitted).output().unwrap();
                let replaced = output.status.success() && output.stdout == b"attacker:1000\n";
                assert_eq!(identity(&held.join("helper")), original);
                fs::remove_file(&path).unwrap();
                fs::remove_dir(&bin).unwrap();
                fs::rename(&held, &bin).unwrap();
                assert_eq!(identity(&path), original);
                println!("TRUSTED_EXECUTABLE_NAMESPACE=observed kind=canonical-{kind} module={name} refused={refused} historical_replacement_executed={replaced} uid=1000 original=preserved");
                assert!(refused && replaced);
            }
        }
    }

    #[test]
    fn hidden_symlink_targets_cannot_choose_authority_images() {
        for (name, select) in SELECTORS {
            let path = fixture(&format!("hidden/{name}/helper"));
            let alias = fixture(&format!("user-links/{name}/tool"));
            let held = alias.with_file_name("held");
            let link_identity = identity(&alias);
            assert_eq!(identity(&path).2, 0);
            assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().uid(), 0);
            let old_before = super::before::select(&path).unwrap();
            let before_refused = select(&path).is_none();
            assert_eq!(Command::new(&old_before).status().unwrap().code(), Some(1));
            fs::rename(&alias, &held).unwrap();
            symlink("/usr/bin/true", &alias).unwrap();
            let old_after = super::before::select(&path).unwrap();
            let after_refused = select(&path).is_none();
            assert_eq!(Command::new(&old_after).status().unwrap().code(), Some(0));
            let changed_image = old_before != old_after;
            fs::remove_file(&alias).unwrap();
            fs::rename(&held, &alias).unwrap();
            assert_eq!(identity(&alias), link_identity);
            println!("TRUSTED_EXECUTABLE_NAMESPACE=observed kind=hidden-hop module={name} before_refused={before_refused} after_refused={after_refused} historical_image_changed={changed_image} exits=1,0 uid=1000 original=preserved");
            assert!(before_refused && after_refused && changed_image);
        }
    }

    #[test]
    fn trusted_link_semantics_and_kernel_write_refusal_preserve_functionality() {
        let helper = fixture("trusted/bin/helper");
        let original = identity(&helper);
        for (name, select) in SELECTORS {
            for alias in ["trusted/bin/helper", "trusted/links/relative", "trusted/links/parent",
                          "trusted/links/absolute", "trusted/links/hop-0"] {
                let path = fixture(alias);
                let selected = select(&path).unwrap();
                assert_eq!(selected, fs::canonicalize(path).unwrap());
                let output = Command::new(selected).output().unwrap();
                assert!(output.status.success());
                assert_eq!(output.stdout, b"legitimate:1000\n");
            }
            for alias in ["trusted/links/file-slash", "trusted/links/file-dot", "trusted/links/hop-41",
                          "trusted/links/cycle-a", "trusted/bin/noexec", "trusted/bin/writable",
                          "trusted/bin/fifo", "trusted/bin"] {
                assert!(select(&fixture(alias)).is_none(), "{name} admitted {alias}");
            }
            let error = fs::rename(&helper, helper.with_file_name("forbidden")).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(identity(&helper), original);
            println!("TRUSTED_EXECUTABLE_NAMESPACE=pass kind=trusted-controls module={name} executed=5 invalid=8 protected_rename=denied links_40=accepted links_41=refused uid=1000");
        }
    }
}
