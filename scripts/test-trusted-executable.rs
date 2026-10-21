mod trusted_executable_tests {
    use std::{fs, os::unix::fs::{symlink, MetadataExt}, path::{Path, PathBuf}, process::Command};

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
}
