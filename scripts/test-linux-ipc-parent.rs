// Included after exact production filesystem functions by the isolated component builder.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4);
    assert!(std::path::Path::new("/run/rustdesk-verifier-vm").is_dir());
    if args[1] == "path" {
        let uid = args[2].parse::<u32>().unwrap();
        println!("{}", config::ipc_parent_dir_for_uid(uid, &args[3]));
        return;
    }
    let path = std::path::Path::new(&args[2]);
    assert!(path.starts_with("/var/tmp/rustdesk-verifier-authority/ipc-parent-native/data")
        || path.starts_with("/run/RustDesk-service"));
    assert!(!path.components().any(|part| matches!(part, std::path::Component::ParentDir)));
    let result = match args[1].as_str() {
        "ensure" => ensure_secure_ipc_parent_dir(&args[2], &args[3]),
        _ => panic!("unknown fixture operation"),
    };
    match result {
        Ok(scrub) => println!("OK {scrub}"),
        Err(error) => {
            eprintln!("ERR {error}");
            std::process::exit(3);
        }
    }
}
