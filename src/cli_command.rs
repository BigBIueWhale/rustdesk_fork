use clap::{Arg, ArgAction, Command};

pub fn command() -> Command {
    Command::new("rustdesk")
        .version(crate::VERSION)
        .author("Purslane Ltd<info@rustdesk.com>")
        .about("RustDesk command line tool")
        .arg(
            Arg::new("port-forward")
                .short('p')
                .long("port-forward")
                .value_name("PORT-FORWARD-OPTIONS")
                .num_args(1)
                .help("Format: remote-id:local-port:remote-port[:remote-host]"),
        )
        .arg(
            Arg::new("connect")
                .short('c')
                .long("connect")
                .value_name("REMOTE_ID")
                .num_args(1)
                .help("test only"),
        )
        .arg(
            Arg::new("server")
                .short('s')
                .long("server")
                .action(ArgAction::SetTrue)
                .help("Start server"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_is_a_value_free_flag() {
        let matches = command()
            .try_get_matches_from(["rustdesk", "--server"])
            .expect("the server flag must parse without a value");
        assert!(matches.get_flag("server"));
    }

    #[test]
    fn connect_keeps_the_exact_direct_target() {
        let matches = command()
            .try_get_matches_from(["rustdesk", "--connect", "127.0.0.1:21118"])
            .expect("the direct connect target must parse");
        assert_eq!(
            matches.get_one::<String>("connect").map(String::as_str),
            Some("127.0.0.1:21118")
        );
    }

    #[test]
    fn port_forward_keeps_the_exact_mapping() {
        let matches = command()
            .try_get_matches_from([
                "rustdesk",
                "--port-forward",
                "127.0.0.1:5000:3389:localhost",
            ])
            .expect("the port-forward mapping must parse");
        assert_eq!(
            matches.get_one::<String>("port-forward").map(String::as_str),
            Some("127.0.0.1:5000:3389:localhost")
        );
    }

    #[test]
    fn retired_server_key_arguments_are_rejected() {
        for arguments in [
            vec!["--key", "pinned"],
            vec!["-k", "pinned"],
            vec!["--key=pinned"],
            vec!["-kpinned"],
        ] {
            let mut argv = vec!["rustdesk", "--connect", "127.0.0.1"];
            argv.extend(arguments);
            let error = command()
                .try_get_matches_from(argv)
                .expect_err("a retired server key cannot be accepted");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
}
