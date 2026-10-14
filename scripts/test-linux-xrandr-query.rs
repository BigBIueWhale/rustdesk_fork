extern crate self as hbb_common;
pub extern crate regex;

#[path = "../src/platform/linux/xrandr_query.rs"]
mod xrandr_query;

#[cfg(test)]
mod tests {
    use super::{regex::Regex, xrandr_query};
    use std::{io::ErrorKind, os::unix::process::ExitStatusExt, process::Command};

    const TWO_DISPLAYS: &str = concat!(
        "Screen 0: minimum 320 x 200, current 4480 x 1440, maximum 16384 x 16384\n",
        "eDP-1 connected primary 1920x1080+0+0 (normal left inverted right x axis y axis) 344mm x 193mm\n",
        "   1920x1080     60.01*+\n",
        "   1280x720      60.00\n",
        "DP-1 connected 2560x1440+1920+0 (normal left inverted right x axis y axis) 597mm x 336mm\n",
        "   2560x1440     59.95*+\n",
        "   1920x1080     60.00\n",
    );

    fn shell_output(script: &str) -> std::process::Output {
        Command::new("/bin/sh")
            .args(["-c", script])
            .output()
            .expect("native child must complete and be reaped")
    }

    #[test]
    fn successful_query_preserves_geometry_and_mode_lines() {
        let output = shell_output("printf '%s\\n' 'DP-1  connected  2560x1440+1920+0' '   2560x1440     59.95*+' '   1920x1080     60.00'");
        assert!(output.status.success());
        assert_eq!(
            xrandr_query::admit_output(output).unwrap(),
            "DP-1 connected 2560x1440+1920+0\n 2560x1440 59.95*+\n 1920x1080 60.00\n"
        );
    }

    #[test]
    fn failed_query_refuses_plausible_stdout() {
        let output = shell_output("printf '%s\\n' 'DP-1 connected 1920x1080+0+0'; exit 7");
        assert_eq!(output.status.code(), Some(7));
        let error = xrandr_query::admit_output(output).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Other);
        assert!(error.to_string().contains('7'));
    }

    #[test]
    fn signalled_query_refuses_plausible_stdout() {
        let output = shell_output("printf '%s\\n' 'DP-1 connected 1920x1080+0+0'; kill -TERM $$");
        assert_eq!(output.status.signal(), Some(15));
        assert_eq!(
            xrandr_query::admit_output(output).unwrap_err().kind(),
            ErrorKind::Other
        );
    }

    #[test]
    fn successful_query_refuses_invalid_utf8() {
        let output = shell_output("printf 'DP-1 connected 1920x1080+0+0\\377\\n'");
        assert!(output.status.success());
        assert_eq!(
            xrandr_query::admit_output(output).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn current_geometry_selects_the_exact_output() {
        let re = Regex::new(&xrandr_query::connected_output_pattern("DP-1")).unwrap();
        let caps = re.captures(TWO_DISPLAYS).unwrap();
        assert_eq!(&caps["width"], "2560");
        assert_eq!(&caps["height"], "1440");
        assert_eq!(&caps["x"], "1920");
        assert!(caps.get(0).unwrap().as_str().starts_with("DP-1 connected"));
        assert!(Regex::new(&xrandr_query::connected_output_pattern("P-1"))
            .unwrap()
            .captures(TWO_DISPLAYS)
            .is_none());
    }

    #[test]
    fn supported_modes_belong_to_the_exact_output() {
        let pattern = format!(
            r"{}(?P<resolutions>(\s*\d+x\d+\s+\d+.*\n)+)",
            xrandr_query::connected_output_pattern("DP-1")
        );
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(TWO_DISPLAYS).unwrap();
        assert!(caps["resolutions"].contains("2560x1440"));
        assert!(caps["resolutions"].contains("1920x1080"));
        assert!(!caps["resolutions"].contains("1280x720"));
    }

    #[test]
    fn output_names_are_literal_regex_text() {
        let re = Regex::new(&xrandr_query::connected_output_pattern("DP.1[2]")).unwrap();
        assert!(re.is_match("DP.1[2] connected 1920x1080+0+0\n"));
        assert!(!re.is_match("DPx12 connected 1920x1080+0+0\n"));
        assert!(!re.is_match("eDP.1[2] connected 1920x1080+0+0\n"));
    }

    #[test]
    fn output_identity_cannot_continue_on_another_line() {
        let re = Regex::new(&xrandr_query::connected_output_pattern("DP-1")).unwrap();
        assert!(!re.is_match("DP-1\n connected 1920x1080+0+0\n"));
        assert!(!re.is_match("DP-1 disconnected 1920x1080+0+0\n"));
    }
}
