use hbb_common::regex;
use std::{io, process::Output};

pub(super) fn connected_output_pattern(name: &str) -> String {
    format!(
        r"(?m)^{}[ \t]+connected.+?(?P<width>\d+)x(?P<height>\d+)\+(?P<x>\d+)\+(?P<y>\d+).*?\n",
        regex::escape(name)
    )
}

pub(super) fn admit_output(output: Output) -> io::Result<String> {
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("xrandr query failed: {}", output.status),
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut normalized = String::with_capacity(text.len());
    let mut previous_was_space = false;
    for c in text.chars() {
        if c == ' ' {
            if !previous_was_space {
                normalized.push(c);
            }
            previous_was_space = true;
        } else {
            normalized.push(c);
            previous_was_space = false;
        }
    }
    Ok(normalized)
}
