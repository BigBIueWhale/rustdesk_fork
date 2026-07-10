use std::{
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

#[cfg(windows)]
const BIN_DATA: &[u8] = include_bytes!("../data.bin");
#[cfg(not(windows))]
const BIN_DATA: &[u8] = &[];
// 4bytes
const LENGTH: usize = 4;
const IDENTIFIER_LENGTH: usize = 8;
const MD5_LENGTH: usize = 32;
const BUF_SIZE: usize = 4096;

pub(crate) struct BinaryData {
    pub md5_code: &'static [u8],
    // compressed gzip data
    pub raw: &'static [u8],
    pub path: String,
}

pub(crate) struct BinaryReader {
    pub files: Vec<BinaryData>,
    pub exe: String,
}

impl Default for BinaryReader {
    fn default() -> Self {
        let (files, exe) = BinaryReader::read();
        Self { files, exe }
    }
}

impl BinaryData {
    fn decompress(&self) -> Result<Vec<u8>, String> {
        let cursor = Cursor::new(self.raw);
        let mut decoder = brotli::Decompressor::new(cursor, BUF_SIZE);
        let mut buf = Vec::new();
        decoder
            .read_to_end(&mut buf)
            .map_err(|err| format!("failed to decompress {}: {err}", self.path))?;
        Ok(buf)
    }

    pub fn write_to_file(&self, prefix: &Path) -> Result<PathBuf, String> {
        let p = prefix.join(relative_payload_path(&self.path)?);
        if let Some(parent) = p.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
            }
        }
        if p.exists() {
            // check md5
            let f = fs::read(&p).map_err(|err| format!("failed to read {}: {err}", p.display()))?;
            let digest = format!("{:x}", md5::compute(&f));
            let md5_record = String::from_utf8_lossy(self.md5_code);
            if digest == md5_record {
                // same, skip this file
                println!("skip {}", &self.path);
                return Ok(p);
            } else {
                println!("writing {}", p.display());
                println!("{} -> {}", md5_record, digest)
            }
        }
        let content = self.decompress()?;
        let tmp = temporary_payload_path(&p)?;
        let write_result = write_new_file(&tmp, &content);
        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        if p.exists() {
            fs::remove_file(&p)
                .map_err(|err| format!("failed to replace {}: {err}", p.display()))?;
        }
        fs::rename(&tmp, &p).map_err(|err| {
            let _ = fs::remove_file(&tmp);
            format!(
                "failed to move {} into {}: {err}",
                tmp.display(),
                p.display()
            )
        })?;
        Ok(p)
    }
}

pub(crate) fn relative_payload_path(path: &str) -> Result<PathBuf, String> {
    if path.starts_with(['/', '\\']) {
        return Err(format!(
            "absolute embedded payload path is not allowed: {path}"
        ));
    }
    let mut relative = PathBuf::new();
    for component in path.split(['/', '\\']) {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".."
            || component.contains(':')
            || component.chars().any(|c| {
                c == '\0' || c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*')
            })
            || !is_windows_safe_component(component)
        {
            return Err(format!("invalid embedded payload path: {path}"));
        }
        relative.push(component);
    }
    if relative.as_os_str().is_empty() {
        return Err("empty embedded payload path".to_owned());
    }
    Ok(relative)
}

fn is_windows_safe_component(component: &str) -> bool {
    let trimmed = component.trim_end_matches(['.', ' ']);
    if trimmed.is_empty() || trimmed != component {
        return false;
    }
    let stem = trimmed
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(trimmed)
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn temporary_payload_path(path: &Path) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("payload path has no file name: {}", path.display()))?
        .to_string_lossy();
    let parent = path
        .parent()
        .ok_or_else(|| format!("payload path has no parent: {}", path.display()))?;
    for attempt in 0..32 {
        let tmp = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        if !tmp.exists() {
            return Ok(tmp);
        }
    }
    Err(format!(
        "failed to allocate temporary payload path for {}",
        path.display()
    ))
}

fn write_new_file(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    file.write_all(content)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", path.display()))
}

impl BinaryReader {
    fn read() -> (Vec<BinaryData>, String) {
        let mut base: usize = 0;
        let mut parsed = vec![];
        assert!(BIN_DATA.len() > IDENTIFIER_LENGTH, "bin data invalid!");
        let mut iden = String::from_utf8_lossy(&BIN_DATA[base..base + IDENTIFIER_LENGTH]);
        if iden != "rustdesk" {
            panic!("bin file is not valid!");
        }
        base += IDENTIFIER_LENGTH;
        loop {
            iden = String::from_utf8_lossy(&BIN_DATA[base..base + IDENTIFIER_LENGTH]);
            if iden == "rustdesk" {
                base += IDENTIFIER_LENGTH;
                break;
            }
            // start reading
            let mut offset = 0;
            let path_length = u32::from_be_bytes([
                BIN_DATA[base + offset],
                BIN_DATA[base + offset + 1],
                BIN_DATA[base + offset + 2],
                BIN_DATA[base + offset + 3],
            ]) as usize;
            offset += LENGTH;
            let path =
                String::from_utf8_lossy(&BIN_DATA[base + offset..base + offset + path_length])
                    .to_string();
            offset += path_length;
            // file sz
            let file_length = u32::from_be_bytes([
                BIN_DATA[base + offset],
                BIN_DATA[base + offset + 1],
                BIN_DATA[base + offset + 2],
                BIN_DATA[base + offset + 3],
            ]) as usize;
            offset += LENGTH;
            let raw = &BIN_DATA[base + offset..base + offset + file_length];
            offset += file_length;
            // md5
            let md5 = &BIN_DATA[base + offset..base + offset + MD5_LENGTH];
            offset += MD5_LENGTH;
            parsed.push(BinaryData {
                md5_code: md5,
                raw: raw,
                path: path,
            });
            base += offset;
        }
        // executable
        let executable = String::from_utf8_lossy(&BIN_DATA[base..]).to_string();
        (parsed, executable)
    }

    #[cfg(linux)]
    pub fn configure_permission(&self, prefix: &Path) {
        use std::os::unix::prelude::PermissionsExt;

        let exe_path = prefix.join(&self.exe);
        if exe_path.exists() {
            if let Ok(f) = File::open(exe_path) {
                if let Ok(meta) = f.metadata() {
                    let mut permissions = meta.permissions();
                    permissions.set_mode(0o755);
                    f.set_permissions(permissions).ok();
                }
            }
        }
    }
}
