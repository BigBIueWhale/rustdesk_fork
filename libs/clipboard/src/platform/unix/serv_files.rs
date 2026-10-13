use super::local_file::LocalFile;
use crate::{platform::unix::local_file::construct_file_list, ClipboardFile, CliprdrError};
use hbb_common::{
    bytes::{BufMut, BytesMut},
    log,
};
use parking_lot::Mutex;
use std::{path::PathBuf, sync::Arc, usize};

lazy_static::lazy_static! {
    // local files are cached, this value should not be changed when copying files
    // Because `CliprdrFileContentsRequest` only contains the index of the file in the list.
    // We need to keep the file list in the same order as the remote side.
    // We may add a `FileId` field to `CliprdrFileContentsRequest` in the future.
    static ref CLIP_FILES: Arc<Mutex<ClipFiles>> = Default::default();
}

#[derive(Debug)]
enum FileContentsRequest {
    Size {
        stream_id: i32,
        file_idx: usize,
    },

    Range {
        stream_id: i32,
        file_idx: usize,
        offset: u64,
        length: u64,
    },
}

#[derive(Default)]
struct ClipFiles {
    files: Vec<String>,
    file_list: Vec<LocalFile>,
    first_file_index: usize,
    files_pdu: Vec<u8>,
}

impl ClipFiles {
    fn clear(&mut self) {
        self.files.clear();
        self.file_list.clear();
        self.first_file_index = usize::MAX;
        self.files_pdu.clear();
    }

    fn sync_files(&mut self, clipboard_files: &[String]) -> Result<(), CliprdrError> {
        let clipboard_paths = clipboard_files
            .iter()
            .map(|s| PathBuf::from(s))
            .collect::<Vec<_>>();
        self.file_list = construct_file_list(&clipboard_paths)?;
        self.first_file_index = self
            .file_list
            .iter()
            .position(|f| !f.path.is_dir())
            .unwrap_or(usize::MAX);
        self.files = clipboard_files.to_vec();
        Ok(())
    }

    fn build_file_list_pdu(&mut self) {
        let mut data = BytesMut::with_capacity(4 + 592 * self.file_list.len());
        data.put_u32_le(self.file_list.len() as u32);
        for file in self.file_list.iter() {
            data.put(file.as_bin().as_slice());
        }
        self.files_pdu = data.to_vec()
    }

    fn get_files_for_audit(&self, request: &FileContentsRequest) -> Option<ClipboardFile> {
        if let FileContentsRequest::Range {
            file_idx, offset, ..
        } = request
        {
            if *file_idx == self.first_file_index && *offset == 0 {
                let files: Vec<(String, u64)> = self
                    .file_list
                    .iter()
                    .filter_map(|f| {
                        if f.path.is_file() {
                            Some((f.path.to_string_lossy().to_string(), f.size))
                        } else {
                            None
                        }
                    })
                    .collect::<_>();
                if files.is_empty() {
                    return None;
                } else {
                    return Some(ClipboardFile::Files { files });
                }
            }
        }
        None
    }

    fn serve_file_contents(
        &mut self,
        conn_id: i32,
        request: FileContentsRequest,
    ) -> Result<ClipboardFile, CliprdrError> {
        let (file_idx, file_contents_resp) = match request {
            FileContentsRequest::Size {
                stream_id,
                file_idx,
            } => {
                log::debug!("file contents (size) requested from conn: {}", conn_id);
                let Some(file) = self.file_list.get(file_idx) else {
                    log::error!(
                        "invalid file index {} requested from conn: {}",
                        file_idx,
                        conn_id
                    );
                    return Err(CliprdrError::InvalidRequest {
                        description: format!(
                            "invalid file index {} requested from conn: {}",
                            file_idx, conn_id
                        ),
                    });
                };

                log::debug!(
                    "conn {} requested file-{}: {}",
                    conn_id,
                    file_idx,
                    file.name
                );

                let size = file.size;
                (
                    file_idx,
                    ClipboardFile::FileContentsResponse {
                        msg_flags: 0x1,
                        stream_id,
                        requested_data: size.to_le_bytes().to_vec(),
                    },
                )
            }
            FileContentsRequest::Range {
                stream_id,
                file_idx,
                offset,
                length,
            } => {
                log::debug!(
                    "file contents (range from {} length {}) request from conn: {}",
                    offset,
                    length,
                    conn_id
                );
                let Some(file) = self.file_list.get_mut(file_idx) else {
                    log::error!(
                        "invalid file index {} requested from conn: {}",
                        file_idx,
                        conn_id
                    );
                    return Err(CliprdrError::InvalidRequest {
                        description: format!(
                            "invalid file index {} requested from conn: {}",
                            file_idx, conn_id
                        ),
                    });
                };
                log::debug!(
                    "conn {} requested file-{}: {}",
                    conn_id,
                    file_idx,
                    file.name
                );

                if offset > file.size {
                    log::error!("invalid reading offset requested from conn: {}", conn_id);
                    return Err(CliprdrError::InvalidRequest {
                        description: format!(
                            "invalid reading offset requested from conn: {}",
                            conn_id
                        ),
                    });
                }
                // §20 integer-overflow guard: a peer cb_requested=-1 makes length=u64::MAX; the old
                // `offset + length > file.size` WRAPPED, selected `length`, and `vec![0u8; length]`
                // below OOMs/panics. clamp_file_read_size() reads at most `length`, capped at the
                // remaining file bytes, overflow-safe (unit-tested at the bottom of this file).
                let read_size = clamp_file_read_size(offset, length, file.size);

                let mut buf = vec![0u8; read_size as usize];

                file.read_exact_at(&mut buf, offset)?;

                (
                    file_idx,
                    ClipboardFile::FileContentsResponse {
                        msg_flags: 0x1,
                        stream_id,
                        requested_data: buf,
                    },
                )
            }
        };

        log::debug!("file contents sent to conn: {}", conn_id);
        // hot reload next file
        for next_file in self.file_list.iter_mut().skip(file_idx + 1) {
            if !next_file.is_dir {
                next_file.load_handle()?;
                break;
            }
        }
        Ok(file_contents_resp)
    }
}

#[inline]
pub fn clear_files() {
    CLIP_FILES.lock().clear();
}

pub fn read_file_contents(
    conn_id: i32,
    stream_id: i32,
    list_index: i32,
    dw_flags: i32,
    n_position_low: i32,
    n_position_high: i32,
    cb_requested: i32,
) -> Vec<Result<ClipboardFile, CliprdrError>> {
    let fcr = if dw_flags == 0x1 {
        FileContentsRequest::Size {
            stream_id,
            file_idx: list_index as usize,
        }
    } else if dw_flags == 0x2 {
        let offset = (u64::from(n_position_high as u32) << 32)
            | u64::from(n_position_low as u32);
        let length = cb_requested as u64;

        FileContentsRequest::Range {
            stream_id,
            file_idx: list_index as usize,
            offset,
            length,
        }
    } else {
        return vec![Err(CliprdrError::InvalidRequest {
            description: format!("got invalid FileContentsRequest, dw_flats: {dw_flags}"),
        })];
    };

    let mut clip_files = CLIP_FILES.lock();
    let mut res = vec![];
    if let Some(files_res) = clip_files.get_files_for_audit(&fcr) {
        res.push(Ok(files_res));
    }
    res.push(clip_files.serve_file_contents(conn_id, fcr));
    res
}

pub fn sync_files(files: &[String]) -> Result<(), CliprdrError> {
    let mut files_lock = CLIP_FILES.lock();
    if files_lock.files == files {
        return Ok(());
    }
    files_lock.sync_files(files)?;
    Ok(files_lock.build_file_list_pdu())
}

pub fn get_file_list_pdu() -> Vec<u8> {
    CLIP_FILES.lock().files_pdu.clone()
}

/// Clamp a peer-requested read `length` to the bytes remaining after `offset`, overflow-safe.
/// The CLIPRDR file-contents serve path computes `length = cb_requested as u64` from a peer i32, so a
/// negative cb_requested yields u64::MAX and `offset + length` would WRAP; `saturating_sub` keeps this
/// correct even if `offset` exceeds `file_size` (the caller validates offset <= file_size first).
fn clamp_file_read_size(offset: u64, length: u64, file_size: u64) -> u64 {
    std::cmp::min(length, file_size.saturating_sub(offset))
}

#[cfg(test)]
mod tests {
    use super::clamp_file_read_size;

    #[test]
    fn file_contents_reads_unsigned_offset_words_from_sparse_file() {
        use std::{fs::File, io::{Seek, SeekFrom, Write}, os::unix::fs::MetadataExt};

        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                super::clear_files();
                std::fs::remove_file(self.0.join("sparse.bin")).expect("remove sparse file");
                std::fs::remove_dir(&self.0).expect("remove clipboard fixture directory");
            }
        }

        let directory = std::env::temp_dir().join(format!(
            "rustdesk-clipboard-offset-{}-{:016x}", std::process::id(), rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).expect("create private clipboard fixture");
        let fixture = Fixture(directory);
        let path = fixture.0.join("sparse.bin");
        let offsets = [0, (1u64 << 31) - 8, 1u64 << 31, (1u64 << 32) - 8,
            1u64 << 32, (1u64 << 32) + (1u64 << 31), (1u64 << 33) + 17];
        let mut file = File::create(&path).expect("create sparse clipboard file");
        for (index, offset) in offsets.iter().enumerate() {
            file.seek(SeekFrom::Start(*offset)).expect("seek sparse fixture");
            file.write_all(&[index as u8, 0x52, 0x44, 0xff]).expect("write sparse marker");
        }
        file.sync_all().expect("synchronize sparse fixture");
        let metadata = file.metadata().expect("inspect sparse file");
        assert!(metadata.blocks() * 512 <= 128 * 1024, "fixture must remain sparse");
        drop(file);
        super::sync_files(&[path.to_string_lossy().into_owned()]).expect("admit clipboard file");

        for (index, offset) in offsets.iter().enumerate() {
            let responses = super::read_file_contents(71, index as i32, 0, 2,
                *offset as u32 as i32, (*offset >> 32) as u32 as i32, 4);
            let mut content = None;
            for response in responses {
                match response.expect("unsigned offset read failed") {
                    crate::ClipboardFile::FileContentsResponse { msg_flags, stream_id, requested_data } => {
                        assert!(content.is_none(), "one content response per request");
                        assert_eq!(msg_flags, 1);
                        assert_eq!(stream_id, index as i32);
                        content = Some(requested_data);
                    }
                    crate::ClipboardFile::Files { .. } if *offset == 0 => {}
                    other => panic!("unexpected clipboard response: {:?}", other),
                }
            }
            assert_eq!(content.as_deref(), Some([index as u8, 0x52, 0x44, 0xff].as_slice()));
        }
        for (index, low, high) in [(-1, 0, 0), (0, -1, -1),
            (0, metadata.len() as u32 as i32 + 1, (metadata.len() >> 32) as i32)] {
            assert!(super::read_file_contents(71, 90, index, 2, low, high, 4)
                .into_iter().any(|response| response.is_err()));
        }
        let responses = super::read_file_contents(71, 91, 0, 2,
            metadata.len() as u32 as i32, (metadata.len() >> 32) as i32, 4);
        assert!(matches!(responses.as_slice(), [Ok(crate::ClipboardFile::FileContentsResponse {
            msg_flags: 1, stream_id: 91, requested_data
        })] if requested_data.is_empty()));
        let responses = super::read_file_contents(71, 92, 0, 2, i32::MIN, 0, 4);
        assert!(matches!(responses.as_slice(), [Ok(crate::ClipboardFile::FileContentsResponse {
            msg_flags: 1, stream_id: 92, requested_data
        })] if requested_data.as_slice() == [2, 0x52, 0x44, 0xff]));
        super::clear_files();
        assert!(super::get_file_list_pdu().is_empty());
    }

    // §20: a peer FileContentsRequest with cb_requested=-1 makes length=u64::MAX; the old
    // `offset + length > file.size` wrapped, selected `length`, and over-allocated vec![0u8; length].
    #[test]
    fn clamp_file_read_size_is_overflow_safe() {
        assert_eq!(clamp_file_read_size(5, u64::MAX, 100), 95); // capped at remaining (95), NOT u64::MAX
        assert_eq!(clamp_file_read_size(0, 10, 100), 10); // normal read
        assert_eq!(clamp_file_read_size(90, 50, 100), 10); // length exceeds remaining -> clamp
        assert_eq!(clamp_file_read_size(100, 10, 100), 0); // at EOF -> 0
        assert_eq!(clamp_file_read_size(200, 10, 100), 0); // offset past EOF (saturating) -> 0
    }
}
