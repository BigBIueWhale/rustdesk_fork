use hbb_common::ResultType;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

#[cfg(feature = "flutter")]
pub mod account;
// R-SV1 / R-X1: hbbs_http::downloader (a reqwest-GET fetch-to-buffer subsystem) is excised — it was
// orphaned by the R-X1 updater excision: its sole starter (the `download-new-version` Flutter key +
// the deleted updater::get_download_file_from_url) is gone, so `download_file` had no caller and the
// `download-data-`/`remove-downloader`/`cancel-downloader` Dart keys were unreachable. Removed, not
// merely neutralized: the binary cannot perform that GET because the code is gone (sovereign posture).
mod http_client;
// R-SV6 / R-SV1: hbbs_http::record_upload (the session-record reqwest POST egress) is excised — the
// module is removed, not just its is_enable() neutralized. Recording stays local (R-D6, dial nobody).
pub mod sync;
pub use http_client::{create_http_client_async, get_url_for_tls};

#[derive(Debug)]
pub enum HbbHttpResponse<T> {
    ErrorFormat,
    Error(String),
    DataTypeFormat,
    Data(T),
}

impl<T: DeserializeOwned> HbbHttpResponse<T> {
    pub fn parse(body: &str) -> ResultType<Self> {
        let map = serde_json::from_str::<Map<String, Value>>(body)?;
        if let Some(error) = map.get("error") {
            if let Some(err) = error.as_str() {
                Ok(Self::Error(err.to_owned()))
            } else {
                Ok(Self::ErrorFormat)
            }
        } else {
            match serde_json::from_value(Value::Object(map)) {
                Ok(v) => Ok(Self::Data(v)),
                Err(_) => Ok(Self::DataTypeFormat),
            }
        }
    }
}
