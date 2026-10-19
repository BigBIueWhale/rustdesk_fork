use super::*;

trait HistoricalPeerStore {
    fn store(&self, id: &str);
    fn store_(&self, id: &str);
    fn store_path_(path: &Path, config: &PeerConfig);
}

impl HistoricalPeerStore for PeerConfig {
    fn store(&self, id: &str) {
        let _lock = CONFIG.read().unwrap();
        self.store_(id);
    }

    fn store_(&self, id: &str) {
        Self::store_path_(&Self::path(id), self);
        NEW_STORED_PEER_CONFIG.lock().unwrap().insert(id.to_owned());
    }

    fn store_path_(path: &Path, config: &PeerConfig) {
        let mut config = config.clone();
        config.password =
            encrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        // R-S16 (viewer twin): the DERIVED Argon2id CPace PRS, encrypted at rest like `password`.
        config.password_prs =
            encrypt_vec_or_original(&config.password_prs, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        remove_retired_rdp_credential_options(&mut config.options);
        if let Err(err) = store_path(path.to_path_buf(), config) {
            log::error!("Failed to store config: {}", err);
        }
    }

}

pub fn store_before(config: &PeerConfig, id: &str) {
    HistoricalPeerStore::store(config, id);
}
