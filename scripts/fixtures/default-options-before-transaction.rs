use super::*;

trait HistoricalDefaultStore {
    fn store(&self);
}

impl HistoricalDefaultStore for UserDefaultConfig {
    fn store(&self) {
        Config::store_(self, "_default");
    }
}

impl UserDefaultConfig {
    pub fn set(&mut self, key: String, value: String) {
        if !is_option_can_save(
            &OVERWRITE_DISPLAY_SETTINGS,
            &key,
            &DEFAULT_DISPLAY_SETTINGS,
            &value,
        ) {
            if self.options.remove(&key).is_some() {
                self.store();
            }
            return;
        }
        if value.is_empty() {
            self.options.remove(&key);
        } else {
            self.options.insert(key, value);
        }
        self.store();
    }
}
