use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

struct OriginalResolution {
    size: (i32, i32),
}

#[derive(Default)]
pub(super) struct ResolutionRestorations {
    entries: RwLock<HashMap<String, Arc<OriginalResolution>>>,
}

impl ResolutionRestorations {
    pub(super) fn record(&self, name: &str, original: (i32, i32)) {
        let mut entries = self.entries.write().unwrap();
        let size = entries.get(name).map(|entry| entry.size).unwrap_or(original);
        // Each publication revokes older restoration claims, even for the same size.
        entries.insert(name.to_owned(), Arc::new(OriginalResolution { size }));
    }

    pub(super) fn original(&self, name: &str) -> Option<(i32, i32)> {
        self.entries.read().unwrap().get(name).map(|entry| entry.size)
    }

    #[cfg(any(not(any(target_os = "android", target_os = "ios")), test))]
    pub(super) fn restore<F>(&self, mut restore: F) -> Result<(), String>
    where
        F: FnMut(&str, usize, usize) -> Result<(), String>,
    {
        let pending = self
            .entries
            .read()
            .unwrap()
            .iter()
            .map(|(name, entry)| (name.clone(), Arc::clone(entry)))
            .collect::<Vec<_>>();
        let mut failures = Vec::new();
        for (name, entry) in pending {
            let (w, h) = entry.size;
            let (width, height) = match (usize::try_from(w), usize::try_from(h)) {
                (Ok(width), Ok(height)) if width > 0 && height > 0 => (width, height),
                _ => {
                    failures.push(format!("{name}: invalid stored resolution ({w},{h})"));
                    continue;
                }
            };
            if let Err(error) = restore(&name, width, height) {
                failures.push(format!("{name}: {error}"));
                continue;
            }
            let mut current = self.entries.write().unwrap();
            match current.get(&name) {
                Some(current_entry) if Arc::ptr_eq(current_entry, &entry) => {
                    current.remove(&name);
                }
                Some(_) => failures.push(format!(
                    "{name}: resolution record changed during restoration"
                )),
                None => {}
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Failed to restore one or more changed resolutions: {}",
                failures.join("; ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResolutionRestorations;
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{mpsc, Arc},
        thread,
        time::Duration,
    };

    #[test]
    fn r_s11iu_r_t4_remembers_first_original_until_success() {
        let restorations = ResolutionRestorations::default();
        restorations.record("DP-1", (1920, 1080));
        restorations.record("DP-1", (1280, 720));
        restorations.record("eDP-1", (2560, 1440));
        assert_eq!(restorations.original("DP-1"), Some((1920, 1080)));
        let mut calls = Vec::new();
        restorations
            .restore(|name, width, height| {
                calls.push((name.to_owned(), width, height));
                Ok(())
            })
            .unwrap();
        calls.sort();
        assert_eq!(
            calls,
            vec![
                ("DP-1".to_owned(), 1920, 1080),
                ("eDP-1".to_owned(), 2560, 1440)
            ]
        );
        assert_eq!(restorations.original("DP-1"), None);
        assert_eq!(restorations.original("eDP-1"), None);
        restorations.record("DP-1", (1280, 720));
        assert_eq!(restorations.original("DP-1"), Some((1280, 720)));
    }

    #[test]
    fn r_s11iu_r_t4_failed_restore_retains_for_retry() {
        let restorations = ResolutionRestorations::default();
        restorations.record("failed", (1920, 1080));
        restorations.record("restored", (2560, 1440));
        let error = restorations
            .restore(|name, _, _| {
                if name == "failed" {
                    Err("native refusal".to_owned())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.contains("failed: native refusal"));
        assert_eq!(restorations.original("restored"), None);
        assert_eq!(restorations.original("failed"), Some((1920, 1080)));
        restorations
            .restore(|name, width, height| {
                assert_eq!((name, width, height), ("failed", 1920, 1080));
                Ok(())
            })
            .unwrap();
        assert_eq!(restorations.original("failed"), None);
    }

    #[test]
    fn r_s11iu_r_t4_invalid_originals_refuse_callback() {
        let restorations = ResolutionRestorations::default();
        for (name, size) in [("negative", (-1, 1080)), ("zero", (1920, 0))] {
            restorations.record(name, size);
        }
        let error = restorations
            .restore(|_, _, _| panic!("invalid native call"))
            .unwrap_err();
        assert!(error.contains("negative: invalid stored resolution (-1,1080)"));
        assert!(error.contains("zero: invalid stored resolution (1920,0)"));
        assert_eq!(restorations.original("negative"), Some((-1, 1080)));
        assert_eq!(restorations.original("zero"), Some((1920, 0)));
    }

    fn replacement_during_restore(retire_before_republication: bool) {
        let restorations = Arc::new(ResolutionRestorations::default());
        restorations.record("DP-1", (1920, 1080));
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker_state = Arc::clone(&restorations);
        let worker = thread::spawn(move || {
            worker_state.restore(|name, width, height| {
                assert_eq!((name, width, height), ("DP-1", 1920, 1080));
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(())
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        if retire_before_republication {
            restorations.restore(|_, _, _| Ok(())).unwrap();
            assert_eq!(restorations.original("DP-1"), None);
        }
        restorations.record("DP-1", (1920, 1080));
        release_tx.send(()).unwrap();
        let error = worker.join().unwrap().unwrap_err();
        assert!(error.contains("DP-1: resolution record changed during restoration"));
        assert_eq!(restorations.original("DP-1"), Some((1920, 1080)));
        restorations
            .restore(|name, width, height| {
                assert_eq!((name, width, height), ("DP-1", 1920, 1080));
                Ok(())
            })
            .unwrap();
        assert_eq!(restorations.original("DP-1"), None);
    }

    #[test]
    fn r_s11iu_r_t4_identical_republication_survives_inflight_restore() {
        replacement_during_restore(false);
    }

    #[test]
    fn r_s11iu_r_t4_removed_and_republished_record_survives_old_completion() {
        replacement_during_restore(true);
    }

    #[test]
    fn r_s11iu_r_t4_callback_unwind_retains_record_without_poisoning() {
        let restorations = ResolutionRestorations::default();
        restorations.record("DP-1", (1920, 1080));
        assert!(catch_unwind(AssertUnwindSafe(|| {
            restorations.restore(|_, _, _| panic!("native callback unwind"))
        }))
        .is_err());
        assert_eq!(restorations.original("DP-1"), Some((1920, 1080)));
        restorations.restore(|_, _, _| Ok(())).unwrap();
        assert_eq!(restorations.original("DP-1"), None);
    }
}
