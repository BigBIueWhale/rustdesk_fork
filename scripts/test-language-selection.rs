extern crate self as hbb_common;
pub use regex;

// Only configuration and application branding are fixture inputs. The language
// menu, selector, catalogues, fallback and substitution code are production code.
pub mod config {
    use std::cell::RefCell;

    thread_local! {
        static LANGUAGE: RefCell<String> = RefCell::new(String::new());
    }

    pub struct LocalConfig;

    impl LocalConfig {
        pub fn get_option(key: &str) -> String {
            assert_eq!(key, "lang");
            LANGUAGE.with(|language| language.borrow().clone())
        }
    }

    pub fn set_language(value: &str) {
        LANGUAGE.with(|language| *language.borrow_mut() = value.to_owned());
    }
}

pub fn is_rustdesk() -> bool {
    true
}

pub fn get_app_name() -> String {
    "RustDesk".to_owned()
}

mod lang;

mod allocation {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static USAGE: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    }

    fn record(bytes: usize) {
        let _ = USAGE.try_with(|usage| {
            if let Some((calls, total)) = usage.get() {
                usage.set(Some((calls.saturating_add(1), total.saturating_add(bytes))));
            }
        });
    }

    struct Counter;
    unsafe impl GlobalAlloc for Counter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record(layout.size());
            System.alloc(layout)
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record(layout.size());
            System.alloc_zeroed(layout)
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            record(size);
            System.realloc(pointer, layout, size)
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            System.dealloc(pointer, layout)
        }
    }

    #[global_allocator]
    static ALLOCATOR: Counter = Counter;

    pub fn during(action: impl FnOnce()) -> (usize, usize) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                USAGE.with(|usage| usage.set(None));
            }
        }
        USAGE.with(|usage| assert!(usage.replace(Some((0, 0))).is_none()));
        let guard = Reset;
        action();
        let result = USAGE.with(|usage| usage.get().unwrap());
        drop(guard);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{config::set_language, lang};

    #[test]
    fn portugal_and_brazil_use_distinct_catalogues() {
        set_language("");
        for (locale, expected) in [
            ("pt_PT", "Data de compilação"),
            ("pt-Latn-PT", "Data de compilação"),
            ("pt_PT_#Latn", "Data de compilação"),
            ("pt_BR", "Data da Build"),
            ("pt", "Data da Build"),
            ("fr_FR", "Date de compilation"),
            ("he_IL", "תאריך בנייה"),
        ] {
            assert_eq!(lang::translate_locale("Build Date".into(), locale), expected, "{locale}");
        }
    }

    #[test]
    fn saved_preferences_override_system_and_unknowns_fall_back() {
        for (configured, locale, expected) in [
            ("pt-pt", "pt_BR", "Data de compilação"),
            ("PT-PT", "en_US", "Data de compilação"),
            ("pt", "pt_PT", "Data da Build"),
            ("br", "pt_PT", "Data da Build"),
            ("en", "pt_PT", "Build date"),
            ("unknown", "pt_PT", "Build date"),
            ("", "unknown", "Build date"),
        ] {
            set_language(configured);
            assert_eq!(lang::translate_locale("Build Date".into(), locale), expected,
                "configured={configured} locale={locale}");
        }
        set_language("pt-pt");
        assert_eq!(lang::translate("Build Date".into()), "Data de compilação");
    }

    #[test]
    fn every_menu_language_returns_a_localized_notice() {
        let mut keys = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        let english = "Some chat history is no longer shown.";
        for &(key, name) in lang::LANGS {
            assert!(keys.insert(key), "duplicate language {key}");
            assert!(names.insert(name), "duplicate language label {name}");
            set_language(key);
            let notice = lang::translate_locale("chat-history-limited-tip".into(), "en_US");
            assert!(!notice.is_empty(), "{key}");
            assert_ne!(notice, "chat-history-limited-tip", "{key}");
            if key == "en" {
                assert_eq!(notice, english);
            } else {
                assert_ne!(notice, english, "English fallback for {key}");
            }
        }
        assert!(keys.contains("pt") && keys.contains("pt-pt"));
        assert_eq!(keys.len(), 50);
    }

    #[test]
    fn substitutions_preserve_unicode_and_literal_unknown_text() {
        for (configured, prefix) in [("pt-pt", "A transferir "), ("pt", "Baixando ")] {
            set_language(configured);
            for value in ["", "report.txt", "α/שלום.txt", "$1\\report.txt"] {
                let input = format!("Downloading {{{value}}}");
                assert_eq!(lang::translate_locale(input, "en_US"), format!("{prefix}{value}"));
            }
            for (input, expected) in [
                ("unknown status", "unknown status"),
                ("unknown {α} status", "unknown α status"),
                (" } { ", " } { "),
            ] {
                assert_eq!(lang::translate_locale(input.into(), "en_US"), expected);
            }
        }
    }

    #[test]
    fn repeated_labels_keep_allocation_work_bounded() {
        use super::allocation::during;

        assert_eq!(during(|| { std::hint::black_box(()); }), (0, 0));
        let control = during(|| { std::hint::black_box(vec![0u8; 4096]); });
        assert!(control.0 > 0 && control.1 >= 4096, "counter control: {control:?}");
        set_language("pt-pt");
        let mut measured = Vec::new();
        for (name, input, expected) in [
            ("plain", "Build Date", "Data de compilação"),
            ("placeholder", "Downloading {שלום.txt}", "A transferir שלום.txt"),
        ] {
            assert_eq!(lang::translate_locale(input.into(), "en_US"), expected);
            let (calls, bytes) = during(|| {
                for _ in 0..100 {
                    assert_eq!(lang::translate_locale(input.into(), "en_US"), expected);
                }
            });
            println!("LANGUAGE_SELECTION_ALLOCATION=cohort:{name} labels:100 calls:{calls} requested_bytes:{bytes} idle_control:0 positive_control:{}", control.1);
            measured.push((name, calls, bytes));
        }
        // A hundred short, warmed labels have room for their owned strings, but
        // not a newly compiled matching engine on every translation.
        for (name, calls, bytes) in measured {
            assert!(calls <= 1000 && bytes <= 64 * 1024, "{name}: {calls} allocations / {bytes} requested bytes");
        }
    }
}
