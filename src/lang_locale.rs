pub(super) fn select_language(configured: &str, locale: &str) -> String {
    if !configured.is_empty() {
        return configured.to_lowercase();
    }

    let locale = locale.to_lowercase();
    let (locale, modifier) = locale.split_once('@').unwrap_or((locale.as_str(), ""));
    let locale = locale.split('.').next().unwrap_or_default();
    // Java Locale.toString places the script after the country and variant.
    let (base, java_script) = match locale.split_once("_#") {
        Some((base, suffix)) => (base, suffix.split('_').next()),
        None => (locale, None),
    };
    let mut subtags = base.split(['-', '_']);
    let language = subtags.next().unwrap_or_default();
    if language == "no" {
        let first = subtags.next().unwrap_or_default();
        let region = if first.len() == 4 && first.bytes().all(|c| c.is_ascii_alphabetic()) {
            subtags.next().unwrap_or_default()
        } else {
            first
        };
        let variant = subtags.next().unwrap_or_default();
        // Default Norwegian uses Bokmål; explicit Nynorsk keeps its own language.
        let nynorsk = modifier == "nynorsk"
            || first == "nyn"
            || (region == "no"
                && (variant == "ny"
                    || (variant == "x"
                        && subtags.next() == Some("lvariant")
                        && subtags.next() == Some("ny")))
                && subtags.next().is_none());
        return if nynorsk { "nn" } else { "nb" }.to_owned();
    }
    if language != "zh" {
        // Map locale subtags to the catalogue's saved language keys.
        return match language {
            "ka" => "ge",
            "kk" => "kz",
            "iw" => "he",
            "in" => "id",
            _ => language,
        }
        .to_owned();
    }
    let first = subtags.next().unwrap_or_default();
    let (script, region) = if first.len() == 4 && first.bytes().all(|c| c.is_ascii_alphabetic()) {
        (Some(first), subtags.next().unwrap_or_default())
    } else {
        (java_script, first)
    };
    // An explicit script wins; CLDR's region defaults apply only otherwise.
    match script {
        Some("hant") => "zh-tw",
        Some("hans") => "zh-cn",
        _ if matches!(region, "tw" | "hk" | "mo") => "zh-tw",
        _ => "zh-cn",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::select_language;

    #[test]
    fn configured_language_takes_precedence() {
        for (configured, locale, expected) in [
            ("en", "zh-Hant-TW", "en"),
            ("zh-cn", "zh-Hant", "zh-cn"),
            ("ZH-TW", "zh-Hans-CN", "zh-tw"),
            ("he", "en_US", "he"),
            ("unknown", "zh-HK", "unknown"),
            ("ge", "kk-KZ", "ge"),
            ("kz", "ka-GE", "kz"),
            ("GE", "en-US", "ge"),
            ("KZ", "en-US", "kz"),
            ("en", "iw_IL", "en"),
            ("en", "in_ID", "en"),
            ("he", "in_ID", "he"),
            ("id", "iw_IL", "id"),
            ("en", "no_NO", "en"),
            ("nb", "no_NO_NY", "nb"),
            ("nn", "no_NO", "nn"),
            ("NB", "en_US", "nb"),
            ("pt", "pt_PT", "pt"),
            ("br", "pt_PT", "br"),
            ("pt-pt", "pt_BR", "pt-pt"),
            ("PT-PT", "en_US", "pt-pt"),
        ] {
            assert_eq!(select_language(configured, locale), expected);
        }
    }

    #[test]
    fn chinese_regions_select_the_supported_script() {
        for (locale, expected) in [
            ("zh", "zh-cn"), ("zh_CN", "zh-cn"), ("zh-SG", "zh-cn"),
            ("zh_TW", "zh-tw"), ("zh-HK", "zh-tw"), ("zh_MO", "zh-tw"),
            ("ZH_hK.UTF-8", "zh-tw"), ("zh_TW@calendar=roc", "zh-tw"),
        ] {
            assert_eq!(select_language("", locale), expected, "{locale}");
        }
    }

    #[test]
    fn explicit_script_wins_over_region() {
        for (locale, expected) in [
            ("zh-Hant", "zh-tw"), ("zh_Hant_CN", "zh-tw"),
            ("zh-Hant-SG", "zh-tw"), ("zh-Hans", "zh-cn"),
            ("zh_Hans_TW", "zh-cn"), ("zh-Hans-HK", "zh-cn"),
            ("zh-Hans-MO", "zh-cn"), ("ZH-hAnT-us", "zh-tw"),
        ] {
            assert_eq!(select_language("", locale), expected, "{locale}");
        }
    }

    #[test]
    fn java_locale_scripts_win_over_country_and_variant() {
        for (locale, expected) in [
            ("zh_CN_#Hans", "zh-cn"), ("zh_TW_#Hant_x-java", "zh-tw"),
            ("zh_CN_#Hant", "zh-tw"), ("zh_TW_#Hans", "zh-cn"),
            ("zh_HK_#Hans", "zh-cn"), ("zh_MO_#Hans", "zh-cn"),
            ("zh__#Hant", "zh-tw"), ("zh_CN_POSIX_#Hant", "zh-tw"),
        ] {
            assert_eq!(select_language("", locale), expected, "{locale}");
        }
    }

    #[test]
    fn extensions_do_not_override_script_or_region() {
        for (locale, expected) in [
            ("zh-CN-x-tw", "zh-cn"), ("zh-x-hant", "zh-cn"),
            ("zh-Hans-u-rg-twzzzz", "zh-cn"), ("zh-Hant-x-hans", "zh-tw"),
            ("zh-TW-x-hans", "zh-tw"), ("zh_CN_#u-rg-twzzzz", "zh-cn"),
            ("zh_CN_#Hans_x-tw", "zh-cn"), ("zh_TW_#Hant_x-hans", "zh-tw"),
        ] {
            assert_eq!(select_language("", locale), expected, "{locale}");
        }
    }

    #[test]
    fn georgian_locales_select_the_catalogue_language() {
        for locale in [
            "ka", "ka_GE", "ka-GE", "ka_Geor_GE", "KA-ge.UTF-8",
            "ka_GE@calendar=gregorian", "ka_GE_#Geor", "ka-u-ca-gregory",
        ] {
            assert_eq!(select_language("", locale), "ge", "{locale}");
        }
    }

    #[test]
    fn kazakh_locales_select_the_catalogue_language() {
        for locale in [
            "kk", "kk_KZ", "kk-KZ", "kk_Cyrl_KZ", "KK-kz.UTF-8",
            "kk_KZ@numbers=latn", "kk_KZ_#Cyrl", "kk-u-nu-latn",
        ] {
            assert_eq!(select_language("", locale), "kz", "{locale}");
        }
    }

    #[test]
    fn other_locales_keep_their_language() {
        for (locale, expected) in [
            ("en_US", "en"), ("he-IL", "he"), ("fr_FR.UTF-8", "fr"),
            ("de.UTF-8", "de"), ("pt_BR", "pt"), ("", ""),
            ("C", "c"), ("zhtw", "zhtw"), ("zhx-TW", "zhx"),
            ("en-GE", "en"), ("de-KZ", "de"), ("kaa", "kaa"), ("kkj", "kkj"),
            ("en-IW", "en"), ("en-IN", "en"), ("iwk", "iwk"), ("inh", "inh"),
            ("yi", "yi"), ("ji", "ji"),
            ("no", "nb"), ("no_NO", "nb"), ("no-NO", "nb"),
            ("NO_no.UTF-8", "nb"), ("no_NO@bokmal", "nb"),
            ("no_Latn_NO", "nb"), ("no_NO_#Latn", "nb"),
            ("no-u-nu-latn", "nb"), ("no-bok", "nb"),
            ("no_NO_BOKMAL", "nb"),
            ("nn", "nn"), ("nn_NO", "nn"), ("nn-Latn-NO", "nn"),
            ("no_NO_NY", "nn"), ("NO_no_NY.UTF-8", "nn"),
            ("no_NO_NY_#Latn", "nn"), ("no-NO-x-lvariant-NY", "nn"),
            ("no-nyn", "nn"), ("no_NO@nynorsk", "nn"),
            ("no_NO.UTF-8@nynorsk", "nn"), ("no-Latn-NO-x-lvariant-NY", "nn"),
            ("en_NO", "en"), ("nob", "nob"), ("non", "non"),
            ("no-x-nyn", "nb"), ("no-NO-x-example-NY", "nb"),
            ("pt_PT", "pt-pt"), ("pt-PT", "pt-pt"),
            ("PT_pt.UTF-8", "pt-pt"), ("pt_PT@euro", "pt-pt"),
            ("pt-Latn-PT", "pt-pt"), ("pt_PT_#Latn", "pt-pt"),
            ("pt-PT-u-nu-latn", "pt-pt"), ("pt-PT-x-br", "pt-pt"),
            ("pt", "pt"), ("pt-BR", "pt"), ("pt-Latn-BR", "pt"),
            ("pt-BR-x-pt", "pt"), ("pt-x-pt", "pt"),
            ("pt-u-rg-ptzzzz", "pt"), ("en-PT", "en"),
        ] {
            assert_eq!(select_language("", locale), expected, "{locale}");
        }
    }

    #[test]
    fn hebrew_platform_codes_select_the_catalogue_language() {
        for locale in [
            "iw_IL", "iw", "iw-IL", "IW_il.UTF-8", "iw_IL@calendar=hebrew",
            "iw_IL_#Hebr", "iw_Hebr_IL", "iw-u-ca-hebrew", "he", "he-IL",
        ] {
            assert_eq!(select_language("", locale), "he", "{locale}");
        }
    }

    #[test]
    fn indonesian_platform_codes_select_the_catalogue_language() {
        for locale in [
            "in_ID", "in", "in-ID", "IN_id.UTF-8", "in_ID@calendar=gregorian",
            "in_ID_#Latn", "in_Latn_ID", "in-u-nu-latn", "id", "id-ID",
        ] {
            assert_eq!(select_language("", locale), "id", "{locale}");
        }
    }
}
