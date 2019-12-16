pub(crate) fn search_match(
    krates: &[crate::KrateDetails],
    name: &str,
    req: &semver::VersionReq,
) -> Option<usize> {
    match search_name(krates, name) {
        Ok(rng) => {
            for i in rng {
                let krate = &krates[i];
                if req.matches(&krate.version) {
                    return Some(i);
                }
            }

            None
        }
        Err(_) => None,
    }
}

pub(crate) fn search_name(
    krates: &[crate::KrateDetails],
    name: &str,
) -> Result<std::ops::Range<usize>, usize> {
    let lowest = semver::Version::new(0, 0, 0);

    match krates.binary_search_by(|i| match i.name.as_str().cmp(&name) {
        std::cmp::Ordering::Equal => i.version.cmp(&lowest),
        o => o,
    }) {
        Ok(i) | Err(i) => {
            if i >= krates.len() || krates[i].name != name {
                return Err(i);
            }

            // Backtrack 1 if the crate name matches, as, for instance, wildcards will be sorted
            // before the 0.0.0 version
            let begin = if i > 0 && krates[i - 1].name == name {
                i - 1
            } else {
                i
            };

            let end = krates[begin..]
                .iter()
                .take_while(|kd| kd.name == name)
                .count()
                + begin;

            Ok(begin..end)
        }
    }
}

#[cfg(test)]
mod test {
    use super::search_name;

    #[test]
    fn search_by_name() {
        use crate::KrateDetails;

        macro_rules! kd {
            ($name:expr, $vs:expr) => {
                KrateDetails {
                    name: $name.to_owned(),
                    version: semver::Version::parse($vs).unwrap(),
                    ..Default::default()
                }
            };
        }

        let krates = [
            kd!("adler32", "1.0.4"),
            kd!("aho-corasick", "0.7.6"),
            kd!("alsa-sys", "0.1.2"),
            kd!("andrew", "0.2.1"),
            kd!("android_glue", "0.2.3"),
            kd!("ansi_term", "0.11.0"),
            kd!("anyhow", "1.0.18"),
            kd!("anymap", "0.12.1"),
            kd!("app_dirs2", "2.0.4"),
            kd!("approx", "0.3.2"),
            kd!("arrayref", "0.3.5"),
            kd!("arrayvec", "0.4.12"),
            kd!("arrayvec", "0.5.1"),
            kd!("ash", "0.29.0"),
            kd!("ash-molten", "0.2.0+37"),
            kd!("assert-json-diff", "1.0.1"),
            kd!("async-stream", "0.1.2"),
            kd!("async-stream-impl", "0.1.1"),
            kd!("async-trait", "0.1.17"),
            kd!("atk-sys", "0.6.0"),
            kd!("atty", "0.2.13"),
            kd!("autocfg", "0.1.7"),
            kd!("backoff", "0.1.5"),
            kd!("backtrace", "0.3.40"),
            kd!("backtrace-sys", "0.1.32"),
            kd!("base-x", "0.2.6"),
            kd!("base64", "0.10.1"),
            kd!("bincode", "1.2.0"),
            kd!("bindgen", "0.51.1"),
            kd!("bitflags", "1.2.1"),
            kd!("core-foundation", "0.6.4"),
            kd!("core-foundation-sys", "0.6.2"),
            kd!("core-graphics", "0.17.3"),
            kd!("coreaudio-rs", "0.9.1"),
            kd!("coreaudio-sys", "0.2.3"),
            kd!("crossbeam", "0.7.2"),
            kd!("crossbeam-channel", "0.3.9"),
            kd!("crossbeam-deque", "0.7.1"),
            kd!("crossbeam-epoch", "0.7.2"),
            kd!("crossbeam-queue", "0.1.2"),
            kd!("crossbeam-utils", "0.6.6"),
            kd!("hex", "0.3.2"),
            kd!("hyper", "0.12.35"),
            kd!("hyper", "0.13.0-alpha.4"),
            kd!("hyper-rustls", "0.17.1"),
            kd!("tokio", "0.1.22"),
            kd!("tokio", "0.2.0-alpha.6"),
            kd!("tokio-buf", "0.1.1"),
            kd!("tokio-codec", "0.1.1"),
            kd!("tokio-codec", "0.2.0-alpha.6"),
            kd!("tokio-current-thread", "0.1.6"),
            kd!("tokio-executor", "0.1.8"),
            kd!("tokio-executor", "0.2.0-alpha.6"),
            kd!("tokio-fs", "0.1.6"),
            kd!("tokio-fs", "0.2.0-alpha.6"),
            kd!("tokio-io", "0.1.12"),
            kd!("tokio-io", "0.2.0-alpha.6"),
            kd!("tokio-macros", "0.2.0-alpha.6"),
            kd!("tokio-net", "0.2.0-alpha.6"),
            kd!("tokio-reactor", "0.1.10"),
            kd!("tokio-rustls", "0.10.2"),
            kd!("tokio-sync", "0.1.7"),
            kd!("tokio-sync", "0.2.0-alpha.6"),
            kd!("tokio-tcp", "0.1.3"),
            kd!("tokio-threadpool", "0.1.16"),
            kd!("tokio-timer", "0.2.11"),
            kd!("tokio-timer", "0.3.0-alpha.6"),
            kd!("tokio-udp", "0.1.5"),
            kd!("tokio-uds", "0.2.5"),
            kd!("tonic", "0.1.0-alpha.4"),
            kd!("tonic-build", "0.1.0-alpha.4"),
            kd!("tower", "0.1.1"),
            kd!("tower", "0.3.0-alpha.2"),
            kd!("tower-balance", "0.3.0-alpha.2"),
            kd!("tower-buffer", "0.1.2"),
            kd!("tower-buffer", "0.3.0-alpha.2"),
            kd!("tower-discover", "0.1.0"),
            kd!("tower-discover", "0.3.0-alpha.2"),
            kd!("tower-http-util", "0.1.0"),
            kd!("tower-hyper", "0.1.1"),
            kd!("tower-layer", "0.1.0"),
            kd!("tower-layer", "0.3.0-alpha.2"),
            kd!("tower-limit", "0.1.1"),
            kd!("tower-limit", "0.3.0-alpha.2"),
            kd!("tower-load", "0.3.0-alpha.2"),
            kd!("tower-load-shed", "0.1.0"),
            kd!("tower-load-shed", "0.3.0-alpha.2"),
            kd!("tower-make", "0.3.0-alpha.2a"),
            kd!("tower-reconnect", "0.3.0-alpha.2"),
            kd!("tower-request-modifier", "0.1.0"),
            kd!("tower-retry", "0.1.0"),
            kd!("tower-retry", "0.3.0-alpha.2"),
            kd!("tower-service", "0.2.0"),
            kd!("tower-service", "0.3.0-alpha.2"),
            kd!("tower-timeout", "0.1.1"),
            kd!("tower-timeout", "0.3.0-alpha.2"),
            kd!("tower-util", "0.1.0"),
            kd!("tower-util", "0.3.0-alpha.2"),
            kd!("tracing", "0.1.10"),
            kd!("tracing-attributes", "0.1.5"),
            kd!("tracing-core", "0.1.7"),
        ];

        assert_eq!(search_name(&krates, "adler32",), Ok(0..1));
        assert_eq!(search_name(&krates, "tower-service",).unwrap().len(), 2);
        assert_eq!(search_name(&krates, "tracing",).unwrap().len(), 1);
        assert_eq!(search_name(&krates, "tokio-codec",).unwrap().len(), 2);

        // Ensure that searching for a crate that doesn't exist, but would be sorted at the end
        // does not cause and out of bounds panic
        assert_eq!(search_name(&krates, "winit",), Err(krates.len()));
    }
}
