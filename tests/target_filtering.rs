use cargo_deny::{prune, Krates};
use cfg_expr::targets::ALL_TARGETS;

fn make_list(k: &Krates) -> String {
    let mut s = String::new();
    for krate in &k.krates {
        for p in krate.id.repr.split(' ').take(2) {
            s.push_str(p);
            s.push(' ');
        }

        s.truncate(s.len() - 1);
        s.push('\n');
    }

    s
}

macro_rules! check_krate_list {
    ($krates:expr, $expected:expr) => {
        let actual = make_list(&$krates);

        let mut expected = String::new();
        for item in $expected {
            expected.push_str(item);
            expected.push('\n');
        }

        if actual != expected {
            assert!(
                false,
                "\n{}",
                difference::Changeset::new(&expected, &actual, "\n")
            );
        }
    };
}

fn load() -> Krates {
    let md: cargo_metadata::Metadata =
        serde_json::from_str(&std::fs::read_to_string("tests/08_target_filtering.json").unwrap())
            .unwrap();

    Krates::from(md)
}

#[test]
fn prune_noop() {
    let mut krates = load();
    assert_eq!(krates.prune(None).unwrap(), 0);

    check_krate_list!(
        krates,
        vec![
            "anyhow 1.0.26",
            "bitflags 1.2.1",
            "bumpalo 2.6.0",
            "cc 1.0.48",
            "cfg-if 0.1.10",
            "difference 2.0.0",
            "heck 0.3.1",
            "js-sys 0.3.33",
            "lazy_static 1.4.0",
            "leftpad 0.2.0",
            "libc 0.2.66",
            "log 0.4.8",
            "memchr 2.2.1",
            "nix 0.16.1",
            "nom 4.2.3",
            "proc-macro2 1.0.6",
            "quote 1.0.2",
            "ring 0.16.9",
            "sourcefile 0.1.4",
            "spin 0.5.2",
            "syn 1.0.11",
            "target-filtering 0.1.0",
            "unicode-segmentation 1.6.0",
            "unicode-xid 0.2.0",
            "untrusted 0.7.0",
            "version_check 0.1.5",
            "void 1.0.2",
            "wasm-bindgen 0.2.56",
            "wasm-bindgen-backend 0.2.56",
            "wasm-bindgen-futures 0.4.6",
            "wasm-bindgen-macro 0.2.56",
            "wasm-bindgen-macro-support 0.2.56",
            "wasm-bindgen-shared 0.2.56",
            "wasm-bindgen-webidl 0.2.56",
            "web-sys 0.3.33",
            "weedle 0.10.0",
            "winapi 0.2.8",
            "winapi 0.3.8",
            "winapi-i686-pc-windows-gnu 0.4.0",
            "winapi-x86_64-pc-windows-gnu 0.4.0",
        ]
    );
}

#[test]
fn prune_all() {
    let mut krates = load();

    krates.prune(Some(prune::Prune::All)).unwrap();

    check_krate_list!(
        krates,
        vec![
            // "anyhow 1.0.26", - wasm-bindgen-webidl
            // "bitflags 1.2.1", - nix
            // "bumpalo 2.6.0", - wasm-bindgen-backend
            // "cc 1.0.48", - nix, ring
            // "cfg-if 0.1.10", nix
            "difference 2.0.0", // <- dev dependency for root crate
            // "heck 0.3.1", wasm-bindgen-webidl
            // "js-sys 0.3.33", wasm-bindgen-futures, web-sys
            // "lazy_static 1.4.0", wasm-bindgen-backend, ring
            "leftpad 0.2.0", // <- uncoditional root crate dependency
            // "libc 0.2.66", nix, ring, root
            // "log 0.4.8", wasm-bindgen-backend, wasm-bindgen-webidl
            // "memchr 2.2.1", wasm-bindgen-webidl
            // "nix 0.16.1", <- conditional dep for root crate
            // "nom 4.2.3", wasm-bindgen-webidl
            // "proc-macro2 1.0.6", wasm crates
            // "quote 1.0.2", <- ditto
            // "ring 0.16.9", <- conditional dep for root crate
            // "sourcefile 0.1.4", <- ring
            // "spin 0.5.2", <- ring, conditional root
            // "syn 1.0.11", <- wasm crates
            //  ROOT
            "target-filtering 0.1.0",
            // "unicode-segmentation 1.6.0", wasm-bindgen-webidl
            // "unicode-xid 0.2.0", wasm crates
            // "untrusted 0.7.0", ring
            // "version_check 0.1.5", nom
            // "void 1.0.2", nix
            // "wasm-bindgen 0.2.56", web-sys, wasm-bindgen-futures, js-sys
            // "wasm-bindgen-backend 0.2.56", wasm-bindgen-webidl, wasm-bindgen
            // "wasm-bindgen-futures 0.4.6", <- conditional dep for root crate
            // "wasm-bindgen-macro 0.2.56", wasm-bindgen
            // "wasm-bindgen-macro-support 0.2.56", wasm-bindgen
            // "wasm-bindgen-shared 0.2.56", wasm-bindgen
            // "wasm-bindgen-webidl 0.2.56", web-sys
            // "web-sys 0.3.33", ring, opt root dep
            // "weedle 0.10.0", wasm-bindgen-idl
            // "winapi 0.2.8", <- opt root dep
            // "winapi 0.3.8", <- opt root dep
            // "winapi-i686-pc-windows-gnu 0.4.0", winapi 0.3.8
            // "winapi-x86_64-pc-windows-gnu 0.4.0", winapi 0.3.8
        ]
    );
}

#[test]
fn prune_to_single_target() {
    {
        let mut krates = load();

        let triple = "x86_64-unknown-linux-gnu";

        let vanilla_linux = &ALL_TARGETS[ALL_TARGETS
            .binary_search_by(|ti| ti.triple.cmp(triple))
            .unwrap()];

        krates
            .prune(Some(prune::Prune::Except(&[prune::Target {
                target: vanilla_linux,
                features: Vec::new(),
            }])))
            .unwrap();

        check_krate_list!(
            krates,
            vec![
                // "anyhow 1.0.26", wasm-bindgen-webidl
                "bitflags 1.2.1", // nix
                // "bumpalo 2.6.0", wasm-bindgen-backend
                "cc 1.0.48",        // nix, ring
                "cfg-if 0.1.10",    // nix
                "difference 2.0.0", // <- dev dependency for root crate
                // "heck 0.3.1", wasm-bindgen-webidl
                // "js-sys 0.3.33", wasm-bindgen-futures, web-sys
                "lazy_static 1.4.0", // ring
                "leftpad 0.2.0",     // <- uncoditional root crate dependency
                "libc 0.2.66",       // nix, ring, root
                // "log 0.4.8", wasm-bindgen-backend, wasm-bindgen-webidl
                // "memchr 2.2.1", wasm-bindgen-webidl
                "nix 0.16.1", // brought in via target triple
                // "nom 4.2.3", wasm-bindgen-webidl
                // "proc-macro2 1.0.6", wasm crates
                // "quote 1.0.2", <- ditto
                "ring 0.16.9", // brought in via x86_64
                // "sourcefile 0.1.4", // ring (from web-sys)
                "spin 0.5.2", // ring, brought in via x86_64
                // "syn 1.0.11", <- wasm crates
                //  ROOT
                "target-filtering 0.1.0",
                // "unicode-segmentation 1.6.0", wasm-bindgen-webidl
                // "unicode-xid 0.2.0", wasm crates
                "untrusted 0.7.0", // ring
                // "version_check 0.1.5", nom
                // nix
                "void 1.0.2",
                // "wasm-bindgen 0.2.56", web-sys, wasm-bindgen-futures, js-sys
                // "wasm-bindgen-backend 0.2.56", wasm-bindgen-webidl, wasm-bindgen
                // "wasm-bindgen-futures 0.4.6", <- conditional dep for root crate
                // "wasm-bindgen-macro 0.2.56", wasm-bindgen
                // "wasm-bindgen-macro-support 0.2.56", wasm-bindgen
                // "wasm-bindgen-shared 0.2.56", wasm-bindgen
                // "wasm-bindgen-webidl 0.2.56", web-sys
                // "web-sys 0.3.33", ring, opt root dep
                // "weedle 0.10.0", wasm-bindgen-idl
                // "winapi 0.2.8", <- opt root dep
                // "winapi 0.3.8", <- opt root dep
                // "winapi-i686-pc-windows-gnu 0.4.0", winapi 0.3.8
                // "winapi-x86_64-pc-windows-gnu 0.4.0", winapi 0.3.8
            ]
        );
    }

    {
        let mut krates = load();

        let triple = "i686-pc-windows-msvc";

        let win = &ALL_TARGETS[ALL_TARGETS
            .binary_search_by(|ti| ti.triple.cmp(triple))
            .unwrap()];

        krates
            .prune(Some(prune::Prune::Except(&[prune::Target {
                target: win,
                features: Vec::new(),
            }])))
            .unwrap();

        check_krate_list!(
            krates,
            vec![
                // "anyhow 1.0.26", wasm-bindgen-webidl
                // "bitflags 1.2.1", // nix
                // "bumpalo 2.6.0", wasm-bindgen-backend
                // "cc 1.0.48",        // nix, ring
                // "cfg-if 0.1.10",    // nix
                "difference 2.0.0", // <- dev dependency for root crate
                // "heck 0.3.1", wasm-bindgen-webidl
                // "js-sys 0.3.33", wasm-bindgen-futures, web-sys
                // "lazy_static 1.4.0", // ring
                "leftpad 0.2.0", // <- uncoditional root crate dependency
                // "libc 0.2.66",       // nix, ring, root
                // "log 0.4.8", wasm-bindgen-backend, wasm-bindgen-webidl
                // "memchr 2.2.1", wasm-bindgen-webidl
                // "nix 0.16.1",
                // "nom 4.2.3", wasm-bindgen-webidl
                // "proc-macro2 1.0.6", wasm crates
                // "quote 1.0.2", <- ditto
                // "ring 0.16.9", not for i686
                // "sourcefile 0.1.4", // ring (from web-sys)
                "spin 0.5.2", // ring, brought in via x86_64
                // "syn 1.0.11", <- wasm crates
                //  ROOT
                "target-filtering 0.1.0",
                // "unicode-segmentation 1.6.0", wasm-bindgen-webidl
                // "unicode-xid 0.2.0", wasm crates
                // "untrusted 0.7.0", // ring
                // "version_check 0.1.5", nom
                //"void 1.0.2", nix
                // "wasm-bindgen 0.2.56", web-sys, wasm-bindgen-futures, js-sys
                // "wasm-bindgen-backend 0.2.56", wasm-bindgen-webidl, wasm-bindgen
                // "wasm-bindgen-futures 0.4.6", <- conditional dep for root crate
                // "wasm-bindgen-macro 0.2.56", wasm-bindgen
                // "wasm-bindgen-macro-support 0.2.56", wasm-bindgen
                // "wasm-bindgen-shared 0.2.56", wasm-bindgen
                // "wasm-bindgen-webidl 0.2.56", web-sys
                // "web-sys 0.3.33", ring, opt root dep
                // "weedle 0.10.0", wasm-bindgen-idl
                // brought in via target_os = windows
                "winapi 0.2.8",
                // "winapi 0.3.8", <- opt root dep
                // "winapi-i686-pc-windows-gnu 0.4.0", winapi 0.3.8
                // "winapi-x86_64-pc-windows-gnu 0.4.0", winapi 0.3.8
            ]
        );
    }

    {
        let mut krates = load();

        let triple = "x86_64-pc-windows-msvc";

        let win = &ALL_TARGETS[ALL_TARGETS
            .binary_search_by(|ti| ti.triple.cmp(triple))
            .unwrap()];

        krates
            .prune(Some(prune::Prune::Except(&[prune::Target {
                target: win,
                features: Vec::new(),
            }])))
            .unwrap();

        check_krate_list!(
            krates,
            vec![
                // "anyhow 1.0.26", wasm-bindgen-webidl
                // "bitflags 1.2.1", // nix
                // "bumpalo 2.6.0", wasm-bindgen-backend
                "cc 1.0.48", // nix, ring
                // "cfg-if 0.1.10",    // nix
                "difference 2.0.0", // <- dev dependency for root crate
                // "heck 0.3.1", wasm-bindgen-webidl
                // "js-sys 0.3.33", wasm-bindgen-futures, web-sys
                // "lazy_static 1.4.0", // ring, not for windows though!
                "leftpad 0.2.0", // <- uncoditional root crate dependency
                // "libc 0.2.66",       // nix, ring, root
                // "log 0.4.8", wasm-bindgen-backend, wasm-bindgen-webidl
                // "memchr 2.2.1", wasm-bindgen-webidl
                // "nix 0.16.1",
                // "nom 4.2.3", wasm-bindgen-webidl
                // "proc-macro2 1.0.6", wasm crates
                // "quote 1.0.2", <- ditto
                "ring 0.16.9", // brought in by x86_64
                // "sourcefile 0.1.4", // ring (from web-sys)
                "spin 0.5.2", // ring, brought in via x86_64
                // "syn 1.0.11", <- wasm crates
                //  ROOT
                "target-filtering 0.1.0",
                // "unicode-segmentation 1.6.0", wasm-bindgen-webidl
                // "unicode-xid 0.2.0", wasm crates
                "untrusted 0.7.0", // ring
                // "version_check 0.1.5", nom
                //"void 1.0.2", nix
                // "wasm-bindgen 0.2.56", web-sys, wasm-bindgen-futures, js-sys
                // "wasm-bindgen-backend 0.2.56", wasm-bindgen-webidl, wasm-bindgen
                // "wasm-bindgen-futures 0.4.6", <- conditional dep for root crate
                // "wasm-bindgen-macro 0.2.56", wasm-bindgen
                // "wasm-bindgen-macro-support 0.2.56", wasm-bindgen
                // "wasm-bindgen-shared 0.2.56", wasm-bindgen
                // "wasm-bindgen-webidl 0.2.56", web-sys
                // "web-sys 0.3.33", ring, opt root dep
                // "weedle 0.10.0", wasm-bindgen-idl
                // brought in via target_os = windows
                "winapi 0.2.8",
                // ring
                "winapi 0.3.8",
                // "winapi-i686-pc-windows-gnu 0.4.0", winapi 0.3.8
                // "winapi-x86_64-pc-windows-gnu 0.4.0", winapi 0.3.8
            ]
        );
    }
}

#[test]
fn prune_to_3_targets() {
    let mut krates = load();

    let triples = [
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "wasm32-unknown-unknown",
    ];

    let targets: Vec<_> = triples
        .iter()
        .map(|t| prune::Target {
            target: &ALL_TARGETS[ALL_TARGETS.binary_search_by(|ti| ti.triple.cmp(t)).unwrap()],
            features: Vec::new(),
        })
        .collect();

    krates.prune(Some(prune::Prune::Except(&targets))).unwrap();

    check_krate_list!(
        krates,
        vec![
            "anyhow 1.0.26",     // wasm-bindgen-webidl
            "bitflags 1.2.1",    // nix
            "bumpalo 2.6.0",     // wasm-bindgen-backend
            "cc 1.0.48",         // nix, ring
            "cfg-if 0.1.10",     // nix
            "difference 2.0.0",  // <- dev dependency for root crate
            "heck 0.3.1",        // wasm-bindgen-webidl
            "js-sys 0.3.33",     // wasm-bindgen-futures, web-sys
            "lazy_static 1.4.0", // ring, not for windows though!
            "leftpad 0.2.0",     // <- uncoditional root crate dependency
            "libc 0.2.66",       // nix, ring, root
            "log 0.4.8",         // wasm-bindgen-backend, wasm-bindgen-webidl
            "memchr 2.2.1",      // wasm-bindgen-webidl
            "nix 0.16.1",
            "nom 4.2.3",         // wasm-bindgen-webidl
            "proc-macro2 1.0.6", // wasm crates
            "quote 1.0.2",
            "ring 0.16.9",      // brought in by x86_64
            "sourcefile 0.1.4", // ring (from web-sys)
            "spin 0.5.2",       // ring, brought in via x86_64
            "syn 1.0.11",       // wasm crates
            //  ROOT
            "target-filtering 0.1.0",
            "unicode-segmentation 1.6.0",  // wasm-bindgen-webidl
            "unicode-xid 0.2.0",           // wasm crates
            "untrusted 0.7.0",             // ring
            "version_check 0.1.5",         // nom
            "void 1.0.2",                  // nix
            "wasm-bindgen 0.2.56",         // web-sys, wasm-bindgen-futures, js-sys
            "wasm-bindgen-backend 0.2.56", // wasm-bindgen-webidl, wasm-bindgen
            // "wasm-bindgen-futures 0.4.6", still doesn't have target_feature = atomics
            "wasm-bindgen-macro 0.2.56",         // wasm-bindgen
            "wasm-bindgen-macro-support 0.2.56", // wasm-bindgen
            "wasm-bindgen-shared 0.2.56",        // wasm-bindgen
            "wasm-bindgen-webidl 0.2.56",        // web-sys
            "web-sys 0.3.33",                    // ring, opt root dep
            "weedle 0.10.0",                     // wasm-bindgen-idl
            // brought in via target_os = windows
            "winapi 0.2.8",
            // ring
            "winapi 0.3.8",
            // "winapi-i686-pc-windows-gnu 0.4.0", winapi 0.3.8
            // "winapi-x86_64-pc-windows-gnu 0.4.0", winapi 0.3.8
        ]
    );
}

#[test]
fn prune_with_target_features() {
    let mut krates = load();

    let triples = [
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "wasm32-unknown-unknown",
    ];

    let targets: Vec<_> = triples
        .iter()
        .map(|t| prune::Target {
            target: &ALL_TARGETS[ALL_TARGETS.binary_search_by(|ti| ti.triple.cmp(t)).unwrap()],
            features: if *t == "wasm32-unknown-unknown" {
                vec!["atomics".to_owned()]
            } else {
                Vec::new()
            },
        })
        .collect();

    krates.prune(Some(prune::Prune::Except(&targets))).unwrap();

    check_krate_list!(
        krates,
        vec![
            "anyhow 1.0.26",     // wasm-bindgen-webidl
            "bitflags 1.2.1",    // nix
            "bumpalo 2.6.0",     // wasm-bindgen-backend
            "cc 1.0.48",         // nix, ring
            "cfg-if 0.1.10",     // nix
            "difference 2.0.0",  // <- dev dependency for root crate
            "heck 0.3.1",        // wasm-bindgen-webidl
            "js-sys 0.3.33",     // wasm-bindgen-futures, web-sys
            "lazy_static 1.4.0", // ring, not for windows though!
            "leftpad 0.2.0",     // <- uncoditional root crate dependency
            "libc 0.2.66",       // nix, ring, root
            "log 0.4.8",         // wasm-bindgen-backend, wasm-bindgen-webidl
            "memchr 2.2.1",      // wasm-bindgen-webidl
            "nix 0.16.1",
            "nom 4.2.3",         // wasm-bindgen-webidl
            "proc-macro2 1.0.6", // wasm crates
            "quote 1.0.2",
            "ring 0.16.9",      // brought in by x86_64
            "sourcefile 0.1.4", // ring (from web-sys)
            "spin 0.5.2",       // ring, brought in via x86_64
            "syn 1.0.11",       // wasm crates
            //  ROOT
            "target-filtering 0.1.0",
            "unicode-segmentation 1.6.0",        // wasm-bindgen-webidl
            "unicode-xid 0.2.0",                 // wasm crates
            "untrusted 0.7.0",                   // ring
            "version_check 0.1.5",               // nom
            "void 1.0.2",                        // nix
            "wasm-bindgen 0.2.56",               // web-sys, wasm-bindgen-futures, js-sys
            "wasm-bindgen-backend 0.2.56",       // wasm-bindgen-webidl, wasm-bindgen
            "wasm-bindgen-futures 0.4.6",        // atomics target_feature is enabled
            "wasm-bindgen-macro 0.2.56",         // wasm-bindgen
            "wasm-bindgen-macro-support 0.2.56", // wasm-bindgen
            "wasm-bindgen-shared 0.2.56",        // wasm-bindgen
            "wasm-bindgen-webidl 0.2.56",        // web-sys
            "web-sys 0.3.33",                    // ring, opt root dep
            "weedle 0.10.0",                     // wasm-bindgen-idl
            // brought in via target_os = windows
            "winapi 0.2.8",
            // ring
            "winapi 0.3.8",
            // "winapi-i686-pc-windows-gnu 0.4.0", winapi 0.3.8
            // "winapi-x86_64-pc-windows-gnu 0.4.0", winapi 0.3.8
        ]
    );
}

#[test]
fn test_graph() {
    let md: cargo_metadata::Metadata =
        serde_json::from_str(&std::fs::read_to_string("tests/08_target_filtering.json").unwrap())
            .unwrap();

    let mut krates = cargo_deny::graph::Krates2::new(md).unwrap();

    let triple = "i686-pc-windows-msvc";

    let win = &ALL_TARGETS[ALL_TARGETS
        .binary_search_by(|ti| ti.triple.cmp(triple))
        .unwrap()];

    assert_eq!(
        krates
            .prune(Some(prune::Prune::Except(&[prune::Target {
                target: win,
                features: Vec::new()
            }])))
            .unwrap(),
        35
    );
}
