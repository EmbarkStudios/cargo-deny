use cargo_deny::{
    licenses::{self, CrateNote, Gatherer, LicenseField, LicenseSource, Note},
    CrateDetails, Version,
};
use std::collections::HashMap;
use tempfile::TempDir;

macro_rules! check_gather {
    ($crates:expr, $expected:expr) => {
        check_gather!($crates, $expected, Gatherer::default(), HashMap::new())
    };

    ($crates:expr, $expected:expr, $gatherer:expr) => {
        check_gather!($crates, $expected, $gatherer, HashMap::new())
    };

    ($crates:expr, $expected:expr, $gatherer:expr, $ignore:expr) => {
        let summary = $gatherer.gather(&$crates, $ignore);
        let expected = $expected;

        if expected.iter().ne(summary.notes()) {
            let notes: Vec<_> = summary.notes().collect();
            let notes = format!("{:#?}", notes);
            let expected = format!("{:#?}", expected);

            let cs = difference::Changeset::new(&expected, &notes, "\n");

            assert!(false, "{}", cs);
        }
    };
}

#[test]
fn handles_spdx_id_in_metadata() {
    let crates = vec![CrateDetails {
        license: LicenseField::new("MIT".to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![Note::License {
                name: license_exprs::license_id("MIT").unwrap(),
                source: LicenseSource::Metadata,
            }]
        }]
    );
}

#[test]
fn handles_multiple_spdx_id_in_metadata() {
    let crates = vec![CrateDetails {
        license: LicenseField::new("MIT/Apache-2.0".to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::License {
                    name: license_exprs::license_id("MIT").unwrap(),
                    source: LicenseSource::Metadata,
                },
                Note::License {
                    name: license_exprs::license_id("Apache-2.0").unwrap(),
                    source: LicenseSource::Metadata,
                }
            ]
        }]
    );
}

#[test]
fn handles_exception_in_metadata() {
    let crates = vec![CrateDetails {
        license: LicenseField::new("MIT OR Apache-2.0 WITH LLVM-exception".to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::License {
                    name: license_exprs::license_id("MIT").unwrap(),
                    source: LicenseSource::Metadata,
                },
                Note::License {
                    name: license_exprs::license_id("Apache-2.0").unwrap(),
                    source: LicenseSource::Metadata,
                },
                Note::Exception("LLVM-exception"),
            ]
        }]
    );
}

#[test]
fn handles_unknown_spdx_id_in_metadata() {
    let crates = vec![CrateDetails {
        license: LicenseField::new(
            "Embark-Proprietary OR Apache-2.0 WITH LLVM-exception".to_owned(),
        ),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::Unknown {
                    name: "Embark-Proprietary".to_owned(),
                    source: LicenseSource::Metadata,
                },
                Note::License {
                    name: license_exprs::license_id("Apache-2.0").unwrap(),
                    source: LicenseSource::Metadata,
                },
                Note::Exception("LLVM-exception"),
            ]
        }]
    );
}

#[test]
fn handles_multiple_unknown_spdx_ids_in_metadata() {
    let crates = vec![CrateDetails {
        license: LicenseField::new("Embark-Proprietary OR This-Doesnt-Exist".to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::Unknown {
                    name: "Embark-Proprietary".to_owned(),
                    source: LicenseSource::Metadata,
                },
                Note::Unknown {
                    name: "This-Doesnt-Exist".to_owned(),
                    source: LicenseSource::Metadata,
                },
            ]
        }]
    );
}

#[test]
fn detects_unlicensed() {
    let crates = vec![CrateDetails::default()];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![Note::Unlicensed],
        }]
    );
}

lazy_static::lazy_static! {
    static ref STORE: std::sync::Arc<licenses::LicenseStore> = std::sync::Arc::new(licenses::LicenseStore::from_cache().unwrap());
}

use std::fs;

#[test]
fn analyzes_license_file() {
    let td = TempDir::new().unwrap();

    let license_path = td.path().join("LICENSE-MIT");
    fs::copy("./LICENSE-MIT", &license_path).expect("failed to copy license to tempdir");

    let crates = vec![CrateDetails {
        license_file: Some(license_path.clone()),
        root: Some(td.path().to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![Note::License {
                name: license_exprs::license_id("MIT").unwrap(),
                source: LicenseSource::Original(licenses::FileSource {
                    path: license_path,
                    hash: 0xa502ee8a,
                }),
            }],
        }],
        Gatherer::default().with_store(STORE.clone())
    );
}

#[test]
fn analyzes_inferred_license_file() {
    let td = TempDir::new().unwrap();

    let license_path = td.path().join("LICENSE-MIT");
    fs::copy("./LICENSE-MIT", &license_path).expect("failed to copy license to tempdir");

    let crates = vec![CrateDetails {
        root: Some(td.path().to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![Note::License {
                name: license_exprs::license_id("MIT").unwrap(),
                source: LicenseSource::Original(licenses::FileSource {
                    path: license_path,
                    hash: 0xa502ee8a,
                }),
            }],
        }],
        Gatherer::default().with_store(STORE.clone())
    );
}

#[test]
fn analyzes_multiple_inferred_license_files() {
    let td = TempDir::new().unwrap();

    let apache_path = td.path().join("LICENSE-APACHE");
    fs::copy("./LICENSE-APACHE", &apache_path).expect("failed to copy license to tempdir");

    let mit_path = td.path().join("LICENSE-MIT");
    fs::copy("./LICENSE-MIT", &mit_path).expect("failed to copy license to tempdir");

    let crates = vec![CrateDetails {
        root: Some(td.path().to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::License {
                    name: license_exprs::license_id("Apache-2.0").unwrap(),
                    source: LicenseSource::Original(licenses::FileSource {
                        path: apache_path,
                        hash: 0x4fccb6b7,
                    }),
                },
                Note::License {
                    name: license_exprs::license_id("MIT").unwrap(),
                    source: LicenseSource::Original(licenses::FileSource {
                        path: mit_path,
                        hash: 0xa502ee8a,
                    }),
                },
            ],
        }],
        Gatherer::default().with_store(STORE.clone())
    );
}

#[test]
fn analyzes_explicit_and_inferred_license_files() {
    let td = TempDir::new().unwrap();

    let apache_path = td.path().join("LICENSE-APACHE");
    fs::copy("./LICENSE-APACHE", &apache_path).expect("failed to copy license to tempdir");

    let mit_path = td.path().join("LICENSE-MIT");
    fs::copy("./LICENSE-MIT", &mit_path).expect("failed to copy license to tempdir");

    let crates = vec![CrateDetails {
        license_file: Some(mit_path.clone()),
        root: Some(td.path().to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::License {
                    name: license_exprs::license_id("Apache-2.0").unwrap(),
                    source: LicenseSource::Original(licenses::FileSource {
                        path: apache_path,
                        hash: 0x4fccb6b7,
                    }),
                },
                Note::License {
                    name: license_exprs::license_id("MIT").unwrap(),
                    source: LicenseSource::Original(licenses::FileSource {
                        path: mit_path,
                        hash: 0xa502ee8a,
                    }),
                }
            ],
        }],
        Gatherer::default().with_store(STORE.clone())
    );
}

#[test]
fn handles_unknown_explicit() {
    let td = TempDir::new().unwrap();

    let license_path = td.path().join("LICENSE");
    fs::copy("./tests/LICENSE-SUMMARY", &license_path).expect("failed to copy license to tempdir");

    let crates = vec![CrateDetails {
        license_file: Some(license_path.clone()),
        root: Some(td.path().to_owned()),
        ..Default::default()
    }];

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![Note::LowConfidence {
                score: 0.0,
                source: LicenseSource::Original(licenses::FileSource {
                    path: license_path,
                    hash: 0xe7dd8f38,
                }),
            }],
        }],
        Gatherer::default().with_store(STORE.clone())
    );
}

#[test]
fn ignores_explicit() {
    let td = TempDir::new().unwrap();

    let license_path = td.path().join("LICENSE");
    fs::copy("./tests/LICENSE-SUMMARY", &license_path).expect("failed to copy license to tempdir");

    let crates = vec![CrateDetails {
        license_file: Some(license_path.clone()),
        root: Some(td.path().to_owned()),
        ..Default::default()
    }];

    let mut cfg = licenses::Config {
        ignore: vec![licenses::IgnoreLicenses {
            name: "".to_owned(),
            version: None,
            license_files: vec![licenses::LicenseFile {
                path: std::path::PathBuf::from("LICENSE"),
                hash: 0xe7dd8f38,
            }],
        }],
        ..Default::default()
    };

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::Ignored(licenses::FileSource {
                    path: license_path,
                    hash: 0xe7dd8f38,
                }),
                Note::Unlicensed
            ],
        }],
        Gatherer::default().with_store(STORE.clone()),
        cfg.get_ignore_licenses()
    );
}

#[test]
fn ignores_implicit() {
    let td = TempDir::new().unwrap();

    let license_path = td.path().join("LICENSE");
    fs::copy("./tests/LICENSE-SUMMARY", &license_path).expect("failed to copy license to tempdir");

    let crates = vec![CrateDetails {
        root: Some(td.path().to_owned()),
        ..Default::default()
    }];

    let mut cfg = licenses::Config {
        ignore: vec![licenses::IgnoreLicenses {
            name: "".to_owned(),
            version: None,
            license_files: vec![licenses::LicenseFile {
                path: std::path::PathBuf::from("LICENSE"),
                hash: 0xe7dd8f38,
            }],
        }],
        ..Default::default()
    };

    check_gather!(
        crates,
        vec![CrateNote {
            name: "",
            version: Version::new(0, 1, 0),
            notes: vec![
                Note::Ignored(licenses::FileSource {
                    path: license_path,
                    hash: 0xe7dd8f38,
                }),
                Note::Unlicensed
            ],
        }],
        Gatherer::default().with_store(STORE.clone()),
        cfg.get_ignore_licenses()
    );
}

#[test]
fn normalizes_line_endings() {
    let fs = licenses::get_file_source(std::path::PathBuf::from("./tests/LICENSE-RING")).unwrap();

    let expected = {
        let text = std::fs::read_to_string("./tests/LICENSE-RING").unwrap();
        text.replace("\r\n", "\n")
    };

    let expected_hash = 0xbd0eed23;

    if expected_hash != fs.1.hash {
        eprintln!("hash: {:#x} != {:#x}", expected_hash, fs.1.hash);

        for (i, (a, b)) in fs.0.chars().zip(expected.chars()).enumerate() {
            assert_eq!(a, b, "character @ {}", i);
        }
    }
}
