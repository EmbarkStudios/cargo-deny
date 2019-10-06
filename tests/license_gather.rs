use cargo_deny::{
    licenses::{self, Gatherer, LicenseExprSource, LicenseInfo},
    KrateDetails, Version,
};
use std::{collections::HashMap, path::PathBuf};
use tempfile::TempDir;

macro_rules! check_gather {
    ($crates:expr, $expected:expr) => {
        check_gather!($crates, $expected, Gatherer::default())
    };

    ($crates:expr, $expected:expr, $gatherer:expr) => {
        let mut files = codespan::Files::new();
        let summary = $gatherer.gather(&$crates[..], &mut files, None);
        let expected = $expected;

        let mut actual = summary.nfos.iter();
        let mut expected = expected.iter();

        loop {
            match (actual.next(), expected.next()) {
                (Some(act), Some(exp)) => {
                    assert!(
                        exp.eq(&act.lic_info),
                        "\nleft: {:?}\nright: {:?}",
                        act.lic_info,
                        exp
                    );
                }
                (Some(act), None) => {
                    assert!(false, "found additional license info {:?}", act);
                }
                (None, Some(exp)) => {
                    assert!(false, "unable to find nfo to compare to {:?}", exp);
                }
                (None, None) => break,
            }
        }

        // if expected.iter().ne(&summary.nfos) {
        //     let actual = format!("{:#?}", summary.nfos);
        //     let expected = format!("{:#?}", expected);

        //     let cs = difference::Changeset::new(&expected, &actual, "\n");

        //     assert!(false, "{}", cs);
        // }
    };
}

macro_rules! src {
    ($src:ident) => {
        LicenseExprSource::$src
    };
}

macro_rules! expr {
    ($expr:expr) => {
        spdx::Expression::parse($expr).unwrap()
    };
}

macro_rules! deetz {
    () => {{
        KrateDetails {
            name: "".to_owned(),
            version: Version::new(0, 1, 0),
            authors: Vec::new(),
            id: cargo_metadata::PackageId {
                repr: "".to_owned(),
            },
            source: None,
            description: None,
            deps: Vec::new(),
            license: None,
            license_file: None,
            targets: Vec::new(),
            features: HashMap::new(),
            manifest_path: PathBuf::new(),
            repository: None,
        }
    }};

    (license $lic:expr) => {{
        let mut deetz = deetz!();

        deetz.license = Some($lic.to_owned());

        deetz
    }};
}

#[derive(Debug)]
struct CmpLicense {
    expr: spdx::Expression,
    source: LicenseExprSource,
}

impl PartialEq<LicenseInfo> for CmpLicense {
    fn eq(&self, o: &LicenseInfo) -> bool {
        match o {
            LicenseInfo::SPDXExpression { expr, nfo } => {
                &self.expr == expr && self.source == nfo.source
            }
            LicenseInfo::Unlicensed => false,
        }
    }
}

#[derive(Debug)]
struct Unlicensed;

impl PartialEq<LicenseInfo> for Unlicensed {
    fn eq(&self, o: &LicenseInfo) -> bool {
        match o {
            LicenseInfo::Unlicensed => true,
            _ => false,
        }
    }
}

#[test]
fn handles_spdx_id_in_metadata() {
    let crates = vec![deetz!(license "MIT")];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!("MIT"),
            source: src!(Metadata),
        }]
    );
}

#[test]
fn handles_dual() {
    let crates = vec![deetz!(license "MIT OR Apache-2.0")];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!("MIT OR Apache-2.0"),
            source: src!(Metadata),
        }]
    );
}

#[test]
fn handles_exception_in_metadata() {
    let crates = vec![deetz!(license "MIT OR Apache-2.0 WITH LLVM-exception")];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!("MIT OR Apache-2.0 WITH LLVM-exception"),
            source: src!(Metadata),
        }]
    );
}

#[test]
fn handles_unknown_spdx_id_in_metadata() {
    let crates = vec![deetz!(license
        "LicenseRef-Embark-Proprietary AND (MIT OR Apache-2.0 WITH LLVM-exception)"
    )];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!(
                "LicenseRef-Embark-Proprietary AND (MIT OR Apache-2.0 WITH LLVM-exception)"
            ),
            source: src!(Metadata),
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

    let mut deetz = deetz!();
    deetz.manifest_path = td.path().join("Cargo.toml");
    deetz.license_file = Some(PathBuf::from("LICENSE-MIT"));

    let crates = vec![deetz];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!("MIT"),
            source: src!(LicenseFiles),
        }],
        Gatherer::default().with_store(STORE.clone())
    );
}

#[test]
fn analyzes_inferred_license_file() {
    let td = TempDir::new().unwrap();

    let license_path = td.path().join("LICENSE-MIT");
    fs::copy("./LICENSE-MIT", &license_path).expect("failed to copy license to tempdir");

    let mut deetz = deetz!();
    deetz.manifest_path = td.path().join("Cargo.toml");

    let crates = vec![deetz];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!("MIT"),
            source: src!(LicenseFiles),
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

    let mut deetz = deetz!();
    deetz.manifest_path = td.path().join("Cargo.toml");

    let crates = vec![deetz];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!("Apache-2.0 AND MIT"),
            source: src!(LicenseFiles),
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

    let mut deetz = deetz!();
    deetz.manifest_path = td.path().join("Cargo.toml");
    deetz.license_file = Some(PathBuf::from("LICENSE-MIT"));

    let crates = vec![deetz];

    check_gather!(
        crates,
        vec![CmpLicense {
            expr: expr!("Apache-2.0 AND MIT"),
            source: src!(LicenseFiles),
        }],
        Gatherer::default().with_store(STORE.clone())
    );
}

#[test]
fn handles_unknown_explicit() {
    let td = TempDir::new().unwrap();

    let license_path = td.path().join("LICENSE");
    fs::copy("./tests/LICENSE-SUMMARY", &license_path).expect("failed to copy license to tempdir");

    let mut deetz = deetz!();
    deetz.manifest_path = td.path().join("Cargo.toml");
    deetz.license_file = Some(PathBuf::from("LICENSE"));

    let crates = vec![deetz];

    check_gather!(
        crates,
        vec![Unlicensed],
        Gatherer::default().with_store(STORE.clone())
    );
}
