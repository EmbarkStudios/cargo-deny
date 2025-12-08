use cargo_deny::{
    Krates, diag, field_eq, func_name,
    licenses::{self, cfg::Config},
    test_utils as tu,
};
use std::sync::{Arc, OnceLock};

static STORE: OnceLock<Arc<licenses::LicenseStore>> = OnceLock::new();

#[inline]
fn store() -> Arc<licenses::LicenseStore> {
    STORE
        .get_or_init(|| Arc::new(licenses::LicenseStore::from_cache().unwrap()))
        .clone()
}

fn setup<'k>(
    krates: &'k crate::Krates,
    name: &str,
    cfg: tu::Config<Config>,
) -> (
    tu::GatherCtx<'k, licenses::cfg::ValidConfig>,
    licenses::Summary<'k>,
) {
    let mut ctx = tu::setup(krates, name, cfg);

    let gatherer = licenses::Gatherer::default()
        .with_store(store())
        .with_confidence_threshold(0.8);

    let summary = gatherer.gather(ctx.krates, &mut ctx.files, Some(&ctx.valid_cfg));
    (ctx, summary)
}

/// TODO: Make this nicer, but I only intended these tests for myself and CI,
/// so if someone else runs them (eg. packagers), just fake that the test passed :p
macro_rules! me_or_ci_or_success {
    () => {
        if !std::env::var_os("CI").is_some() {
            if std::env::var("CARGO_HOME").expect("CARGO_HOME not set") != "/home/jake/.cargo" {
                return;
            }
        }
    };
}

#[inline]
pub fn gather_licenses_with_overrides(
    name: &str,
    cfg: impl Into<tu::Config<Config>>,
    overrides: Option<diag::DiagnosticOverrides>,
) -> Vec<serde_json::Value> {
    let mut md: krates::cm::Metadata = serde_json::from_str(
        &std::fs::read_to_string("tests/test_data/features-galore/metadata.json").unwrap(),
    )
    .unwrap();

    if std::env::var_os("CI").is_some() {
        std::process::Command::new("cargo")
            .args([
                "fetch",
                "--locked",
                "--manifest-path",
                "tests/test_data/features-galore/Cargo.toml",
            ])
            .status()
            .expect("failed to spawn cargo fetch");

        let chome = std::env::var("CARGO_HOME").expect("CARGO_HOME not set");
        let chome = cargo_deny::Path::new(&chome);

        for pkg in &mut md.packages {
            if let Ok(mp) = pkg.manifest_path.strip_prefix("/home/jake/.cargo") {
                pkg.manifest_path = chome.join(mp);
            } else if let Some(parent) = pkg.manifest_path.parent()
                && parent.file_name() == Some("features-galore")
            {
                pkg.manifest_path = std::env::current_dir()
                    .unwrap()
                    .join("tests/test_data/features-galore/Cargo.toml")
                    .try_into()
                    .unwrap();
            }
        }
    }

    let krates = krates::Builder::new()
        .build_with_metadata(md, krates::NoneFilter)
        .unwrap();

    let (ctx, summary) = setup(&krates, name, cfg.into());

    tu::run_gather(ctx, |ctx, tx| {
        crate::licenses::check(
            ctx,
            summary,
            diag::ErrorSink {
                overrides: overrides.map(Arc::new),
                channel: tx,
            },
        );
    })
}

#[test]
fn accepts_licenses() {
    me_or_ci_or_success!();

    let cfg = tu::Config::new(
        "allow = ['Apache-2.0', 'MIT']
    exceptions = [{ name = 'tinyvec_macros', allow = ['Zlib']}]",
    );

    let diags = gather_licenses_with_overrides(func_name!(), cfg, None);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn rejects_licenses() {
    me_or_ci_or_success!();
    let cfg = tu::Config::new("allow = []");

    let diags = gather_licenses_with_overrides(func_name!(), cfg, None);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn accepts_exceptions() {
    me_or_ci_or_success!();
    let cfg = tu::Config::new("exceptions = [{ name = 'tinyvec_macros', allow = ['Zlib']}]");

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, None);

    // Just keep tinyvec and tinyvec_macros which both have the same licenses,
    // but since we only allowed the exception on macros, that is the only
    // one that should succeed
    diags.retain(|d| {
        field_eq!(d, "/fields/graphs/0/Krate/name", "tinyvec")
            || field_eq!(d, "/fields/graphs/0/Krate/name", "tinyvec_macros")
    });

    insta::assert_json_snapshot!(diags);
}

#[test]
fn detects_unlicensed() {
    me_or_ci_or_success!();
    let cfg = tu::Config::new("");

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, None);

    diags.retain(|d| field_eq!(d, "/fields/graphs/0/Krate/name", "features-galore"));

    insta::assert_json_snapshot!(diags);
}

#[test]
fn flags_unencountered_licenses() {
    me_or_ci_or_success!();
    let cfg = tu::Config::new("allow = ['Aladdin', 'MIT']");

    // Override the warning to be a failure
    let overrides = cargo_deny::overrides! {
        "license-not-encountered" => Error,
    };

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, Some(overrides));

    diags.retain(|d| field_eq!(d, "/fields/code", "license-not-encountered"));

    insta::assert_json_snapshot!(diags);
}

#[test]
fn flags_unencountered_exceptions() {
    me_or_ci_or_success!();
    let cfg = tu::Config::new(
        "allow = ['MIT']
    exceptions = [{name='bippity-boppity-boop', allow = ['Aladdin']}]",
    );

    // Override the warning to be a failure
    let overrides = cargo_deny::overrides! {
        "license-exception-not-encountered" => Error,
    };

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, Some(overrides));

    diags.retain(|d| field_eq!(d, "/fields/code", "license-exception-not-encountered"));

    insta::assert_json_snapshot!(diags);
}

/// Ensures that invalid SPDX expressions in strict mode can be parsed when
/// falling back to more lax rules, but still output a warning
#[test]
fn lax_fallback() {
    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("examples/04_gnu_licenses/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let cfg = tu::Config::<Config>::new("allow = ['GPL-2.0-or-later', 'LGPL-3.0-only']");

    let (ctx, summary) = setup(&krates, func_name!(), cfg);

    let diags = tu::run_gather(ctx, |ctx, tx| {
        crate::licenses::check(
            ctx,
            summary,
            diag::ErrorSink {
                overrides: None,
                channel: tx,
            },
        );
    });

    insta::assert_json_snapshot!(diags);
}

/// Ensures deprecated licenses can be used in configs, since for GNU licenses
/// we only compare on the exact license identifiers, and upstream crates may
/// be using the deprecated identifiers
#[test]
fn allows_deprecated_and_imprecise() {
    let cfg = tu::Config::<Config>::new("allow = ['GPL-2.0', 'LGPL-3.0']");

    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("examples/04_gnu_licenses/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let (ctx, _summary) = setup(&krates, func_name!(), cfg);

    let diags = tu::run_gather(ctx, |_ctx, _tx| {});

    assert!(diags.is_empty());
}

/// Ensures clarifications are supported, even for nested license files
#[test]
fn clarifications() {
    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("examples/13_license_clarification/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let cfg = tu::Config::<Config>::new(
        r#"
allow = ["MIT", "Apache-2.0", "ISC"]
private = { ignore = true }
exceptions = [
    { name = "ring", allow = [
        "OpenSSL",
    ] },
    { name = "unicode-ident", allow = [
        "Unicode-DFS-2016",
    ] },
    { name = "rustls-webpki", allow = [
        "BSD-3-Clause",
    ] },
]

[[clarify]]
name = "ring"
expression = "ISC AND MIT AND OpenSSL"
license-files = [{ path = "LICENSE", hash = 0xbd0eed23 }]

[[clarify]]
name = "rustls-webpki"
expression = "ISC AND BSD-3-Clause"
license-files = [
    { path = "LICENSE", hash = 0x001c7e6c },
    { path = "third-party/chromium/LICENSE", hash = 0x001c7e6c },
]
"#,
    );

    let (ctx, summary) = setup(&krates, func_name!(), cfg);

    let diags = tu::run_gather(ctx, |ctx, tx| {
        crate::licenses::check(
            ctx,
            summary,
            diag::ErrorSink {
                overrides: None,
                channel: tx,
            },
        );
    });

    insta::assert_json_snapshot!(diags);
}

#[test]
fn handles_dev_dependencies() {
    me_or_ci_or_success!();
    let cfg = tu::Config::new(
        r"
allow = ['Apache-2.0']
include-dev = true
",
    );

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, None);
    diags.retain(|d| {
        field_eq!(d, "/fields/severity", "error")
            && field_eq!(d, "/fields/graphs/0/Krate/name", "dynamic")
            || field_eq!(d, "/fields/graphs/0/Krate/name", "simple_ecs")
    });

    insta::assert_json_snapshot!(diags);
}

/// Ensures that an Apache-2.0 licenses without the appendix are not misidentified
/// as Pixar, because Pixar is an almost exact copy of Apache-2.0. Fuck I hate licenses so much.
#[test]
fn forces_apache_over_pixar() {
    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("tests/test_data/so-annoying/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let cfg = tu::Config::new(
        r"
    allow = ['Apache-2.0']
    ",
    );

    let (ctx, summary) = setup(&krates, func_name!(), cfg);

    let diags = tu::run_gather(ctx, |ctx, tx| {
        crate::licenses::check(
            ctx,
            summary,
            diag::ErrorSink {
                overrides: None,
                channel: tx,
            },
        );
    });

    insta::assert_json_snapshot!(diags);
}

#[test]
fn insane_licenses() {
    let cfg = tu::Config::new("allow = ['MIT']");

    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("tests/test_data/insane-licenses/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let (ctx, summary) = setup(&krates, func_name!(), cfg);

    let diags = tu::run_gather(ctx, |ctx, tx| {
        crate::licenses::check(
            ctx,
            summary,
            diag::ErrorSink {
                overrides: None,
                channel: tx,
            },
        );
    });

    insta::assert_json_snapshot!(diags);
}

/// Checks that license text that _could_ be attributed to a deprecated license id,
/// is either corrected, or works
#[test]
fn deprecated_license_detection() {
    let cfg = tu::Config::new(
        "allow = ['MIT', 'AGPL-3.0-or-later', 'MIT-Festival', 'BSD-2-Clause-FreeBSD']",
    );

    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("examples/14_license_detection/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let (ctx, summary) = setup(&krates, func_name!(), cfg);

    let diags = tu::run_gather(ctx, |ctx, tx| {
        crate::licenses::check(
            ctx,
            summary,
            diag::ErrorSink {
                overrides: None,
                channel: tx,
            },
        );
    });

    insta::assert_json_snapshot!(diags);
}
