use cargo_deny::{diag, field_eq, func_name, licenses, test_utils as tu, Krates};
use parking_lot::Once;
use std::sync::Arc;

static mut STORE: Option<Arc<licenses::LicenseStore>> = None;
static INIT: Once = Once::new();

fn store() -> Arc<licenses::LicenseStore> {
    #[allow(unsafe_code)]
    unsafe {
        INIT.call_once(|| {
            STORE = Some(Arc::new(licenses::LicenseStore::from_cache().unwrap()));
        });
        STORE.as_ref().unwrap().clone()
    }
}

#[inline]
pub fn gather_licenses_with_overrides(
    name: &str,
    cfg: impl Into<tu::Config<crate::licenses::cfg::Config>>,
    overrides: Option<diag::DiagnosticOverrides>,
) -> Vec<serde_json::Value> {
    let md: krates::cm::Metadata = serde_json::from_str(
        &std::fs::read_to_string("tests/test_data/features-galore/metadata.json").unwrap(),
    )
    .unwrap();

    let krates: Krates = krates::Builder::new()
        .build_with_metadata(md, krates::NoneFilter)
        .unwrap();

    let gatherer = licenses::Gatherer::default()
        .with_store(store())
        .with_confidence_threshold(0.8);

    let mut files = codespan::Files::new();

    let cfg = cfg.into();
    let lic_cfg = {
        let des: licenses::cfg::Config = toml::from_str(&cfg.config).unwrap();
        let cfg_id = files.add("config.toml", cfg.config.clone());

        let mut diags = Vec::new();
        use cargo_deny::UnvalidatedConfig;
        des.validate(cfg_id, &mut diags)
    };

    let summary = gatherer.gather(&krates, &mut files, Some(&lic_cfg));

    tu::gather_diagnostics_with_files::<crate::licenses::cfg::Config, _, _>(
        &krates,
        name,
        cfg,
        files,
        |ctx, _cs, tx| {
            crate::licenses::check(
                ctx,
                summary,
                diag::ErrorSink {
                    overrides: overrides.map(Arc::new),
                    channel: tx,
                },
            );
        },
    )
}

#[test]
fn accepts_licenses() {
    let cfg = tu::Config::new(
        "allow = ['Apache-2.0', 'MIT']
    exceptions = [{ name = 'tinyvec_macros', allow = ['Zlib']}]",
    );

    let diags = gather_licenses_with_overrides(func_name!(), cfg, None);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn rejects_licenses() {
    let cfg = tu::Config::new("allow = []");

    let diags = gather_licenses_with_overrides(func_name!(), cfg, None);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn accepts_exceptions() {
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
    let cfg = tu::Config::new("unlicensed = 'warn'");

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, None);

    diags.retain(|d| field_eq!(d, "/fields/severity", "warning"));

    insta::assert_json_snapshot!(diags);
}

#[test]
fn flags_unencountered_licenses() {
    let cfg = tu::Config::new(
        "allow = ['Aladdin', 'MIT']
    unlicensed = 'allow'",
    );

    // Override the warning to be a failure
    let overrides = cargo_deny::overrides! {
        "license-not-encountered" => Error,
    };

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, Some(overrides));

    diags.retain(|d| field_eq!(d, "/fields/severity", "error"));

    insta::assert_json_snapshot!(diags);
}

#[test]
fn flags_unencountered_exceptions() {
    let cfg = tu::Config::new(
        "allow = ['MIT']
    unlicensed = 'allow'
    exceptions = [{name='bippity-boppity-boop', allow = ['Aladdin']}]",
    );

    // Override the warning to be a failure
    let overrides = cargo_deny::overrides! {
        "license-exception-not-encountered" => Error,
    };

    let mut diags = gather_licenses_with_overrides(func_name!(), cfg, Some(overrides));

    diags.retain(|d| field_eq!(d, "/fields/severity", "error"));

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

    let gatherer = licenses::Gatherer::default()
        .with_store(store())
        .with_confidence_threshold(0.8);

    let mut files = codespan::Files::new();

    let cfg: tu::Config<crate::licenses::cfg::Config> = tu::Config::new(
        "allow = ['GPL-2.0', 'LGPL-3.0']
    unlicensed = 'deny'",
    );

    let lic_cfg = {
        let des: licenses::cfg::Config = toml::from_str(&cfg.config).unwrap();
        let cfg_id = files.add("config.toml", cfg.config.clone());

        let mut diags = Vec::new();
        use cargo_deny::UnvalidatedConfig;
        des.validate(cfg_id, &mut diags)
    };

    let summary = gatherer.gather(&krates, &mut files, Some(&lic_cfg));

    let diags = tu::gather_diagnostics_with_files::<crate::licenses::cfg::Config, _, _>(
        &krates,
        "lax_fallback",
        cfg,
        files,
        |ctx, _cs, tx| {
            crate::licenses::check(
                ctx,
                summary,
                diag::ErrorSink {
                    overrides: None,
                    channel: tx,
                },
            );
        },
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures clarifications are supported, even for nested license files
#[test]
fn clarifications() {
    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("examples/13_license_clarification/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let gatherer = licenses::Gatherer::default()
        .with_store(store())
        .with_confidence_threshold(0.8);

    let mut files = codespan::Files::new();

    let cfg: tu::Config<crate::licenses::cfg::Config> = tu::Config::new(
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

    let lic_cfg = {
        let des: licenses::cfg::Config = toml::from_str(&cfg.config).unwrap();
        let cfg_id = files.add("config.toml", cfg.config.clone());

        let mut diags = Vec::new();
        use cargo_deny::UnvalidatedConfig;
        des.validate(cfg_id, &mut diags)
    };

    let summary = gatherer.gather(&krates, &mut files, Some(&lic_cfg));

    let diags = tu::gather_diagnostics_with_files::<crate::licenses::cfg::Config, _, _>(
        &krates,
        "clarifications",
        cfg,
        files,
        |ctx, _cs, tx| {
            crate::licenses::check(
                ctx,
                summary,
                diag::ErrorSink {
                    overrides: None,
                    channel: tx,
                },
            );
        },
    );

    insta::assert_json_snapshot!(diags);
}
