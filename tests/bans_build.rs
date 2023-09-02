use cargo_deny::{field_eq, func_name, test_utils::*};

/// Verifies we can detect and error on builtin globs
#[test]
fn detects_scripts_by_builtin_glob() {
    let mut diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &["scripts"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new(
            r#"
[build]
enable-builtin-globs = true
include-dependencies = true
"#,
        ),
    );

    diags.retain(|d| {
        field_eq!(d, "/fields/graphs/0/Krate/name", "ring")
            && field_eq!(d, "/fields/code", "disallowed-by-extension")
    });

    insta::assert_json_snapshot!(diags);
}

/// Verifies we can detect and error on extensions provided by the user
#[test]
fn detects_scripts_by_user_extension() {
    let mut diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &[],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new("[build]\ninclude-workspace = true\nscript-extensions = ['cs']"),
    );

    diags.retain(|d| field_eq!(d, "/fields/graphs/0/Krate/name", "build-bans"));

    insta::assert_json_snapshot!(diags);
}

/// Verifies we detect and error on scripts detected by shebang
#[test]
fn detects_scripts_by_shebang() {
    let mut diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &["mixed"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new("[build]\ninterpreted = 'deny'"),
    );

    diags.retain(|d| {
        field_eq!(d, "/fields/graphs/0/Krate/name", "ittapi-sys")
            && field_eq!(d, "/fields/code", "detected-executable-script")
    });

    insta::assert_json_snapshot!(diags);
}

/// Verifies we detect and error on native executables
#[test]
fn detects_native_executables() {
    let mut diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &["native", "curious"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new(
            r#"
[build]
enable-builtin-globs = true
include-dependencies = true
"#,
        ),
    );

    diags.retain(|d| field_eq!(d, "/fields/code", "detected-executable"));

    insta::assert_json_snapshot!(diags);
}

/// Verifies user provided builscript checksums are always validated correctly
#[test]
fn detects_build_script_mismatch() {
    let mut diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &["mixed"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new(
            r#"
[[build.allow-executables]]
name = "ittapi-sys"
build-script = "00abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef00"
required-features = []
"#,
        ),
    );

    diags.retain(|d| {
        field_eq!(d, "/fields/graphs/0/Krate/name", "ittapi-sys")
            && field_eq!(d, "/fields/code", "checksum-mismatch")
    });

    insta::assert_json_snapshot!(diags);
}

/// Verifies that matching build scripts cause the rest of the build check to be
/// skipped
#[test]
fn skips_matching_build_scripts() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &["mixed", "scripts"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new(
            r#"
[[build.allow-executables]]
name = "ittapi-sys"
build-script = "474a3eb189a698475d8a6f4b358eb0790db6379aea8b8a85ac925102784cd520"
required-features = []

[[build.allow-executables]]
name = "ring"
build-script = "1a850d791184374f614d01c86c8d6c9ba0500e64cb746edc9720ceaaa1cd8eaf"
required-features = []
"#,
        ),
    );

    insta::assert_json_snapshot!(diags);
}

/// Verifies executables are allowed by glob patterns
#[test]
fn allows_by_glob() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &["scripts"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new(
            r#"
[build]
enable-builtin-globs = true
include-dependencies = true

[[build.allow-executables]]
name = "ring"
allow-globs = ["crypto/**.pl", "src/rsa/convert_nist_rsa_test_vectors.py"]
"#,
        ),
    );

    insta::assert_json_snapshot!(diags);
}

/// Verifies executables are allowed by path/checksum
#[test]
fn allows_by_path() {
    let mut diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "build-bans",
            features: &["native"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new(
            r#"
[[build.allow-executables]]
name = "prost-build"
allow = [
    { path = "third-party/protobuf/protoc-linux-aarch_64", checksum = "5392f0e58ad06e089462d93304dfe82337acbbefb87a0749a7dc2ed32af04af7" },
    { path = "third-party/protobuf/protoc-linux-x86_32" },
    { path = "third-party/protobuf/protoc-linux-x86_64", checksum = "151dfe76345298b055000c31376f925222ef3426d6b7892b8156421fdd3fd3c4" },
    { path = "third-party/protobuf/protoc-osx-aarch64", checksum = "2363256459ab02d5abdda2db52e96879f9417102d14086fe852d97d0380b79ff" },
    { path = "third-party/protobuf/protoc-osx-x86_64", checksum = "e7dff9c38bf0cbcf43f055b8269ea939d6b298f611de16481ba7d3e2eec0bc2f" },
    { path = "third-party/protobuf/protoc-win32.exe", checksum = "62e803f7433799af63acf605f7fe19108d22d0c73e82a475b27d3ff0cfbf1990" },
]
"#,
        ),
    );

    diags.retain(|d| {
        field_eq!(d, "/fields/graphs/0/Krate/name", "prost-build")
            && field_eq!(d, "/fields/code", "checksum-match")
    });

    insta::assert_json_snapshot!(diags);
}
