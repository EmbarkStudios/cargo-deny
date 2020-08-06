use cargo_deny::sources;

#[macro_use]
mod utils;

#[test]
fn fails_unknown_git() {
    let cfg = "unknown-git = 'deny'";

    let krates = utils::get_test_data_krates("sources").unwrap();
    let diags = utils::gather_diagnostics::<sources::Config, _, _>(
        krates,
        "fails_unknown_git",
        Some(cfg),
        None,
        |ctx, tx| {
            sources::check(ctx, tx);
        },
    )
    .unwrap();

    let failed_urls = [
        // Note this one is used by multiple crates, but that's ok
        "https://gitlab.com/amethyst-engine/amethyst",
        "https://github.com/EmbarkStudios/krates",
        "https://bitbucket.org/marshallpierce/line-wrap-rs",
        "https://github.com/EmbarkStudios/spdx",
    ];

    for url in &failed_urls {
        assert!(
            diags.iter().any(|v| {
                field_eq!(v, "/fields/severity", "error")
                    && field_eq!(
                        v,
                        "/fields/message",
                        "detected 'git' source not specifically allowed"
                    )
                    && v.pointer("/fields/labels/0/span")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .contains(url)
            }),
            "failed to find diagnostic for git source '{}'",
            url
        );
    }
}

#[test]
fn allows_git() {
    let cfg = "unknown-git = 'deny'
    allow-git = [
        'https://gitlab.com/amethyst-engine/amethyst',
        'https://github.com/EmbarkStudios/krates',
        'https://bitbucket.org/marshallpierce/line-wrap-rs',
    ]";

    let krates = utils::get_test_data_krates("sources").unwrap();
    let diags = utils::gather_diagnostics::<sources::Config, _, _>(
        krates,
        "fails_unknown_git",
        Some(cfg),
        None,
        |ctx, tx| {
            sources::check(ctx, tx);
        },
    )
    .unwrap();

    let allowed_urls = [
        // Note this one is used by multiple crates, but that's ok
        "https://gitlab.com/amethyst-engine/amethyst",
        "https://github.com/EmbarkStudios/krates",
        "https://bitbucket.org/marshallpierce/line-wrap-rs",
    ];

    for url in &allowed_urls {
        assert!(
            diags.iter().any(|v| {
                field_eq!(v, "/fields/severity", "note")
                    && field_eq!(v, "/fields/message", "\'git\' source explicitly allowed")
                    && v.pointer("/fields/labels/0/span")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .contains(url)
                    && field_eq!(v, "/fields/labels/1/span", format!("'{}'", url))
            }),
            "failed to find diagnostic for git source '{}'",
            url
        );
    }
}

#[test]
fn allows_github_org() {
    // We shouldn't have any errors for the embark urls now
    let cfg = "unknown-git = 'deny'
    [allow-org]
    github = ['EmbarkStudios']
    ";

    let krates = utils::get_test_data_krates("sources").unwrap();
    let diags = utils::gather_diagnostics::<sources::Config, _, _>(
        krates,
        "allows_github_org",
        Some(cfg),
        None,
        |ctx, tx| {
            sources::check(ctx, tx);
        },
    )
    .unwrap();

    let allowed_by_org = [
        "https://github.com/EmbarkStudios/krates",
        "https://github.com/EmbarkStudios/spdx",
    ];

    for diag in diags {
        match diag.pointer("/fields/severity").unwrap().as_str().unwrap() {
            "error" => {
                let source = diag
                    .pointer("/fields/labels/0/span")
                    .unwrap()
                    .as_str()
                    .unwrap();

                assert!(!allowed_by_org.iter().any(|ao| source.contains(ao)));
            }
            "note" => {
                let source = diag
                    .pointer("/fields/labels/0/span")
                    .unwrap()
                    .as_str()
                    .unwrap();

                assert!(allowed_by_org.iter().any(|ao| source.contains(ao)));
            }
            ty => unreachable!("unexpected '{}' diagnostic", ty),
        }
    }
}

// #[test]
// fn allows_org() {}
