use cargo_deny::{
    field_eq, sources,
    test_utils::{self as tu, KrateGather},
};

#[test]
fn fails_unknown_git() {
    let cfg = "unknown-git = 'deny'";

    let diags = tu::gather_diagnostics::<sources::Config, _, _, _>(
        KrateGather::new("sources"),
        "fails_unknown_git",
        Some(cfg),
        None,
        |ctx, _, tx| {
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
                        "detected 'git' source not explicitly allowed"
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

    let diags = tu::gather_diagnostics::<sources::Config, _, _, _>(
        KrateGather::new("sources"),
        "fails_unknown_git",
        Some(cfg),
        None,
        |ctx, _, tx| {
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

    let diags = tu::gather_diagnostics::<sources::Config, _, _, _>(
        KrateGather::new("sources"),
        "allows_github_org",
        Some(cfg),
        None,
        |ctx, _, tx| {
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

#[test]
fn allows_gitlab_org() {
    let cfg = "unknown-git = 'deny'
    [allow-org]
    gitlab = ['amethyst-engine']
    ";

    let diags = tu::gather_diagnostics::<sources::Config, _, _, _>(
        KrateGather::new("sources"),
        "allows_gitlab_org",
        Some(cfg),
        None,
        |ctx, _, tx| {
            sources::check(ctx, tx);
        },
    )
    .unwrap();

    let allowed_by_org = ["https://gitlab.com/amethyst-engine"];

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

#[test]
fn allows_bitbucket_org() {
    let cfg = "unknown-git = 'deny'
    [allow-org]
    bitbucket = ['marshallpierce']
    ";

    let diags = tu::gather_diagnostics::<sources::Config, _, _, _>(
        KrateGather::new("sources"),
        "allows_bitbucket_org",
        Some(cfg),
        None,
        |ctx, _, tx| {
            sources::check(ctx, tx);
        },
    )
    .unwrap();

    let allowed_by_org = ["https://bitbucket.org/marshallpierce/line-wrap-rs"];

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

#[test]
fn validates_git_source_specs() {
    use sources::GitSpec;

    assert!(GitSpec::Rev > GitSpec::Tag);
    assert!(GitSpec::Tag > GitSpec::Branch);
    assert!(GitSpec::Branch > GitSpec::Any);

    let levels = [
        (GitSpec::Rev, "https://gitlab.com/amethyst-engine/amethyst"),
        (GitSpec::Tag, "https://github.com/EmbarkStudios/spdx"),
        (GitSpec::Branch, "https://github.com/EmbarkStudios/krates"),
        (
            GitSpec::Any,
            "https://bitbucket.org/marshallpierce/line-wrap-rs",
        ),
    ];

    for (i, (spec, _url)) in levels.iter().enumerate() {
        let cfg = format!(
            "unknown-git = 'allow'
        required-git-spec = '{}'",
            spec
        );

        let mut diags = tu::gather_diagnostics::<sources::Config, _, _, _>(
            KrateGather::new("sources"),
            "validates_git_source_specs",
            Some(&cfg),
            None,
            |ctx, _, tx| {
                sources::check(ctx, tx);
            },
        )
        .unwrap();

        diags.retain(|d| {
            d.pointer("/fields/message")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("'git' source is underspecified, expected")
        });

        for (j, (_, url)) in levels.iter().enumerate() {
            let severities: Vec<_> = diags
                .iter()
                .filter_map(|d| {
                    d.pointer("/fields/labels/0/span")
                        .and_then(|u| u.as_str())
                        .and_then(|u| {
                            if u.contains(url) {
                                d.pointer("/fields/severity").and_then(|s| s.as_str())
                            } else {
                                None
                            }
                        })
                })
                .collect();

            if j <= i {
                assert!(severities.is_empty());
            } else {
                assert!(!severities.is_empty());
                assert!(severities.into_iter().all(|s| s == "error"));
            }
        }
    }
}
