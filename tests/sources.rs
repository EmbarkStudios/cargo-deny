use cargo_deny::{func_name, sources, test_utils::*};

#[inline]
pub fn src_check(
    name: &str,
    kg: KrateGather<'_>,
    cfg: impl Into<Config<sources::Config>>,
) -> Vec<serde_json::Value> {
    let krates = kg.gather();
    let cfg = cfg.into();

    gather_diagnostics::<sources::Config, _, _>(&krates, name, cfg, |ctx, _cs, tx| {
        sources::check(ctx, tx);
    })
}

#[test]
fn fails_unknown_git() {
    let diags = src_check(
        func_name!(),
        KrateGather::new("sources"),
        "unknown-git = 'deny'",
    );

    insta::assert_json_snapshot!(diags);
}

#[test]
fn allows_git() {
    let cfg = "unknown-git = 'deny'
    allow-git = [
        'https://gitlab.com/amethyst-engine/amethyst',
        'https://github.com/EmbarkStudios/krates',
        'https://bitbucket.org/marshallpierce/line-wrap-rs',
    ]";

    let diags = src_check(func_name!(), KrateGather::new("sources"), cfg);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn allows_github_org() {
    // We shouldn't have any errors for the embark urls now
    let cfg = "unknown-git = 'deny'
    [allow-org]
    github = ['EmbarkStudios']
    ";

    let diags = src_check(func_name!(), KrateGather::new("sources"), cfg);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn allows_gitlab_org() {
    let cfg = "unknown-git = 'deny'
    [allow-org]
    gitlab = ['amethyst-engine']
    ";

    let diags = src_check(func_name!(), KrateGather::new("sources"), cfg);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn allows_bitbucket_org() {
    let cfg = "unknown-git = 'deny'
    [allow-org]
    bitbucket = ['marshallpierce']
    ";

    let diags = src_check(func_name!(), KrateGather::new("sources"), cfg);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn allows_registry_index_git() {
    let cfg = "unknown-registry = 'deny'
    allow-registry = [
        'https://dl.cloudsmith.io/public/embark/deny/cargo/index.git'
    ]
    ";

    let diags = src_check(func_name!(), KrateGather::new("non-crates-io"), cfg);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn allows_registry_index_sparse() {
    let cfg = "unknown-registry = 'deny'
    allow-registry = [
        'https://cargo.cloudsmith.io/embark/deny/'
    ]
    ";

    let diags = src_check(func_name!(), KrateGather::new("non-crates-io"), cfg);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn allows_registry_index_sparse_or_git() {
    let cfg = "unknown-registry = 'deny'
allow-registry = [
    'https://dl.cloudsmith.io/public/embark/deny/cargo/index.git',
    'https://cargo.cloudsmith.io/embark/deny/',
]
";

    let diags = src_check(func_name!(), KrateGather::new("non-crates-io"), cfg);

    insta::assert_json_snapshot!(diags);
}

#[test]
fn validates_git_source_specs() {
    use sources::GitSpec;

    assert!(GitSpec::Rev > GitSpec::Tag);
    assert!(GitSpec::Tag > GitSpec::Branch);
    assert!(GitSpec::Branch > GitSpec::Any);

    let levels: &[&[(_, _)]] = &[
        [(GitSpec::Rev, "https://gitlab.com/amethyst-engine/amethyst")].as_ref(),
        [(GitSpec::Tag, "https://github.com/EmbarkStudios/spdx")].as_ref(),
        [
            (GitSpec::Branch, "https://github.com/EmbarkStudios/krates"),
            (GitSpec::Branch, "https://github.com/dtolnay/anyhow"),
        ]
        .as_ref(),
        [(
            GitSpec::Any,
            "https://bitbucket.org/marshallpierce/line-wrap-rs",
        )]
        .as_ref(),
    ];

    for (i, (spec, _url)) in levels
        .iter()
        .enumerate()
        .flat_map(|(i, lvl)| lvl.iter().map(move |l| (i, l)))
    {
        let cfg = format!(
            "unknown-git = 'allow'
        required-git-spec = '{spec}'"
        );

        let mut diags = src_check(func_name!(), KrateGather::new("sources"), cfg);

        diags.retain(|d| {
            d.pointer("/fields/message")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("'git' source is underspecified, expected")
        });

        for (j, (_, url)) in levels
            .iter()
            .enumerate()
            .flat_map(|(i, lvl)| lvl.iter().map(move |l| (i, l)))
        {
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
