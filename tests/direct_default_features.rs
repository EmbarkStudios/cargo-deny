use cargo_deny::{func_name, test_utils::*};

fn gather(config: &str) -> Vec<serde_json::Value> {
    gather_bans(
        func_name!(),
        KrateGather::new("direct-default-features"),
        config,
    )
}

#[test]
fn direct_external_default_features_only_checks_direct_dependencies() {
    let diags = gather("direct-external-default-features = 'deny'");

    insta::assert_json_snapshot!(diags);
}

#[test]
fn direct_external_default_features_overrides_external_default_features() {
    let diags =
        gather("external-default-features = 'deny'\ndirect-external-default-features = 'warn'");

    insta::assert_json_snapshot!(diags);
}
