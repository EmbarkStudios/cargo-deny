const REPOS: &[&str] = &[
    "git://github.com/EmbarkStudios/ash-molten.git",
    "git://github.com/EmbarkStudios/cargo-about.git",
    //"git://github.com/EmbarkStudios/cargo-fetcher.git",
    "git://github.com/bitshifter/glam-rs.git",
    "git://github.com/EmbarkStudios/physx-rs.git",
    "git://github.com/gwihlidal/smush-rs.git",
    "git://github.com/EmbarkStudios/tame-gcs.git",
    "git://github.com/EmbarkStudios/tame-oauth.git",
    "git://github.com/EmbarkStudios/texture-synthesis.git",
    //"git://github.com/hyperium/tonic.git",
];

fn main() {
    use std::process::Command;

    let td = std::env::temp_dir().join("deny-repos");
    // This kind of doesn't work on windows!
    if td.exists() {
        std::fs::remove_dir_all(&td).unwrap();
    }
    std::fs::create_dir_all(&td).unwrap();

    // Fetch external sources once
    if !Command::new("cargo")
        .args(&["deny", "-L", "debug", "fetch", "all"])
        .status()
        .expect("failed to run cargo deny fetch")
        .success()
    {
        panic!("failed to run cargo deny fetch");
    }

    let (tx, rx) = std::sync::mpsc::channel();

    for repo in REPOS {
        let tx = tx.clone();
        let td = td.clone();
        std::thread::spawn(move || {
            let repo_name = &repo[repo.rfind('/').unwrap() + 1..];
            let repo_dir = td.join(repo_name);

            println!("cloning {}", repo);

            match Command::new("git")
                .arg("clone")
                .arg(repo)
                .arg(&repo_dir)
                .output()
            {
                Ok(out) => {
                    if !out.status.success() {
                        let err_str = String::from_utf8(out.stderr)
                            .unwrap_or_else(|e| format!("git err output has bad utf8: {}", e));
                        tx.send(Some((repo, err_str))).unwrap();
                        return;
                    }
                }
                Err(e) => {
                    tx.send(Some((repo, format!("failed to spawn git clone: {}", e))))
                        .unwrap();
                    return;
                }
            };

            println!("checking {}", repo);

            match Command::new("cargo")
                .args(&["deny", "-L", "info", "check", "--disable-fetch"])
                .current_dir(repo_dir)
                .output()
            {
                Ok(out) => {
                    if !out.status.success() {
                        let err_str = String::from_utf8(out.stderr)
                            .unwrap_or_else(|e| format!("deny err output has bad utf8: {}", e));
                        tx.send(Some((repo, err_str))).unwrap();
                    }
                }
                Err(e) => {
                    tx.send(Some((repo, format!("failed to spawn cargo deny: {}", e))))
                        .unwrap();
                }
            }
        });
    }

    drop(tx);

    let mut code = 0;
    while let Ok(bad) = rx.recv() {
        if let Some((repo, output)) = bad {
            code = 1;

            eprintln!("failed {}:\n{}", repo, output);
        }
    }

    std::process::exit(code);
}
