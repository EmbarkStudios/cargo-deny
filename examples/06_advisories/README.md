# 06_advisories

This example shows cargo-deny's default behavior when checking and advisory database

## Description

When checking security advisories (by default from <https://github.com/RustSec/advisory-db>) via `cargo deny check advisories`, the default behavior is to **deny** all advisories whether they be for actual vulnerabilities, unsoundness, or marked as unmaintained, and **warn** if the particular crate version in the graph has been yanked from its source package repository. In this example, the check fails due to numerous advisories being placed on crates, while ignoring some of them.
