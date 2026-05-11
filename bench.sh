#!/usr/bin/bash
ROOT=$(git rev-parse --show-toplevel)

cd $ROOT/crates/magicsvm/test_programs
cargo build-sbf --workspace --sbf-out-dir target/deploy

cd $ROOT
RUST_LOG= cargo bench --features internal-test
