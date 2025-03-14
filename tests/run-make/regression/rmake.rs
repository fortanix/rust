use run_make_support::{cmd, cwd, set_current_dir, target};

fn main() {
    let main_dir = cwd();
    set_current_dir("rustc_min_poc");
    // HACK(eddyb) sets `RUSTC_BOOTSTRAP=1` so Cargo can accept nightly features.
    // These come from the top-level Rust workspace, that this crate is not a
    // member of, but Cargo tries to load the workspace `Cargo.toml` anyway.
    cmd("cargo")
        .env("RUSTC_BOOTSTRAP", "1")
        .arg("-v")
        .arg("run")
        .arg("--target")
        .arg(target())
        .run();
}

