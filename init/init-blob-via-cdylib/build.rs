fn main() {
    if pkg_config::probe_library("libkrun_init").is_err() {
        // Fallback: libkrun_init.so is being built in the same workspace,
        // so pkg-config won't find it yet. Point the linker at the workspace
        // target directory where the cdylib is produced, and emit the link
        // directive manually.
        let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
        let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let target_dir = manifest_dir.join("../../target").join(&profile);
        println!("cargo:rustc-link-search=native={}", target_dir.display());
        println!("cargo:rustc-link-lib=dylib=krun_init");
    }
}
