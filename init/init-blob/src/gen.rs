use std::path::PathBuf;

fn schema_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    workspace_root.join("target/ffier-krun_init.json")
}

fn gen_c_header() {
    let path = schema_path();
    let json = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read {}: {e}\nBuild the cdylib first.",
            path.display()
        )
    });
    let lib: ffier_schema::Library = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
    let opts = ffier_gen_c_header::Options {
        fn_typedefs: true,
        ..Default::default()
    };
    print!(
        "{}",
        ffier_gen_c_header::generate(&lib, "LIBKRUN_INIT_H", &opts)
    );
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("c-header") => gen_c_header(),
        _ => {
            eprintln!("usage: krun-init-blob-gen c-header");
            std::process::exit(1);
        }
    }
}
