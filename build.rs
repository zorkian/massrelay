fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let source = "src/private/diagnostics_oslog.c";
        println!("cargo:rerun-if-changed={source}");
        cc::Build::new().file(source).compile("massrelay_oslog");
    }
}
