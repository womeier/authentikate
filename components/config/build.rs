use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=../../wit/config.wit");
    println!("cargo:rerun-if-changed=wit/config.wit");
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() != "wasm32" {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let wit = out.join("wit");
    fs::create_dir_all(&wit).unwrap();
    fs::copy("../../wit/config.wit", wit.join("interfaces.wit")).unwrap();
    fs::copy("wit/config.wit", wit.join("config.wit")).unwrap();
    fs::write(
        out.join("bindings.rs"),
        format!("wit_bindgen::generate!({{ world: \"config-provider\", path: {wit:?} }});"),
    )
    .unwrap();
}
