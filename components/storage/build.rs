use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let wit = out.join("wit");
    if wit.exists() {
        fs::remove_dir_all(&wit).unwrap();
    }
    fs::create_dir_all(&wit).unwrap();
    println!("cargo:rerun-if-changed=../../wit/accounts.wit");
    fs::copy("../../wit/accounts.wit", wit.join("accounts.wit")).unwrap();
    println!("cargo:rerun-if-changed=wit/storage.wit");
    fs::copy("wit/storage.wit", wit.join("storage.wit")).unwrap();
    fs::write(
        out.join("bindings.rs"),
        format!(
            "wit_bindgen::generate!({{ world: \"storage\", path: {:?} }});",
            wit
        ),
    )
    .unwrap();
}
