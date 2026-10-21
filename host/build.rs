use std::{env, fs, path::Path};

fn copy_wit(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            copy_wit(&path, &destination.join(entry.file_name()));
        } else if path.extension().is_some_and(|ext| ext == "wit") {
            fs::copy(&path, destination.join(entry.file_name())).unwrap();
        }
    }
}

fn main() {
    for path in [
        "../components/service/wit",
        "../components/crypto/wit",
        "../components/email/wit",
        "world.wit",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    let out = env::var_os("OUT_DIR").unwrap();
    let out = Path::new(&out);
    let wit = out.join("wit");
    if wit.exists() {
        fs::remove_dir_all(&wit).unwrap();
    }
    copy_wit(Path::new("../components/service/wit"), &wit);
    copy_wit(
        Path::new("../components/crypto/wit"),
        &wit.join("deps/crypto"),
    );
    copy_wit(
        Path::new("../components/crypto/wit/deps"),
        &wit.join("deps"),
    );
    copy_wit(
        Path::new("../components/email/wit"),
        &wit.join("deps/email"),
    );
    fs::copy("world.wit", wit.join("host.wit")).unwrap();
    fs::write(
        out.join("bindings.rs"),
        format!(
            "wasmtime::component::bindgen!({{path: {:?}, world: \"web-host\", imports: {{ default: trappable }}, with: {{ \"wasi:keyvalue/store.bucket\": super::Bucket }} }});",
            wit
        ),
    )
    .unwrap();
}
