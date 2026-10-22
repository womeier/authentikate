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
        "../wit/config.wit",
        "../components/service/wit/api.wit",
        "../components/service/wit/deps/keyvalue",
        "../components/gateway/wit",
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
    let deps = wit.join("deps");
    // The gateway's tree carries the pinned wasi:http, wasi:io and wasi:clocks
    // copies the exported handler resolves against, plus `authentikate:config`
    // and the service's `api` interface.
    copy_wit(Path::new("../components/gateway/wit/deps"), &deps);
    // The keyvalue draft is not in that tree -- the gateway does not touch
    // storage -- so it comes from the service, which does.
    copy_wit(
        Path::new("../components/service/wit/deps/keyvalue"),
        &deps.join("keyvalue"),
    );
    // Authoritative sources win over the gateway's vendored copies, so the
    // host is never built against a stale interface.  `make check-wit` fails
    // when the two have drifted.
    fs::copy("../wit/config.wit", deps.join("config/config.wit")).unwrap();
    fs::copy(
        "../components/service/wit/api.wit",
        deps.join("service/api.wit"),
    )
    .unwrap();
    fs::copy("world.wit", wit.join("host.wit")).unwrap();
    fs::write(
        out.join("bindings.rs"),
        format!(
            "wasmtime::component::bindgen!({{\
               path: {:?}, \
               world: \"web-host\", \
               imports: {{ default: trappable }}, \
               with: {{ \
                 \"wasi:http\": wasmtime_wasi_http::p2::bindings::http, \
                 \"wasi:io\": wasmtime_wasi::p2::bindings::sync::io, \
                 \"wasi:keyvalue/store.bucket\": super::Bucket, \
                 \"wasi:keyvalue/atomics.cas\": super::Cas, \
               }} \
             }});",
            wit
        ),
    )
    .unwrap();
}
