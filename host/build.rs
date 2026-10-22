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
        "../components/frontend/wit",
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
    // The front-end's tree carries the pinned wasi:http, wasi:io, wasi:clocks
    // (both 0.2.4 and, version-qualified, the service's 0.2.0) and wasi:cli
    // copies that the exported handler resolves against.
    copy_wit(Path::new("../components/frontend/wit/deps"), &deps);
    fs::create_dir_all(deps.join("frontend")).unwrap();
    fs::copy(
        "../components/frontend/wit/frontend.wit",
        deps.join("frontend/frontend.wit"),
    )
    .unwrap();
    // Authoritative sources win over the front-end's vendored copies, so the
    // host is never built against a stale interface.  `make check-wit` fails
    // when the two have drifted.
    copy_wit(Path::new("../components/service/wit"), &deps.join("service"));
    copy_wit(Path::new("../components/crypto/wit"), &deps.join("crypto"));
    copy_wit(Path::new("../components/email/wit"), &deps.join("email"));
    // service/wit carries its own deps/ (keyvalue, clocks 0.2.0); flatten them
    // up a level and keep the service's clock version-qualified.
    for name in ["keyvalue", "clocks", "store"] {
        let nested = deps.join("service/deps").join(name);
        if nested.exists() {
            let target = if name == "clocks" {
                deps.join("clocks@0.2.0")
            } else {
                deps.join(name)
            };
            copy_wit(&nested, &target);
        }
    }
    fs::remove_dir_all(deps.join("service/deps")).ok();
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
