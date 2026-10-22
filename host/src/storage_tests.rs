//! Exercise the actual Wasm provider, including races between separate processes.
use std::{path::Path, sync::OnceLock};
use wasmtime::{
    Engine, Store,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{FsPerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/storage-bindings.rs"));
}
use bindings::{StorageTest, exports::authentikate::storage::accounts::Error};

struct State {
    wasi: WasiCtx,
    table: ResourceTable,
}
impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
fn instance(path: &Path, writable: bool) -> (Store<State>, StorageTest) {
    static COMPONENT: OnceLock<(Engine, Component)> = OnceLock::new();
    let (engine, component) = COMPONENT.get_or_init(|| {
        let engine = Engine::default();
        let component = Component::from_file(
            &engine,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../build/storage.component.wasm"
            ),
        )
        .unwrap();
        (engine, component)
    });
    let mut wasi = WasiCtxBuilder::new();
    wasi.preopened_dir(
        path,
        "/accounts",
        if writable {
            FsPerms::ReadWrite
        } else {
            FsPerms::ReadOnly
        },
    )
    .unwrap();
    let mut store = Store::new(
        engine,
        State {
            wasi: wasi.build(),
            table: ResourceTable::new(),
        },
    );
    let mut linker = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker).unwrap();
    let guest = StorageTest::instantiate(&mut store, component, &linker).unwrap();
    (store, guest)
}

#[test]
fn immutable_records_survive_instances_and_reject_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let keys = [
        "../outside/a@example.test".to_owned(),
        "A@example.test".into(),
        "a@example.test".into(),
        "".into(),
        "x".repeat(20_000),
    ];
    for key in &keys {
        let (mut state, guest) = instance(directory.path(), true);
        assert_eq!(
            guest
                .authentikate_storage_accounts()
                .call_get(&mut state, key)
                .unwrap()
                .unwrap(),
            None
        );
        assert!(
            guest
                .authentikate_storage_accounts()
                .call_create(&mut state, key, b"value\0\xff")
                .unwrap()
                .unwrap()
        );
    }
    for key in &keys {
        let (mut state, guest) = instance(directory.path(), true);
        for value in [b"replacement".as_slice(), b"value\0\xff"] {
            assert!(
                !guest
                    .authentikate_storage_accounts()
                    .call_create(&mut state, key, value)
                    .unwrap()
                    .unwrap()
            );
        }
        assert_eq!(
            guest
                .authentikate_storage_accounts()
                .call_get(&mut state, key)
                .unwrap()
                .unwrap(),
            Some(b"value\0\xff".to_vec())
        );
    }
    let entries: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(entries.len(), keys.len());
    for entry in entries {
        let name = entry.file_name().into_string().unwrap();
        assert_eq!(name.len(), 72);
        assert!(name.ends_with(".account"));
        assert!(name[..64].bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

#[test]
fn storage_errors_do_not_become_absence_or_conflict() {
    let directory = tempfile::tempdir().unwrap();
    let (mut state, guest) = instance(directory.path(), false);
    assert!(matches!(
        guest
            .authentikate_storage_accounts()
            .call_create(&mut state, "key", b"value")
            .unwrap(),
        Err(Error::Unavailable)
    ));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    let (mut state, guest) = instance(directory.path(), true);
    assert!(
        guest
            .authentikate_storage_accounts()
            .call_create(&mut state, "key", b"value")
            .unwrap()
            .unwrap()
    );
    let file = std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    for corrupt in [
        b"broken".to_vec(),
        [b"AKSTORE1".as_slice(), &3u32.to_le_bytes(), b"badvalue"].concat(),
        vec![0; 1024 * 1024 + 1],
    ] {
        std::fs::write(&file, corrupt).unwrap();
        assert!(matches!(
            guest
                .authentikate_storage_accounts()
                .call_get(&mut state, "key")
                .unwrap(),
            Err(Error::Unavailable)
        ));
    }
    std::fs::write(directory.path().join(".tmp-orphan"), b"partial").unwrap();
    assert_eq!(
        guest
            .authentikate_storage_accounts()
            .call_get(&mut state, "missing")
            .unwrap()
            .unwrap(),
        None
    );
    assert!(matches!(
        guest
            .authentikate_storage_accounts()
            .call_create(&mut state, "missing", &vec![0; 1024 * 1024])
            .unwrap(),
        Err(Error::Unavailable)
    ));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn only_the_named_preopen_is_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let (mut state, guest) = instance(directory.path(), true);
    let mut wasi = WasiCtxBuilder::new();
    wasi.preopened_dir(directory.path(), "/wrong", FsPerms::ReadWrite)
        .unwrap();
    state.data_mut().wasi = wasi.build();
    for no_preopen in [false, true] {
        if no_preopen {
            state.data_mut().wasi = WasiCtxBuilder::new().build();
        }
        assert!(matches!(
            guest
                .authentikate_storage_accounts()
                .call_get(&mut state, "key")
                .unwrap(),
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            guest
                .authentikate_storage_accounts()
                .call_create(&mut state, "key", b"value")
                .unwrap(),
            Err(Error::Unavailable)
        ));
    }
}

// Both processes observe absence before the parent releases their creates.
#[test]
fn process_creator() {
    let Some(path) = std::env::var_os("STORAGE_TEST_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let id = std::env::var("STORAGE_TEST_ID").unwrap();
    let (mut state, guest) = instance(path, true);
    assert_eq!(
        guest
            .authentikate_storage_accounts()
            .call_get(&mut state, "racing/key")
            .unwrap()
            .unwrap(),
        None
    );
    std::fs::write(path.join(format!("ready-{id}")), b"").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !path.join("go").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let value = vec![id.as_bytes()[0]; 128 * 1024];
    let won = guest
        .authentikate_storage_accounts()
        .call_create(&mut state, "racing/key", &value)
        .unwrap()
        .unwrap();
    let current = guest
        .authentikate_storage_accounts()
        .call_get(&mut state, "racing/key")
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(current.len(), value.len());
    assert!(current.iter().all(|b| *b == current[0]));
    if won {
        assert_eq!(current, value);
    }
    std::fs::write(
        path.join(format!("result-{id}")),
        if won {
            b"won".as_slice()
        } else {
            b"lost".as_slice()
        },
    )
    .unwrap();
}

#[test]
fn publication_is_atomic_across_processes() {
    let directory = tempfile::tempdir().unwrap();
    let mut children: Vec<_> = ["1", "2"]
        .into_iter()
        .map(|id| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage_tests::process_creator", "--nocapture"])
                .env("STORAGE_TEST_DIR", directory.path())
                .env("STORAGE_TEST_ID", id)
                .spawn()
                .unwrap()
        })
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    while !(directory.path().join("ready-1").exists() && directory.path().join("ready-2").exists())
    {
        if std::time::Instant::now() > deadline {
            for child in &mut children {
                let _ = child.kill();
                let _ = child.wait();
            }
            panic!("storage subprocesses did not become ready");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let (mut state, guest) = instance(directory.path(), false);
    std::fs::write(directory.path().join("go"), b"").unwrap();
    loop {
        if let Some(value) = guest
            .authentikate_storage_accounts()
            .call_get(&mut state, "racing/key")
            .unwrap()
            .unwrap()
        {
            assert_eq!(value.len(), 128 * 1024);
            assert!(value[0] == b'1' || value[0] == b'2');
            assert!(value.iter().all(|b| *b == value[0]));
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let mut outcomes = [
        std::fs::read(directory.path().join("result-1")).unwrap(),
        std::fs::read(directory.path().join("result-2")).unwrap(),
    ];
    outcomes.sort();
    assert_eq!(outcomes, [b"lost".to_vec(), b"won".to_vec()]);
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".tmp-")
    }));
}
