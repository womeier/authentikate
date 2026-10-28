Written by LLMs. TODO: check.

# Immutable Account Storage

This Rust component exports `authentikate:storage/accounts@0.1.0`, defined in
`wit/accounts.wit`. Its only operations are `get` and atomic create-if-absent.
`create` returns `true` for this caller creating the key and `false` when it is
already taken, even for identical values. Both operations return `unavailable`
on failure. No buckets, CAS resources, overwrites, deletion, counters, or
enumeration are exposed. This directly matches the Rocq storage operations and
does not depend on a WASI keyvalue draft.

The runtime grants a read/write directory preopen named `/accounts`.
No absolute host paths, environment variables, or networking are needed by the
provider. The service and gateway do not import filesystem interfaces.
In the final composition, config and storage share all filesystem preopens:
both can access `/accounts` and `/config`, and the CLI grants are writable.
The provider uses `/accounts` by convention, not per-provider runtime isolation.

## Disk Format

Each account is one `<lowercase SHA-256 hex of exact key bytes>.account` file.
Keys are neither normalized nor used as paths. The file contains:

| Bytes | Meaning |
| --- | --- |
| 0..8 | ASCII `AKSTORE1`, including the format version |
| 8..12 | Original key length, little-endian `u32` |
| 12..12+length | Original UTF-8 key bytes |
| Remaining bytes | Opaque value bytes (the service's account JSON) |

The entire envelope is limited to 1 MiB. Reads validate the version, bound,
and exact key; a misplaced record or hash collision fails closed. Only
`no-entry` means absence. Malformed records and other I/O errors remain errors.
SHA-256 collision resistance is an additional assumption for key availability.

## Publication And Durability

Creation writes the complete envelope into `.tmp-<random digest>`, opened with
`create | exclusive` in the same directory. It handles partial writes, syncs
the file, and calls `link-at` to publish the final name. An existing final name
cannot be replaced. The hard link is the atomic claim and publication point:
readers see either absence or the complete record, across independent component
instances and OS processes. The final account is never opened for writing.

After publication the provider syncs the directory before acknowledging success.
A directory-sync failure returns a storage error but leaves the account visible:
the durability outcome is uncertain, and a retry can report an existing account.
These operations rely on the underlying filesystem's hard-link, atomicity, and
sync guarantees; filesystems that do not support them fail rather than silently
falling back to claim-then-write. This is tested Rust/WASI code, not a formal
discharge of the Rocq storage hypotheses.

Temporary names are unlinked after a completed attempt. Cleanup errors do not
undo publication. A crash, trap, fuel exhaustion, or cleanup failure can leave
orphan temporaries, which lookups ignore. With every process using the directory
stopped, operators may remove `.tmp-*` files; do not sweep them while writers
are active. Backup, quotas, automated garbage collection, and recovery tooling
are not implemented. The directory must be protected from other writers; the
provider does not defend against a host or local user modifying its files.

## Verification

From the repository root, `make app-component` builds all providers and the
service; `make compose-app` rebuilds storage, config and gateway and wires them
to existing service/crypto/email artifacts via root `composition.wac`.
`cargo test --locked -p authentikate-storage` checks the native storage logic.
`make test-app` exercises the actual Wasm provider through Wasmtime HTTP requests,
including duplicate creation and account persistence across process restarts.
The provisioned signing key is retained too, so unexpired tokens remain valid.
These tests do not establish filesystem durability or all concurrent failure modes.
