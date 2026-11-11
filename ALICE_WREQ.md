# alice-wreq/wreq-rust

Fork of [0x676e67/wreq](https://github.com/0x676e67/wreq) (Apache-2.0) for the alice-wreq stack.

**Current base: upstream `v0.16.3`** → released here as tag **`alice-v0.16.3`**.

## Fork changes

- `Proxy::force_absolute(bool)` — for HTTPS destinations, skip the CONNECT tunnel and send
  the request to the proxy in absolute-form (`src/proxy.rs`, `src/proxy/matcher.rs`,
  `src/conn/connector.rs`). `WREQ_FORCE_ABSOLUTE_PROXY=1` enables it process-wide.
  Test: `tests/proxy.rs::force_absolute_skips_connect_for_https`.
- `.github/workflows/notify-wreq-js.yml` — `repository_dispatch` to wreq-js on `main` push.

## Remotes

| remote     | URL                                     |
| ---------- | --------------------------------------- |
| `origin`   | https://github.com/alice-wreq/wreq-rust |
| `upstream` | https://github.com/0x676e67/wreq       |

## Sync from upstream — release tags only

Track upstream **release tags**, not `upstream/main`: wreq-util releases lag behind
breaking API changes on wreq `main` (e.g. #1371 removed `enable_ech_grease`, which
wreq-util 0.2.1 still uses), so `main` builds break the profile crate.

```bash
git fetch upstream --tags
git merge vX.Y.Z                     # upstream release tag
cargo test --test proxy              # needs the rustc version in Cargo.toml (0.16.3: ≥ 1.98)
git tag -a alice-vX.Y.Z -m alice-vX.Y.Z
git push origin main alice-vX.Y.Z
```

Then bump the tag in wreq-js `rust/Cargo.toml` (`[patch.crates-io]`) and run
`cargo update -p wreq` there.

Note: on v0.16.3, 8 doctests fail upstream as well (`redirect`, `ws::message`,
`tls::trust::identity`, `conn::http`); unrelated to fork changes.

## Consumer

[alice-wreq/wreq-js](https://github.com/alice-wreq/wreq-js) pins this repo by tag:

```toml
[patch.crates-io]
wreq = { git = "https://github.com/alice-wreq/wreq-rust", tag = "alice-v0.16.3" }
```
