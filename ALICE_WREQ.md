# alice-wreq/wreq-rust

Fork of [0x676e67/wreq](https://github.com/0x676e67/wreq) (Apache-2.0) for the alice-wreq stack.

## Remotes

| remote | URL |
|--------|-----|
| `origin` | https://github.com/alice-wreq/wreq-rust |
| `upstream` | https://github.com/0x676e67/wreq |

## Sync from upstream

```bash
git fetch upstream
git merge upstream/main
git push origin main
```

## Consumer

[alice-wreq/wreq-js](https://github.com/alice-wreq/wreq-js) depends on this repo via Cargo:

```toml
wreq = { git = "https://github.com/alice-wreq/wreq-rust", branch = "main", ... }
```

Pushing to `main` triggers `wreq-js` rebuild CI (repository_dispatch).
