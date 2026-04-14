# Portly Public Beta Release Playbook

## Goal

Ship a reproducible public beta with verified frontend build, frontend tests, Rust tests, and Tauri bundle.

## Versioning

- App version source must stay aligned:
  - `package.json`
  - `src-tauri/Cargo.toml`
  - `src-tauri/tauri.conf.json`
- Beta tag format:
  - `v0.2.4-beta.1`
  - `v0.2.4-beta.2`

## Local Verification (before tag)

```bash
npm ci
npm run build
npm test -- --run
CARGO_TARGET_DIR=/tmp/portly-target cargo test --manifest-path src-tauri/Cargo.toml
CARGO_TARGET_DIR=/tmp/portly-target npm run tauri build -- --bundles app
```

## CI Gate

- `CI` workflow must pass on push/PR:
  - frontend build
  - frontend tests
  - Rust tests
- `Release` workflow includes `verify` job before creating release.

## Release Procedure

1. Merge release-ready branch to `main`.
2. Create and push beta tag:
   - `git tag v0.2.4-beta.1`
   - `git push origin v0.2.4-beta.1`
3. Wait for `Release` workflow to complete.
4. Validate uploaded artifacts:
   - macOS app bundle
   - CLI binaries
5. Publish release notes and known issues.

## Rollback

1. Mark faulty beta release as deprecated in GitHub release notes.
2. Publish next fixed beta tag (`v0.2.4-beta.N+1`).
3. If critical, temporarily pause distribution links in README.

## Known Environment Note

- In local workspaces with non-ASCII paths, Rust build artifacts can be unstable on some toolchains.
- Workaround: set `CARGO_TARGET_DIR` to an ASCII path (for example `/tmp/portly-target`).
