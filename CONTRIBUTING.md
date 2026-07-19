# Contributing to ably-rust

## Contributing

1. Fork it.
2. Clone your fork, then initialise the submodules (the `ably-common` test
   resources are required to run the suite):
   ```shell
   git submodule init && git submodule update
   ```
3. Create your feature branch (`git checkout -b my-new-feature`).
4. Commit your changes (`git commit -am 'Add some feature'`).
5. Ensure you have added suitable tests and the suite is passing (see
   [Test suite](#test-suite) below), and that `cargo fmt` and `cargo clippy`
   are clean.
6. Update `DESIGN.md` if the public API or the realtime state/concurrency
   contract changes, and the UTS traceability matrix if coverage changes (see
   [Coding conventions](#coding-conventions)).
7. Push the branch (`git push origin my-new-feature`).
8. Create a new Pull Request.

## Building the library

```shell
cargo build
```

The library has no non-standard build steps. The bundled vcdiff delta decoder
is the [`vcdiff-decode`](https://crates.io/crates/vcdiff-decode) crate, pulled
in as a normal dependency.

## Test suite

Unit tests (mocked HTTP/WebSocket) run in parallel:

```shell
cargo test --lib -- --skip tests_rest_integration --skip tests_realtime_integration --skip tests_proxy
```

The integration and proxy tests run against the live Ably nonprod sandbox and
share a provisioned app, so they must run serially:

```shell
cargo test --lib -- --test-threads=1 tests_rest_integration tests_realtime_integration tests_proxy
```

Notes:

- The full suite is green with zero failures; any failure after a change is a
  regression. Every `#[ignore]` carries an explicit recorded-deferral reason.
- The provisioned sandbox app is deleted automatically when the test process
  exits.
- The UTS traceability ratchet (`tests_uts_coverage`) reads the Universal Test
  Specification from a sibling checkout of
  [`ably/specification`](https://github.com/ably/specification) at
  `../specification`; check that out alongside this repo to run it.
- Formatting and lints:
  ```shell
  cargo fmt --check
  cargo clippy --all-targets
  ```

## Coding conventions

The binding conventions are documented in [`CLAUDE.md`](./CLAUDE.md) (loaded
into every working session) and [`DESIGN.md`](./DESIGN.md) (the API surface and
the realtime state/concurrency contract). In particular:

- Realtime tests are **derived from the UTS** (`../specification/uts/`), not
  from any prior implementation, and every UTS Test ID is either mapped to a
  covering test or excluded with a reason in `uts_coverage.txt`. The
  `tests_uts_coverage` ratchet enforces this; regenerate the matrix with
  `python3 tools/uts_coverage_generate.py <full-serial-run.txt>` and review the
  diff (it is a curated artifact). When converting an exclusion, update the
  generator's dispositions in `tools/uts_coverage_generate.py` in the same
  change.
- All mutable realtime protocol state is owned by the single connection loop
  with no locks on it; `tests_design_conformance` enforces the lock inventory.
- Observability is part of "done" per the policy in `DESIGN.md`.

Ongoing work is tracked with the [Backlog.md](https://backlog.md) CLI in
`backlog/tasks/`; `backlog` resolves via the repo `.tool-versions`. Use
`backlog task list --plain`.

## Release Process

Releases are made through a release pull request that bumps the version.

1. Ensure all work for the release has landed on `main` and CI is green.
2. Create a release branch, e.g. `release/0.3.0`.
3. Bump `version` in [`Cargo.toml`](./Cargo.toml).
4. Open the release PR (include an SDK Team reviewer), gain approval, and merge
   to `main`.
5. Tag the release (`git tag v0.3.0 && git push origin v0.3.0`) and create the
   GitHub release with notes.
6. Publish to [crates.io](https://crates.io/crates/ably): `cargo publish`.
7. Update the [Ably Changelog](https://changelog.ably.com/) with the changes.
