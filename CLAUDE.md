To implement a new sFlow specification extension, follow these steps:

1. Read the specification document. You can find it on the `README.md`.
2. Implement the models in the `src/models` directory for the flows and counters records. Please keep the ordering of the models based on the (enterprise, format) tuple. Also, please include a docstring for each model with the specification XDR record definition. Stay as close as possible to the specification, keeping the field names, types (adapting for Rust) and order.
3. Implement the parser in the `src/parsers` directory. Please keep the ordering of the parsers based on the (enterprise, format) tuple.
4. Add unit tests in the `tests/unit` directory. Particularly, implement at minimum one test for each parser in the `tests/unit/comprehensive` directory. Please keep the ordering of the tests based on the (enterprise, format) tuple.
5. See if the integration tests need to be updated in the `tests/integration` directory.
6. Update the documentation in the `README.md` file, checking newly implemented specifications, and the newly implemented flow and counter records sections.
7. Add the specification in the `tests/validation/specs_validation.rs` file (in the `SFLOW_SPECS` constant). Please keep the ordering of the specifications based on the year.

To implement records that are not part of a spec (such as sFlow discussions), you can follow the plan above but skip the steps related to the specification validation.

To check that the implementation is correct, please run:

1. `make test` to validate the unit tests.
2. `make test-integration` to validate the integration tests.
3. `make specs-validate` to validate the implementation against the official sFlow specifications. If there is any warning, please check if is due to the implementation or the validation script. In any case, please fix the issue until there is no warning. Avoid doing exception to make the tests pass unless it is really justified and well documented. Also make sure that all of the newly added models are validated.
4. `make coverage` to validate the coverage of the implementation.

Finally, run `make fmt` and `make clippy` and `make build` to validate the code quality and build the project.

## Releasing

Releases are cut with [`cargo-release`](https://github.com/crate-ci/cargo-release) and published to crates.io as the `sflow-parser` crate. There is **no CI publish workflow** — publishing happens locally, so you need crates.io credentials (`cargo login` once; the API token is stored in `~/.cargo/credentials.toml`).

`main` is ruleset-protected (PRs required), but the `OrganizationAdmin` role has `bypass: always`, so an org owner's local `cargo release` push to `main` is allowed — which is why release commits land directly on `main` rather than via a PR.

To cut a release X.Y.Z (semver — the library is pre-1.0, so a behavioural/robustness change such as the #45 OOM fix warrants a minor bump):

1. Make sure `main` is checked out, clean, up to date, and green: `make test && make fmt && make clippy && make build` (CI additionally runs `cargo doc` with `-D warnings` and the specs validation).
2. Run the release. One command bumps `Cargo.toml`, commits `chore: Release sflow-parser version X.Y.Z`, runs `cargo publish`, tags `vX.Y.Z`, and pushes `main` + the tag to `origin`:
   ```bash
   cargo release X.Y.Z --execute
   ```
   Omit `--execute` for a dry run that prints every step without publishing or pushing.
3. Create the GitHub Release. `cargo-release` does **not** do this, but every prior version has one:
   ```bash
   gh release create vX.Y.Z --generate-notes --latest --verify-tag
   ```
4. Confirm crates.io shows the new version and the GitHub release/tag exist.

Gotchas:
- crates.io is publish-once: the `Cargo.toml` version must not already be published. `cargo publish` hard-fails on a duplicate, and you can only *yank*, never unpublish.
- `cargo publish` runs **before** the git push, so if the push to `main` is rejected the crate is already live — re-run only the tag/push steps, do not re-publish.
- The published package excludes `.github/`, `benches/`, and `tests/` (see `exclude` in `Cargo.toml`), so CI, workflow, and test-only changes never affect crate contents.
