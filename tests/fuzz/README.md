# Fuzz Testing

Fuzz testing targets for the sFlow parser using `cargo-fuzz`.

## Setup

```bash
make fuzz-install
```

## Run Fuzzers

```bash
make fuzz-single      # Basic datagram fuzzing (60s)
make fuzz-multiple    # Multiple datagrams fuzzing (60s)
make fuzz-structured  # Structured fuzzing with valid headers (60s)
make fuzz-all         # All fuzzers (5 minutes each)
```

## Analyze Crashes

Crashes are saved in `tests/fuzz/artifacts/<target>/`.

```bash
# Reproduce
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single artifacts/fuzz_single/crash-<hash>
```

## macOS

The nightly AddressSanitizer runtime hangs at startup on recent macOS, before any input is run (libFuzzer prints nothing and the process spins at 100% CPU). The Makefile targets therefore pass `--sanitizer none` on macOS; when running `cargo fuzz` directly, add it yourself:

```bash
cargo +nightly fuzz run --sanitizer none --fuzz-dir tests/fuzz fuzz_single
```

## Expected Behavior

The parser should **never panic**. All invalid inputs must return `Result::Err`.
