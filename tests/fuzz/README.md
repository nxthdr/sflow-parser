# Fuzz Testing for sFlow Parser

This directory contains fuzz testing targets for the sFlow parser using `cargo-fuzz` and libFuzzer.

## Setup

Fuzzing requires the Rust nightly toolchain. Install cargo-fuzz:
```bash
make fuzz-install
# or manually:
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
```

## Fuzz Targets

### 1. `fuzz_single` - Basic Datagram Fuzzing
Tests parsing of a single sFlow datagram with completely random data.

```bash
make fuzz-single
# or
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single
```

### 2. `fuzz_multiple` - Multiple Datagrams Fuzzing
Tests parsing of multiple consecutive sFlow datagrams, including boundary detection.

```bash
make fuzz-multiple
# or
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_multiple
```

### 3. `fuzz_structured` - Structured Fuzzing
Uses structured fuzzing with the `arbitrary` crate to generate more realistic sFlow data with valid headers but fuzzed sample data.

```bash
make fuzz-structured
# or
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_structured
```

## Running Fuzzers

### Quick Test (1 minute each)
```bash
make fuzz-single     # Run basic fuzzer for 60 seconds
make fuzz-multiple   # Run multiple datagrams fuzzer for 60 seconds
make fuzz-structured # Run structured fuzzer for 60 seconds
```

### Extended Test (5 minutes each)
```bash
make fuzz-all       # Run all fuzzers for 5 minutes each
```

### Custom Duration
```bash
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single -- -max_total_time=300  # 5 minutes
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single -- -runs=1000000        # 1 million runs
```

## Corpus Management

The fuzzer maintains a corpus of interesting inputs in `tests/fuzz/corpus/<target>/`.

### Seed Corpus
Initial seed inputs are provided in the corpus directories to help the fuzzer start with valid sFlow data.

### Minimize Corpus
```bash
cargo +nightly fuzz cmin --fuzz-dir tests/fuzz fuzz_single
```

### Merge Corpora
```bash
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single -- -merge=1 corpus/fuzz_single new_corpus/
```

## Analyzing Crashes

If the fuzzer finds a crash, it will save the input in `tests/fuzz/artifacts/<target>/`.

### Reproduce a Crash
```bash
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single tests/fuzz/artifacts/fuzz_single/crash-<hash>
```

### Debug a Crash
```bash
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single --debug-assertions tests/fuzz/artifacts/fuzz_single/crash-<hash>
```

## Coverage Analysis

Generate coverage information for the fuzz corpus:

```bash
make fuzz-coverage
# or
cargo +nightly fuzz coverage --fuzz-dir tests/fuzz fuzz_single
```

This generates coverage data in `tests/fuzz/coverage/fuzz_single/`.

## Continuous Fuzzing

For continuous fuzzing in CI/CD:

```bash
# Run for 1 hour
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single -- -max_total_time=3600

# Run until crash found
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single
```

## Tips

1. **Start with seed corpus**: The fuzzers use real sFlow data as seeds for better coverage
2. **Monitor memory**: Fuzzing can be memory-intensive, use `-rss_limit_mb=2048` to limit
3. **Parallel fuzzing**: Run multiple instances with `-jobs=N` for faster results
4. **Dictionary**: Create a dictionary file with common sFlow values for better mutations

## Cleaning Up

Remove all fuzz artifacts and corpus:
```bash
make fuzz-clean
```

## Expected Behavior

The parser should **never panic** on any input. All invalid inputs should return proper `Result::Err` values.

Common issues to watch for:
- Buffer overruns
- Integer overflows
- Infinite loops
- Stack overflows
- Excessive memory allocation
