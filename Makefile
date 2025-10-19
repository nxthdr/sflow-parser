.PHONY: help test test-unit test-integration test-unit-verbose test-integration-verbose test-all test-verbose test-lib test-validate bench coverage coverage-html coverage-open coverage-lcov coverage-unit coverage-integration clean build build-release build-all check fmt fmt-check clippy clippy-strict doc doc-open doc-all install-tools audit outdated

# Default target
help:
	@echo "sFlow Parser - Available targets:"
	@echo ""
	@echo "Testing:"
	@echo "  make test                     - Run all tests"
	@echo "  make test-unit                - Run unit tests only"
	@echo "  make test-integration         - Run integration tests only"
	@echo "  make test-unit-verbose        - Run unit tests with output"
	@echo "  make test-integration-verbose - Run integration tests with output"
	@echo "  make test-verbose             - Run all tests with verbose output"
	@echo "  make test-validate            - Validate against official sflow.h (requires network)"
	@echo "  make bench                    - Run performance benchmarks"
	@echo ""
	@echo "Coverage:"
	@echo "  make coverage          - Generate coverage report (text)"
	@echo "  make coverage-html     - Generate HTML coverage report"
	@echo "  make coverage-open     - Generate and open HTML coverage report"
	@echo "  make coverage-lcov     - Generate LCOV coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  make check             - Run all checks (fmt, clippy, test)"
	@echo "  make fmt               - Format code"
	@echo "  make fmt-check         - Check code formatting"
	@echo "  make clippy            - Run clippy lints"
	@echo "  make clippy-strict     - Run clippy with strict lints"
	@echo ""
	@echo "Build:"
	@echo "  make build             - Build the project"
	@echo "  make build-release     - Build release version"
	@echo "  make doc               - Generate documentation"
	@echo "  make doc-open          - Generate and open documentation"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean             - Clean build artifacts"
	@echo "  make install-tools     - Install required development tools"
	@echo "  make audit             - Run security audit"
	@echo "  make outdated          - Check for outdated dependencies"

# Testing targets
test:
	@echo "Running all tests..."
	cargo test

test-unit:
	@echo "Running unit tests..."
	cargo test --test unit_tests

test-integration:
	@echo "Running integration tests..."
	cargo test --test integration_test

test-unit-verbose:
	@echo "Running unit tests with output..."
	cargo test --test unit_tests -- --nocapture

test-integration-verbose:
	@echo "Running integration tests with output..."
	cargo test --test integration_test -- --nocapture

test-all: test
	@echo "All tests completed!"

test-verbose:
	@echo "Running tests with verbose output..."
	cargo test -- --nocapture --test-threads=1

test-lib:
	@echo "Running library tests..."
	cargo test --lib

test-validate:
	@echo "Validating implementation against official sflow.h..."
	@echo "Note: This requires network access to download sflow.h from GitHub"
	cargo test validation::validation::tests::test_validate_all_formats_live -- --nocapture --ignored

bench:
	@echo "Running performance benchmarks..."
	cargo bench --bench parser_benchmark

# Coverage targets
coverage:
	@echo "Generating coverage report..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found. Run 'make install-tools' first."; exit 1; }
	cargo llvm-cov --all-features

coverage-html:
	@echo "Generating HTML coverage report..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found. Run 'make install-tools' first."; exit 1; }
	cargo llvm-cov --all-features --html
	@echo "Coverage report generated at: target/llvm-cov/html/index.html"

coverage-open:
	@echo "Generating and opening HTML coverage report..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found. Run 'make install-tools' first."; exit 1; }
	cargo llvm-cov --all-features --html --open

coverage-lcov:
	@echo "Generating LCOV coverage report..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found. Run 'make install-tools' first."; exit 1; }
	cargo llvm-cov --all-features --lcov --output-path lcov.info
	@echo "LCOV report generated at: lcov.info"

coverage-unit:
	@echo "Generating coverage for unit tests only..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found. Run 'make install-tools' first."; exit 1; }
	cargo llvm-cov --test unit_tests

coverage-integration:
	@echo "Generating coverage for integration tests only..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found. Run 'make install-tools' first."; exit 1; }
	cargo llvm-cov --test integration_test

# Code quality targets
check: fmt-check clippy test
	@echo "All checks passed!"

fmt:
	@echo "Formatting code..."
	cargo fmt

fmt-check:
	@echo "Checking code formatting..."
	cargo fmt -- --check

clippy:
	@echo "Running clippy..."
	cargo clippy -- -D warnings

clippy-strict:
	@echo "Running clippy with strict lints..."
	cargo clippy --all-targets --all-features -- \
		-D warnings \
		-D clippy::all \
		-D clippy::pedantic \
		-W clippy::cargo

# Build targets
build:
	@echo "Building project..."
	cargo build

build-release:
	@echo "Building release version..."
	cargo build --release

build-all: build build-release
	@echo "All builds completed!"

# Documentation targets
doc:
	@echo "Generating documentation..."
	cargo doc --no-deps

doc-open:
	@echo "Generating and opening documentation..."
	cargo doc --no-deps --open

doc-all:
	@echo "Generating documentation with dependencies..."
	cargo doc

# Utility targets
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f lcov.info
	rm -rf target/llvm-cov

install-tools:
	@echo "Installing development tools..."
	@echo "Installing cargo-llvm-cov for coverage..."
	cargo install cargo-llvm-cov
	@echo "Installing cargo-audit for security audits..."
	cargo install cargo-audit
	@echo "Installing cargo-outdated for dependency checks..."
	cargo install cargo-outdated
	@echo "All tools installed!"

# Security and dependency checks
audit:
	@echo "Running security audit..."
	@command -v cargo-audit >/dev/null 2>&1 || { echo "cargo-audit not found. Run 'make install-tools' first."; exit 1; }
	cargo audit

outdated:
	@echo "Checking for outdated dependencies..."
	@command -v cargo-outdated >/dev/null 2>&1 || { echo "cargo-outdated not found. Run 'make install-tools' first."; exit 1; }
	cargo outdated

# Fuzzing targets
fuzz-install:
	@echo "Installing cargo-fuzz and nightly toolchain..."
	rustup toolchain install nightly
	cargo +nightly install cargo-fuzz

fuzz-single:
	@echo "Running single datagram fuzzer..."
	@command -v cargo-fuzz >/dev/null 2>&1 || { echo "cargo-fuzz not found. Run 'make fuzz-install' first."; exit 1; }
	cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single -- -max_total_time=60 -rss_limit_mb=2048

fuzz-multiple:
	@echo "Running multiple datagrams fuzzer..."
	@command -v cargo-fuzz >/dev/null 2>&1 || { echo "cargo-fuzz not found. Run 'make fuzz-install' first."; exit 1; }
	cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_multiple -- -max_total_time=60 -rss_limit_mb=2048

fuzz-structured:
	@echo "Running structured fuzzer..."
	@command -v cargo-fuzz >/dev/null 2>&1 || { echo "cargo-fuzz not found. Run 'make fuzz-install' first."; exit 1; }
	cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_structured -- -max_total_time=60 -rss_limit_mb=2048

fuzz-all:
	@echo "Running all fuzzers (5 minutes each)..."
	@command -v cargo-fuzz >/dev/null 2>&1 || { echo "cargo-fuzz not found. Run 'make fuzz-install' first."; exit 1; }
	cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_single -- -max_total_time=300 -rss_limit_mb=2048
	cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_multiple -- -max_total_time=300 -rss_limit_mb=2048
	cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_structured -- -max_total_time=300 -rss_limit_mb=2048

fuzz-list:
	@echo "Available fuzz targets:"
	@command -v cargo-fuzz >/dev/null 2>&1 || { echo "cargo-fuzz not found. Run 'make fuzz-install' first."; exit 1; }
	cargo +nightly fuzz list --fuzz-dir tests/fuzz

fuzz-coverage:
	@echo "Generating coverage for fuzz corpus..."
	@command -v cargo-fuzz >/dev/null 2>&1 || { echo "cargo-fuzz not found. Run 'make fuzz-install' first."; exit 1; }
	cargo +nightly fuzz coverage --fuzz-dir tests/fuzz fuzz_single

fuzz-clean:
	@echo "Cleaning fuzz artifacts..."
	rm -rf tests/fuzz/corpus tests/fuzz/artifacts
