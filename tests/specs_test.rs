//! Specification validation tests
//!
//! This module validates the sFlow parser implementation against official
//! sFlow specification documents. It downloads and parses XDR definitions
//! from the specifications and compares them with the Rust implementation.
//!
//! Run with: `cargo test --test specs_test -- --ignored --nocapture`
//! Or use: `make specs-validate`

mod specs;
