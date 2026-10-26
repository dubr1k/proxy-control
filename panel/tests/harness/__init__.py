"""External acceptance harness for the actual Rust panel binary.

`server` launches the panel built with Cargo's `test-hooks` feature, seeds it through its
CLI, and exposes HTTP, read-only SQL, clock and explicit loop-tick seams. `fake_managers`
serves the test-owned `memories` over real manager wire protocols. No Python panel
implementation, in-process ASGI fallback, or migration-category deselection is used.
"""
