//! Engine-neutral routing policies, compilation and lifecycle integration.

pub mod compiler;
pub mod difflib;
pub mod error;
pub mod exits;
pub mod intent;
pub mod lanes;
pub mod net;
pub mod presets;
pub mod runtime;
pub mod service;
pub mod store;

#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod tests;
