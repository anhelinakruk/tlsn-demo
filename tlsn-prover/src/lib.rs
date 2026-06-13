mod error;
pub mod parser;
mod prover;
mod reveal;
pub mod transport;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::{Error, Result};
pub use prover::{Prover, ProverConfigBundle, ProverOutput};
pub use reveal::{BodyFieldConfig, KeyValueCommitConfig, RevealConfig};
#[cfg(not(target_arch = "wasm32"))]
pub use transport::SmolRuntime;
