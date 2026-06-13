pub mod io;
pub mod prover;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

use crate::transport::{BoxFuture, Runtime};

pub(crate) struct WasmRuntime;

impl Runtime for WasmRuntime {
    fn spawn_detached(&self, future: BoxFuture<()>) {
        spawn_local(future);
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();
}

#[wasm_bindgen]
pub async fn initialize() -> Result<(), JsError> {
    JsFuture::from(web_spawn::start_spawner())
        .await
        .map_err(|e| JsError::new(&format!("web-spawn spawner failed to start: {e:?}")))?;
    Ok(())
}
