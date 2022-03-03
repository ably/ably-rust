use crate::rest::Rest as RestInternal;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
pub struct Rest {
    rest: RestInternal,
}

#[wasm_bindgen]
impl Rest {
    #[wasm_bindgen(constructor)]
    pub fn new(key: String) -> Rest {
        Rest {
            rest: RestInternal::from(key),
        }
    }

    // https://github.com/rustwasm/wasm-bindgen/issues/2195
    pub async fn publish(self, channel: String, name: String) -> bool {
        let channel = self.rest.channels.get(channel);
        match channel.publish().string(name).send().await {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
