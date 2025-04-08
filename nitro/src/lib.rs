// SPDX-License-Identifier: Apache-2.0

use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicI32, Ordering},
        Mutex,
    },
};

static CTX_MAP: Lazy<Mutex<HashMap<u32, NitroContextConfig>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CTX_IDS: AtomicI32 = AtomicI32::new(0);

#[derive(Default)]
#[allow(dead_code)]
struct NitroContextConfig {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    cid: Option<u8>,
    eif: Option<PathBuf>,
    debug: bool,
}

#[no_mangle]
pub extern "C" fn krun_create_ctx() -> i32 {
    let ctx_cfg = NitroContextConfig::default();

    let ctx_id = CTX_IDS.fetch_add(1, Ordering::SeqCst);
    if ctx_id == i32::MAX || CTX_MAP.lock().unwrap().contains_key(&(ctx_id as u32)) {
        panic!("Context ID namespace exhausted");
    }

    CTX_MAP.lock().unwrap().insert(ctx_id as u32, ctx_cfg);

    ctx_id
}
