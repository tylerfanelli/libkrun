// SPDX-License-Identifier: Apache-2.0

use log::warn;
use once_cell::sync::Lazy;
use std::{
    collections::{hash_map::Entry, HashMap},
    path::PathBuf,
    sync::{
        atomic::{AtomicI32, Ordering},
        Mutex,
    },
};

const KRUN_SUCCESS: i32 = 0;

static CTX_MAP: Lazy<Mutex<HashMap<u32, NitroContextConfig>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CTX_IDS: AtomicI32 = AtomicI32::new(0);

#[derive(Default)]
#[allow(dead_code)]
struct NitroContextConfig {
    vcpus: Option<u8>,
    ram_mib: Option<usize>,
    cid: Option<u8>,
    eif: Option<PathBuf>,
    debug: bool,
}

impl NitroContextConfig {
    fn set_vm_config(&mut self, vcpus: u8, ram_mib: usize) {
        self.vcpus = Some(vcpus);
        self.ram_mib = Some(ram_mib);
    }
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

#[no_mangle]
pub extern "C" fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32 {
    let mem_size_mib: usize = match ram_mib.try_into() {
        Ok(size) => size,
        Err(e) => {
            warn!("Error parsing the amount of RAM: {e:?}");
            return -libc::EINVAL;
        }
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => ctx_cfg.get_mut().set_vm_config(num_vcpus, mem_size_mib),
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}
