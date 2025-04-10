// SPDX-License-Identifier: Apache-2.0

use super::*;

use nix::{
    sys::signal::{SigSet, Signal, SIGHUP},
    unistd::*,
};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    thread, time,
};

pub struct SignalHandler {
    sig_set: Option<SigSet>,
}

impl SignalHandler {
    pub fn new(signals: &[Signal]) -> Self {
        let mut sig_set = SigSet::empty();
        for signal in signals.iter() {
            sig_set.add(*signal);
        }

        SignalHandler {
            sig_set: Some(sig_set),
        }
    }

    pub fn mask_all(&self) {
        if let Some(set) = self.sig_set {
            set.thread_block().unwrap();
        }
    }

    pub fn unmask_all(&self) {
        if let Some(set) = self.sig_set {
            set.thread_unblock().unwrap();
        }
    }
}

pub struct NitroEnclave {
    config: NitroContextConfig,
    usr_sock: UnixStream,
    enclave_sock: UnixStream,
}

impl From<NitroContextConfig> for NitroEnclave {
    fn from(config: NitroContextConfig) -> Self {
        let (usr_sock, enclave_sock) = UnixStream::pair().unwrap();

        let enclave_sock_fd = enclave_sock.as_raw_fd();

        // Prevent the enclave's file descriptor from being closed on exec().
        unsafe {
            let flags = libc::fcntl(enclave_sock_fd, libc::F_GETFD);
            libc::fcntl(enclave_sock_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }

        Self {
            config,
            usr_sock,
            enclave_sock,
        }
    }
}

impl NitroEnclave {
    pub fn run(&self) -> &UnixStream {
        let fork_status = unsafe { fork().unwrap() };
        if let ForkResult::Child = fork_status {
            self.enclave_process_run();
        }

        &self.usr_sock
    }

    fn enclave_process_run(&self) {
        let signal_handler = SignalHandler::new(&[SIGHUP]);
        signal_handler.mask_all();

        let ppid = getpid();
        daemon(true, false).unwrap();

        while getppid() == ppid {
            thread::sleep(time::Duration::from_millis(10));
        }

        signal_handler.unmask_all();
    }
}
