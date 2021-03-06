// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use core::{slice, convert::TryFrom};
use redbpf_probes::{kprobe::prelude::*, helpers};
use bpf_sniffer_common::{DataTag, SocketId, EventId};
use super::{
    syscall_context::SyscallContext,
    send,
    address::Address,
};

pub trait AppIo {
    fn rb(&mut self) -> &mut RingBuffer;

    fn is_interesting_port(&self, port: u16) -> bool;

    fn reg_process(&mut self, pid: u32, port: u16);
    fn is_process(&mut self, pid: u32) -> bool;

    fn reg_connection(&mut self, pid: u32, fd: u32, incoming: bool);
    fn is_connection(&self, pid: u32, fd: u32) -> bool;
    fn forget_connection(&mut self, pid: u32, fd: u32);

    fn push_context(&mut self, thread_id: u32, pid: u32, ts: u64, context: SyscallContext);
    fn pop_context<H: FnOnce(&mut Self, SyscallContext, u64)>(&mut self, thread_id: u32, handler: H);

    fn inc_counter(&mut self);
}

pub trait AppProbes {
    fn on_bind(&mut self, regs: &Registers);
    fn on_listen(&mut self, regs: &Registers);
    fn on_connect(&mut self, regs: &Registers, incoming: bool);
    fn on_close(&mut self, regs: &Registers);
    fn on_data(&mut self, regs: &Registers, incoming: bool, net: bool);

    fn on_ret_get_fd(&mut self, regs: &Registers);
    fn on_ret(&mut self, regs: &Registers);
}

impl<App: AppIo> AppProbes for App {
    fn on_bind(&mut self, regs: &Registers) {
        let fd = regs.parm1() as u32;
        let buf = regs.parm2() as *const u8;
        let size = regs.parm3() as usize;

        let (pid, thread_id) = {
            let x = helpers::bpf_get_current_pid_tgid();
            ((x >> 32) as u32, (x & 0xffffffff) as u32)
        };
        let ts = helpers::bpf_ktime_get_ns();

        let address = unsafe { slice::from_raw_parts(buf, size) };
    
        let context = SyscallContext::Bind { fd, address };
        self.push_context(thread_id, pid, ts, context);
    }

    fn on_listen(&mut self, regs: &Registers) {
        let fd = regs.parm1() as u32;

        let (pid, thread_id) = {
            let x = helpers::bpf_get_current_pid_tgid();
            ((x >> 32) as u32, (x & 0xffffffff) as u32)
        };
        let ts = helpers::bpf_ktime_get_ns();

        if !self.is_process(pid) {
            return;
        }
        let context = SyscallContext::Listen { fd, unused: 0 };
        self.push_context(thread_id, pid, ts, context);
    }

    fn on_connect(&mut self, regs: &Registers, incoming: bool) {
        let fd = regs.parm1() as u32;
        let buf = regs.parm2() as *const u8;
        let size = regs.parm3() as usize;

        let (pid, thread_id) = {
            let x = helpers::bpf_get_current_pid_tgid();
            ((x >> 32) as u32, (x & 0xffffffff) as u32)
        };
        let ts = helpers::bpf_ktime_get_ns();

        if !self.is_process(pid) {
            return;
        }
        let address = unsafe { slice::from_raw_parts(buf, size) };

        let context = if incoming {
            SyscallContext::Accept { listen_on_fd: fd, address }
        } else {
            SyscallContext::Connect { fd, address }
        };
        self.push_context(thread_id, pid, ts, context);
    }

    fn on_close(&mut self, regs: &Registers) {
        let fd = regs.parm1() as u32;

        let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
        let ts = helpers::bpf_ktime_get_ns();
        if !self.is_process(pid) {
            return;
        }

        if self.is_connection(pid, fd) {
            // TODO: check if socket actually closed
            self.forget_connection(pid, fd);

            let id = EventId::new(SocketId { pid, fd }, ts, ts);
            send::sized::<typenum::U0, typenum::B0>(id, DataTag::Close, &[], self.rb());
            self.inc_counter();
        }
    }

    fn on_data(&mut self, regs: &Registers, incoming: bool, net: bool) {
        let fd = regs.parm1() as u32;
        let data_ptr = regs.parm2() as usize;

        let (pid, thread_id) = {
            let x = helpers::bpf_get_current_pid_tgid();
            ((x >> 32) as u32, (x & 0xffffffff) as u32)
        };
        let ts = helpers::bpf_ktime_get_ns();

        if !self.is_connection(pid, fd) {
            return;
        }

        let context = match (net, incoming) {
            (false, false) => SyscallContext::Write { fd, data_ptr },
            (false, true) => SyscallContext::Read { fd, data_ptr },
            (true, false) => SyscallContext::Send { fd, data_ptr },
            (true, true) => SyscallContext::Recv { fd, data_ptr },
        };
        self.push_context(thread_id, pid, ts, context);
    }

    fn on_ret_get_fd(&mut self, regs: &Registers) {
        let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
        if !self.is_process(pid) {
            return;
        }

        let fd = regs.rc() as u32;
        let ts = helpers::bpf_ktime_get_ns();
        let id = EventId::new(SocketId { pid, fd }, ts, ts);
        send::sized::<typenum::U0, typenum::B0>(id, DataTag::GetFd, &[], self.rb());
    }

    fn on_ret(&mut self, regs: &Registers) {
        let (pid, thread_id) = {
            let x = helpers::bpf_get_current_pid_tgid();
            ((x >> 32) as u32, (x & 0xffffffff) as u32)
        };
        let ts = helpers::bpf_ktime_get_ns();

        self.pop_context(thread_id, |app, context, ts0| match context {
            SyscallContext::Bind { fd, address } => {
                if regs.is_syscall_success() {
                    let mut tmp = [0xff; Address::RAW_SIZE];
                    unsafe {
                        gen::bpf_probe_read_user(
                            tmp.as_mut_ptr() as _,
                            tmp.len().min(address.len()) as u32,
                            address.as_ptr() as _,
                        )
                    };

                    let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                    if let Ok(a) = Address::try_from(tmp.as_ref()) {
                        let port = a.port();
                        if app.is_interesting_port(port) {
                            app.reg_process(pid, port);
                            send::sized::<typenum::U28, typenum::B0>(id, DataTag::Bind, address, app.rb());
                            app.inc_counter();
                        } else {
                            // ignore
                        }
                    } else {
                        // ignore connection to other type of address
                        // track only ipv4 (af_inet) and ipv6 (af_inet6)
                    }
                }
            },
            SyscallContext::Listen { fd, .. } => {
                if regs.is_syscall_success() {
                    let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                    send::sized::<typenum::U0, typenum::B0>(id, DataTag::Listen, &[], app.rb());
                    app.inc_counter();
                }
            },
            SyscallContext::Connect { fd, address } => {
                if regs.is_syscall_success() {
                    let mut tmp = [0xff; Address::RAW_SIZE];
                    unsafe {
                        gen::bpf_probe_read_user(
                            tmp.as_mut_ptr() as _,
                            tmp.len().min(address.len()) as u32,
                            address.as_ptr() as _,
                        )
                    };

                    let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                    if let Ok(_) = Address::try_from(tmp.as_ref()) {
                        app.reg_connection(pid, fd, false);
                        send::sized::<typenum::U28, typenum::B0>(id, DataTag::Connect, address, app.rb());
                        app.inc_counter();
                    } else {
                        // AF_UNSPEC
                        if tmp[0] == 0 && tmp[1] == 0 {
                            if app.is_connection(pid, fd) {
                                app.forget_connection(pid, fd);
                                send::sized::<typenum::U0, typenum::B0>(id, DataTag::Close, &[], app.rb());
                                app.inc_counter();
                            }
                        }
                        // ignore connection to other type of address
                        // track only ipv4 (af_inet) and ipv6 (af_inet6)
                    }
                }
            },
            SyscallContext::Accept { listen_on_fd, address } => {
                if regs.is_syscall_success() {
                    let fd = regs.rc() as u32;

                    let mut tmp = [0xff; Address::RAW_SIZE];
                    unsafe {
                        gen::bpf_probe_read_user(
                            tmp.as_mut_ptr() as _,
                            Address::RAW_SIZE.min(address.len()) as u32,
                            address.as_ptr() as _,
                        )
                    };
                    let _ = listen_on_fd;
    
                    let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                    if let Ok(_) = Address::try_from(tmp.as_ref()) {
                        app.reg_connection(pid, fd, true);
                        send::sized::<typenum::U28, typenum::B0>(id, DataTag::Accept, address, app.rb());
                        app.inc_counter();
                    } else {
                        // AF_UNSPEC
                        if tmp[0] == 0 && tmp[1] == 0 {
                            if app.is_connection(pid, fd) {
                                app.forget_connection(pid, fd);
                                send::sized::<typenum::U0, typenum::B0>(id, DataTag::Close, &[], app.rb());
                                app.inc_counter();
                            }
                        }
                        // ignore connection to other type of address
                        // track only ipv4 (af_inet) and ipv6 (af_inet6)
                    }
                }
            },
            SyscallContext::Read { fd, data_ptr } => {
                let read = regs.rc();
                let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                if regs.is_syscall_success() && read as i64 > 0 {
                    let data = unsafe { slice::from_raw_parts(data_ptr as *mut u8, read as usize) };
                    send::dyn_sized::<typenum::B0>(id, DataTag::Read, data, app.rb());
                }
                app.inc_counter();
            },
            SyscallContext::Write { fd, data_ptr } => {
                let written = regs.rc();
                let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                if regs.is_syscall_success() && written as i64 > 0 {
                    let data = unsafe { slice::from_raw_parts(data_ptr as *mut u8, written as usize) };
                    send::dyn_sized::<typenum::B0>(id, DataTag::Write, data, app.rb());
                }
                app.inc_counter();
            },
            SyscallContext::Recv { fd, data_ptr } => {
                let read = regs.rc();
                let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                if regs.is_syscall_success() && read as i64 > 0 {
                    let data = unsafe { slice::from_raw_parts(data_ptr as *mut u8, read as usize) };
                    send::dyn_sized::<typenum::B0>(id, DataTag::Recv, data, app.rb());
                }
                app.inc_counter();
            },
            SyscallContext::Send { fd, data_ptr } => {
                let written = regs.rc();
                let id = EventId::new(SocketId { pid, fd }, ts0, ts);
                if regs.is_syscall_success() && written as i64 > 0 {
                    let data = unsafe { slice::from_raw_parts(data_ptr as *mut u8, written as usize) };
                    send::dyn_sized::<typenum::B0>(id, DataTag::Send, data, app.rb());
                }
                app.inc_counter();
            },
            _ => (),
        })
    }
}
