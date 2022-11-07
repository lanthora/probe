use aya_bpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

use aya_log_ebpf::info;

use crate::{golang::get_opid, socket::fd_to_socket, EACCES, EINVAL, ENOMEM};

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct RwCtx {
    fd: i32,
    buf: usize,
    count: u64,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct FdKey(u32, i64);

#[map]
static mut RW_CTX_MAP: HashMap<u64, RwCtx> = HashMap::with_max_entries(1024, 0);

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
fn try_sys_enter_read(ctx: TracePointContext) -> Result<i32, i32> {
    let fd: i32 = unsafe { ctx.read_at(16) }.or(Err(-EINVAL))?;
    let buf: usize = unsafe { ctx.read_at(24) }.or(Err(-EINVAL))?;
    let count: u64 = unsafe { ctx.read_at(32) }.or(Err(-EINVAL))?;

    let id = bpf_get_current_pid_tgid();
    let rw_ctx = RwCtx { fd, buf, count };
    unsafe { RW_CTX_MAP.insert(&id, &rw_ctx, 0) }.or(Err(-ENOMEM))?;
    Ok(0)
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
fn try_sys_enter_write(ctx: TracePointContext) -> Result<i32, i32> {
    let fd: i32 = unsafe { ctx.read_at(16) }.or(Err(-EINVAL))?;
    let buf: usize = unsafe { ctx.read_at(24) }.or(Err(-EINVAL))?;
    let count: u64 = unsafe { ctx.read_at(32) }.or(Err(-EINVAL))?;

    let id = bpf_get_current_pid_tgid();
    let rw_ctx = RwCtx { fd, buf, count };
    unsafe { RW_CTX_MAP.insert(&id, &rw_ctx, 0) }.or(Err(-ENOMEM))?;
    Ok(0)
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
fn try_sys_exit_read(ctx: TracePointContext) -> Result<i32, i32> {
    let id = bpf_get_current_pid_tgid();
    let rw_ctx = unsafe { RW_CTX_MAP.get(&id) }.ok_or(-EACCES)?;
    unsafe { RW_CTX_MAP.remove(&id) }.or(Err(-EACCES))?;

    let ret: i64 = unsafe { ctx.read_at(16) }.or(Err(-EINVAL))?;
    if ret <= 0 {
        return Err(-EACCES);
    }

    fd_to_socket(&ctx, rw_ctx.fd as i32)?;

    let opid = get_opid()?;
    info!(&ctx, "read: opid={}, fd={}, ret={}", opid, rw_ctx.fd, ret);

    Ok(0)
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
fn try_sys_exit_write(ctx: TracePointContext) -> Result<i32, i32> {
    let id = bpf_get_current_pid_tgid();
    let rw_ctx = unsafe { RW_CTX_MAP.get(&id) }.ok_or(-EACCES)?;
    unsafe { RW_CTX_MAP.remove(&id) }.or(Err(-EACCES))?;

    let ret: i64 = unsafe { ctx.read_at(16) }.or(Err(-EINVAL))?;
    if ret <= 0 {
        return Err(-EACCES);
    }

    fd_to_socket(&ctx, rw_ctx.fd as i32)?;

    let opid = get_opid()?;
    info!(&ctx, "write: opid={}, fd={}, ret={}", opid, rw_ctx.fd, ret);

    Ok(0)
}

#[tracepoint(name = "sys_enter_read")]
pub fn sys_enter_read(ctx: TracePointContext) -> i32 {
    match try_sys_enter_read(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "sys_exit_read")]
pub fn sys_exit_read(ctx: TracePointContext) -> i32 {
    match try_sys_exit_read(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "sys_enter_write")]
pub fn sys_enter_write(ctx: TracePointContext) -> i32 {
    match try_sys_enter_write(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "sys_exit_write")]
pub fn sys_exit_write(ctx: TracePointContext) -> i32 {
    match try_sys_exit_write(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}
