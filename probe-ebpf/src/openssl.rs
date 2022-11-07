use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    macros::{map, uprobe, uretprobe},
    maps::HashMap,
    programs::ProbeContext,
};

use aya_log_ebpf::info;

use crate::{EACCES, EINVAL, ENOMEM};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SSLCtx {
    pub ssl: usize,
    pub buf: usize,
    pub num: i32,
}

#[map]
static mut SSL_CTX_MAP: HashMap<u64, SSLCtx> = HashMap::with_max_entries(1024, 0);

const RBIO_SSL_OFFSET: usize = 0x10;
const FD_RBIO_OFFSET: usize = 0x30;

fn get_fd_from_ssl(ssl: usize) -> Result<i32, i32> {
    let rbio = (ssl + RBIO_SSL_OFFSET) as *const usize;
    let rbio = unsafe { bpf_probe_read(rbio) }.or(Err(-ENOMEM))?;
    let fd = (rbio + FD_RBIO_OFFSET) as *const i32;
    let fd = unsafe { bpf_probe_read(fd) }.or(Err(-ENOMEM))?;
    Ok(fd)
}

// int SSL_write(SSL *ssl, const void *buf, int num);
fn try_enter_openssl_write(ctx: ProbeContext) -> Result<i32, i32> {
    let ssl: usize = ctx.arg(0).ok_or(-EINVAL)?;
    let buf: usize = ctx.arg(1).ok_or(-EINVAL)?;
    let num: i32 = ctx.arg(2).ok_or(-EINVAL)?;

    let id = bpf_get_current_pid_tgid();
    let ssl_ctx = SSLCtx { ssl, buf, num };
    unsafe { SSL_CTX_MAP.insert(&id, &ssl_ctx, 0) }.or(Err(-ENOMEM))?;
    Ok(0)
}

// int SSL_write(SSL *ssl, const void *buf, int num);
fn try_exit_openssl_write(ctx: ProbeContext) -> Result<i32, i32> {
    let retval: i32 = ctx.ret().ok_or(-EINVAL)?;

    let id = bpf_get_current_pid_tgid();
    let ssl_ctx = unsafe { SSL_CTX_MAP.get(&id) }.ok_or(-EACCES)?;
    unsafe { SSL_CTX_MAP.remove(&id) }.or(Err(-EACCES))?;

    let fd = get_fd_from_ssl(ssl_ctx.ssl)?;

    info!(
        &ctx,
        "write: ssl={}, buf={}, num={}, retval={}, fd={}",
        ssl_ctx.ssl,
        ssl_ctx.buf,
        ssl_ctx.num,
        retval,
        fd
    );

    Ok(0)
}

// int SSL_read(SSL *ssl, void *buf, int num);
fn try_enter_openssl_read(ctx: ProbeContext) -> Result<i32, i32> {
    let ssl: usize = ctx.arg(0).ok_or(-EINVAL)?;
    let buf: usize = ctx.arg(1).ok_or(-EINVAL)?;
    let num: i32 = ctx.arg(2).ok_or(-EINVAL)?;

    let id = bpf_get_current_pid_tgid();
    let ssl_ctx = SSLCtx { ssl, buf, num };
    unsafe { SSL_CTX_MAP.insert(&id, &ssl_ctx, 0) }.or(Err(-ENOMEM))?;
    Ok(0)
}

// int SSL_read(SSL *ssl, void *buf, int num);
fn try_exit_openssl_read(ctx: ProbeContext) -> Result<i32, i32> {
    let id = bpf_get_current_pid_tgid();

    let ssl_ctx = unsafe { SSL_CTX_MAP.get(&id) }.ok_or(-EACCES)?;
    unsafe { SSL_CTX_MAP.remove(&id) }.or(Err(-EACCES))?;

    let retval: i32 = ctx.ret().ok_or(-EINVAL)?;
    if retval > 0 {
        let fd = get_fd_from_ssl(ssl_ctx.ssl)?;

        info!(
            &ctx,
            "read: ssl={}, buf={}, num={}, retval={}, fd={}",
            ssl_ctx.ssl,
            ssl_ctx.buf,
            ssl_ctx.num,
            retval,
            fd
        );
    }

    Ok(0)
}

#[uprobe(name = "uprobe_enter_openssl_write")]
pub fn uprobe_enter_openssl_write(ctx: ProbeContext) -> i32 {
    match try_enter_openssl_write(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[uretprobe(name = "uprobe_exit_openssl_write")]
pub fn uprobe_exit_openssl_write(ctx: ProbeContext) -> i32 {
    match try_exit_openssl_write(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[uprobe(name = "uprobe_enter_openssl_read")]
pub fn uprobe_enter_openssl_read(ctx: ProbeContext) -> i32 {
    match try_enter_openssl_read(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[uretprobe(name = "uprobe_exit_openssl_read")]
pub fn uprobe_exit_openssl_read(ctx: ProbeContext) -> i32 {
    match try_exit_openssl_read(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}
