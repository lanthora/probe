use aya_bpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use crate::golang::get_logical_goid;

#[repr(C, packed(1))]
struct Rw_Ctx {
    fd: i32,
    buf: usize,
    count: u64,
}

#[map]
static mut RW_CTX_MAP: HashMap<u64, Rw_Ctx> = HashMap::with_max_entries(1024, 0);

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
unsafe fn try_sys_enter_read(ctx: TracePointContext) -> Result<i32, i32> {
    let fd: i32 = ctx.read_at(16).or(Err(-crate::EINVAL))?;
    let buf: usize = ctx.read_at(24).or(Err(-crate::EINVAL))?;
    let count: u64 = ctx.read_at(32).or(Err(-crate::EINVAL))?;

    let id = bpf_get_current_pid_tgid();
    let rw_ctx = Rw_Ctx { fd, buf, count };
    RW_CTX_MAP.insert(&id, &rw_ctx, 0).or(Err(-crate::ENOMEM))?;

    Ok(0)
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
unsafe fn try_sys_exit_read(ctx: TracePointContext) -> Result<i32, i32> {
    let ret: i32 = ctx.read_at(16).or(Err(-crate::EINVAL))?;
    let id = bpf_get_current_pid_tgid();
    let rw_ctx = RW_CTX_MAP.get(&id).ok_or(-crate::EACCES)?;
    RW_CTX_MAP.remove(&id).or(Err(-crate::EACCES))?;

    // 由于没有进行协议过滤,会出现很多预期外的包,简单的通过包大小进行过滤
    if ret > 1 {
        // 必须通过协议过滤后才能开始获取业务逻辑相关协程号
        let goid = get_logical_goid()?;
        info!(&ctx, "read: goid={}, fd={}, ret={}", goid, rw_ctx.fd, ret);
    }

    Ok(0)
}

#[tracepoint(name = "sys_enter_read")]
pub fn sys_enter_read(ctx: TracePointContext) -> i32 {
    unsafe {
        match try_sys_enter_read(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

#[tracepoint(name = "sys_exit_read")]
pub fn sys_exit_read(ctx: TracePointContext) -> i32 {
    unsafe {
        match try_sys_exit_read(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}
