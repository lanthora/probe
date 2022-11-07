use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read},
    macros::{map, uprobe, uretprobe},
    maps::LruHashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

use crate::{EACCES, ENOMEM};

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct GoKey(u32, u64);

// TODO: 验证在执行 newproc 时,是否发生 M->P 映射切换
// 如果不发生,可以直接进行线程号与协程号的映射
#[map]
static mut PID_TGID_CALLERID_MAP: LruHashMap<u64, u64> = LruHashMap::with_max_entries(1024, 0);

// 线程号到协程号的映射,可以在线程执行过程中获取协程号
#[map]
static mut PID_GOID_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(1024, 0);

// 特定进程内协程ID到祖先协程ID的映射,将协程号向前映射为有业务意义的协程号
#[map]
static mut GOID_ANCESTOR_MAP: LruHashMap<GoKey, u64> = LruHashMap::with_max_entries(1024, 0);

// 特定进程内协程ID到业务相关操作的时间戳的映射,用来判定超时,作为寻找祖先的一个终止条件.
// 此处的业务为协程对 socket 的读写操作
#[map]
static mut GOID_OP_TS_MAP: LruHashMap<GoKey, u64> = LruHashMap::with_max_entries(1024, 0);

fn is_final_ancestor(tgid: u32, goid: u64, now: u64) -> bool {
    // 追溯祖先协程的最大有效时间.应当略大于接收到最初请求到返回最终响应的时间.
    // 目前设置为 3 秒. 如果时间过小,将无法追溯到有效的业务相关的协程.如果时间
    // 过大,可能会追溯到业务协程更靠前的协程.
    // 如果能够确认放入 GOID_RW_TS_MAP 中的数据都是有效的 socket 读写操作,就
    // 可以增加这个值.
    const TIMEOUT: u64 = 3000000000;

    let key = GoKey(tgid, goid);
    if let Some(ts) = unsafe { GOID_OP_TS_MAP.get(&key) } {
        return now < (*ts) + TIMEOUT;
    } else {
        return false;
    }
}

#[inline(always)]
pub fn get_opid() -> Result<u64, i32> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let goid = get_current_goid()?;
    let mut ancestor = goid;

    for _ in 0..10 {
        if is_final_ancestor(tgid, ancestor, ts) {
            // 优化查询,间接祖先设置为直接祖先
            if goid != ancestor {
                let key = GoKey(tgid, goid);
                unsafe { GOID_ANCESTOR_MAP.insert(&key, &ancestor, 0) }.ok();
            }
            return Ok(ancestor);
        }

        // 继续向前寻找祖先,直到没有祖先
        let key = GoKey(tgid, ancestor);
        if let Some(newancestor) = unsafe { GOID_ANCESTOR_MAP.get(&key) } {
            ancestor = *newancestor;
            continue;
        } else {
            break;
        }
    }

    // 没有查找到与业务操作相关的祖先,当前协程是处理服务的第一个协程,为其他协程的祖先.
    let key = GoKey(tgid, goid);
    unsafe { GOID_OP_TS_MAP.insert(&key, &ts, 0) }.or(Err(-ENOMEM))?;

    Ok(goid)
}

fn get_goid_from_g(g: usize) -> Result<u64, i32> {
    const GOID_RUNTIME_G_OFFSET: usize = 152;
    let g = (g + GOID_RUNTIME_G_OFFSET) as *const u64;
    unsafe { bpf_probe_read(g) }.or(Err(-ENOMEM))
}

#[inline(always)]
pub fn get_current_goid() -> Result<u64, i32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    let goid = unsafe { PID_GOID_MAP.get(&pid) };
    goid.map(|v| *v).ok_or(-EACCES)
}

// func casgstatus(gp *g, oldval, newval uint32)
fn try_enter_golang_runtime_casgstatus(ctx: ProbeContext) -> Result<i32, i32> {
    let newval: u32 = unsafe { *ctx.regs }.rcx as u32;
    let gp: usize = unsafe { *ctx.regs }.rax as usize;
    let goid: u64 = get_goid_from_g(gp)?;

    let pid = bpf_get_current_pid_tgid() as u32;

    const G_STATUS_RUNNING: u32 = 2;
    if newval == G_STATUS_RUNNING {
        unsafe { PID_GOID_MAP.insert(&pid, &goid, 0) }.or(Err(-ENOMEM))?;
    }
    Ok(0)
}

// func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
fn try_enter_golang_runtime_newproc1(ctx: ProbeContext) -> Result<i32, i32> {
    let callergp: usize = unsafe { *ctx.regs }.rbx as usize;
    let callerid = get_goid_from_g(callergp)?;
    let id = bpf_get_current_pid_tgid();
    unsafe { PID_TGID_CALLERID_MAP.insert(&id, &callerid, 0) }.or(Err(-ENOMEM))?;
    Ok(0)
}

// func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
fn try_exit_golang_runtime_newproc1(ctx: ProbeContext) -> Result<i32, i32> {
    let id = bpf_get_current_pid_tgid();
    let newgp: usize = unsafe { *ctx.regs }.rax as usize;
    let newid = get_goid_from_g(newgp)?;
    let callerid = unsafe { PID_TGID_CALLERID_MAP.get(&id) }.ok_or(-EACCES)?;

    let tgid = (id >> 32) as u32;
    let key = GoKey(tgid, newid);
    unsafe { GOID_ANCESTOR_MAP.insert(&key, &callerid, 0) }.or(Err(-ENOMEM))?;
    info!(
        &ctx,
        "newproc: tgid={}, callerid={}, newid={}", tgid, callerid, newid
    );
    Ok(0)
}

#[uprobe(name = "enter_golang_runtime_casgstatus")]
pub fn enter_golang_runtime_casgstatus(ctx: ProbeContext) -> i32 {
    match try_enter_golang_runtime_casgstatus(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[uprobe(name = "enter_golang_runtime_newproc1")]
pub fn enter_golang_runtime_newproc1(ctx: ProbeContext) -> i32 {
    match try_enter_golang_runtime_newproc1(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// TODO: 验证 g0 栈是否会扩展
// 不动态扩展栈的情况下,可以直接用 uretprobe
#[uretprobe(name = "exit_golang_runtime_newproc1")]
pub fn exit_golang_runtime_newproc1(ctx: ProbeContext) -> i32 {
    match try_exit_golang_runtime_newproc1(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}
