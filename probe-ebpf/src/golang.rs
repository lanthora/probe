use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    macros::{map, uprobe, uretprobe},
    maps::HashMap,
    programs::ProbeContext,
};

use aya_log_ebpf::info;

// TODO: 验证在执行 newproc 时,是否发生 M->P 映射切换
// 如果不发生,可以直接进行线程号与协程号的映射
#[map]
static mut PID_TGID_CALLERID_MAP: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

unsafe fn get_goid_from_g(g: usize) -> u64 {
    const GOID_RUNTIME_G_OFFSET: usize = 152;
    bpf_probe_read((g + GOID_RUNTIME_G_OFFSET) as *const u64).unwrap()
}

// func casgstatus(gp *g, oldval, newval uint32)
unsafe fn try_enter_golang_runtime_casgstatus(ctx: ProbeContext) -> Result<u32, u32> {
    let newval: u32 = (*ctx.regs).rcx as u32;
    let gp: usize = (*ctx.regs).rax as usize;
    let goid: u64 = get_goid_from_g(gp);

    let pid = bpf_get_current_pid_tgid() as u32;

    info!(
        &ctx,
        "casgstatus: pid={}, goid={} newval={}", pid, goid, newval
    );
    Ok(0)
}

// func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
unsafe fn try_enter_golang_runtime_newproc1(ctx: ProbeContext) -> Result<u32, u32> {
    let callergp: usize = (*ctx.regs).rbx as usize;
    let callerid = get_goid_from_g(callergp);
    let id = bpf_get_current_pid_tgid();
    PID_TGID_CALLERID_MAP.insert(&id, &callerid, 0).ok();
    Ok(0)
}

// func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
unsafe fn try_exit_golang_runtime_newproc1(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    if let Some(callerid) = PID_TGID_CALLERID_MAP.get(&id) {
        let newgp: usize = (*ctx.regs).rax as usize;
        let newid = get_goid_from_g(newgp);
        let pid = id as u32;
        info!(
            &ctx,
            "newproc: pid={} callerid={} newid={}", pid, callerid, newid
        );
    }

    Ok(0)
}

#[uprobe(name = "enter_golang_runtime_casgstatus")]
pub fn enter_golang_runtime_casgstatus(ctx: ProbeContext) -> u32 {
    unsafe {
        match try_enter_golang_runtime_casgstatus(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

#[uprobe(name = "enter_golang_runtime_newproc1")]
pub fn enter_golang_runtime_newproc1(ctx: ProbeContext) -> u32 {
    unsafe {
        match try_enter_golang_runtime_newproc1(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

// TODO: 验证 g0 栈是否会扩展
// 不动态扩展栈的情况下,可以直接用 uretprobe
#[uretprobe(name = "exit_golang_runtime_newproc1")]
pub fn exit_golang_runtime_newproc1(ctx: ProbeContext) -> u32 {
    unsafe {
        match try_exit_golang_runtime_newproc1(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}
