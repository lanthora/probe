use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, LruHashMap},
    programs::ProbeContext,
};

#[repr(C, packed(1))]
struct GoKey {
    tgid: u32,
    goid: u64,
}

// TODO: 验证在执行 newproc 时,是否发生 M->P 映射切换
// 如果不发生,可以直接进行线程号与协程号的映射
#[map]
static mut PID_TGID_CALLERID_MAP: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

// 线程号到协程号的映射,可以在线程执行过程中获取协程号
#[map]
static mut PID_GOID_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(1024, 0);

// 特定进程内协程ID到祖先协程ID的映射,将协程号向前映射为有业务意义的协程号
#[map]
static mut GOID_ANCESTOR_MAP: LruHashMap<GoKey, u64> = LruHashMap::with_max_entries(1024, 0);

// 特定进程内协程ID到读写时间戳的映射,作为寻找祖先的终止条件
#[map]
static mut GOID_RW_TS_MAP: LruHashMap<GoKey, u64> = LruHashMap::with_max_entries(1024, 0);

unsafe fn is_final_ancestor(tgid: u32, goid: u64, now: u64) -> bool {
    // 5 seconds
    const TIMEOUT: u64 = 5000000000;

    let key = GoKey {
        tgid: tgid,
        goid: goid,
    };
    if let Some(ts) = GOID_RW_TS_MAP.get(&key) {
        return now - *ts < TIMEOUT;
    } else {
        return false;
    };
}

#[inline(always)]
pub unsafe fn get_logical_goid() -> Result<u64, i32> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = bpf_ktime_get_ns();
    let curid = get_current_goid()?;
    let mut ancestor = curid;

    for _ in 0..10 {
        // 成功找到最终祖先,优化查询后返回祖先,可以插入失败
        if is_final_ancestor(tgid, ancestor, now) {
            return Ok(ancestor);
        }
        let key = GoKey {
            tgid: tgid,
            goid: ancestor,
        };
        // 继续向前寻找祖先,直到没有祖先
        if let Some(newancestor) = GOID_ANCESTOR_MAP.get(&key) {
            ancestor = *newancestor;
            continue;
        } else {
            break;
        }
    }
    let key = GoKey {
        tgid: tgid,
        goid: curid,
    };
    GOID_RW_TS_MAP
        .insert(&key, &now, 0)
        .or(Err(-crate::ENOMEM))?;

    Ok(curid)
}

unsafe fn get_goid_from_g(g: usize) -> Result<u64, i32> {
    const GOID_RUNTIME_G_OFFSET: usize = 152;
    let g = (g + GOID_RUNTIME_G_OFFSET) as *const u64;
    bpf_probe_read(g).or(Err(-crate::ENOMEM))
}

pub unsafe fn get_current_goid() -> Result<u64, i32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    PID_GOID_MAP
        .get(&pid)
        .map(|goid| *goid)
        .ok_or(-crate::EACCES)
}

// func casgstatus(gp *g, oldval, newval uint32)
unsafe fn try_enter_golang_runtime_casgstatus(ctx: ProbeContext) -> Result<i32, i32> {
    let newval: u32 = (*ctx.regs).rcx as u32;
    let gp: usize = (*ctx.regs).rax as usize;
    let goid: u64 = get_goid_from_g(gp)?;

    let pid = bpf_get_current_pid_tgid() as u32;

    const G_STATUS_RUNNING: u32 = 2;
    if newval == G_STATUS_RUNNING {
        PID_GOID_MAP
            .insert(&pid, &goid, 0)
            .or(Err(-crate::ENOMEM))?;
    }
    Ok(0)
}

// func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
unsafe fn try_enter_golang_runtime_newproc1(ctx: ProbeContext) -> Result<i32, i32> {
    let callergp: usize = (*ctx.regs).rbx as usize;
    let callerid = get_goid_from_g(callergp)?;
    let id = bpf_get_current_pid_tgid();
    PID_TGID_CALLERID_MAP
        .insert(&id, &callerid, 0)
        .or(Err(-crate::ENOMEM))?;
    Ok(0)
}

// func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
unsafe fn try_exit_golang_runtime_newproc1(ctx: ProbeContext) -> Result<i32, i32> {
    let id = bpf_get_current_pid_tgid();
    let newgp: usize = (*ctx.regs).rax as usize;
    let newid = get_goid_from_g(newgp)?;
    let callerid = PID_TGID_CALLERID_MAP.get(&id).ok_or(-crate::EACCES)?;
    PID_TGID_CALLERID_MAP.remove(&id).or(Err(-crate::EACCES))?;

    let tgid = (id >> 32) as u32;
    let key = GoKey {
        tgid: tgid,
        goid: newid,
    };
    GOID_ANCESTOR_MAP
        .insert(&key, callerid, 0)
        .or(Err(-crate::ENOMEM))?;

    Ok(0)
}

#[uprobe(name = "enter_golang_runtime_casgstatus")]
pub fn enter_golang_runtime_casgstatus(ctx: ProbeContext) -> i32 {
    unsafe {
        match try_enter_golang_runtime_casgstatus(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

#[uprobe(name = "enter_golang_runtime_newproc1")]
pub fn enter_golang_runtime_newproc1(ctx: ProbeContext) -> i32 {
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
pub fn exit_golang_runtime_newproc1(ctx: ProbeContext) -> i32 {
    unsafe {
        match try_exit_golang_runtime_newproc1(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}
