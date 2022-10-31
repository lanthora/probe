use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    macros::uprobe,
    programs::ProbeContext,
};

use aya_log_ebpf::info;

const GOID_RUNTIME_G_OFFSET: usize = 152;

// func casgstatus(gp *g, oldval, newval uint32)
unsafe fn try_golang_runtime_casgstatus(ctx: ProbeContext) -> Result<u32, u32> {
    let newval: u32 = (*ctx.regs).rcx as u32;
    let gp: usize = (*ctx.regs).rax as usize;
    let goid: u64 = bpf_probe_read((gp + GOID_RUNTIME_G_OFFSET) as *const u64).unwrap();

    let pid = bpf_get_current_pid_tgid() as u32;

    info!(
        &ctx,
        "casgstatus: pid={}, goid={} newval={}", pid, goid, newval
    );
    Ok(0)
}

#[uprobe(name = "golang_runtime_casgstatus")]
pub fn golang_runtime_casgstatus(ctx: ProbeContext) -> u32 {
    unsafe {
        match try_golang_runtime_casgstatus(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}
