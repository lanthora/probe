use aya::{programs::TracePoint, Bpf};

pub(super) fn load_and_attach(bpf: &mut Bpf, _opt: &mut crate::Opt) -> Result<(), anyhow::Error> {
    let program: &mut TracePoint = bpf.program_mut("sys_enter_read").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_read")?;

    let program: &mut TracePoint = bpf.program_mut("sys_exit_read").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_read")?;

    Ok(())
}
