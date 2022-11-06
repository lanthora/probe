use aya::{programs::UProbe, Bpf};

pub(super) fn load_and_attach(bpf: &mut Bpf, opt: &mut crate::Opt) -> Result<(), anyhow::Error> {
    let pid = opt.pid;
    if pid.is_none() {
        return Ok(());
    }

    let target = "libssl";

    let fn_name = "uprobe_enter_openssl_write";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_write"), 0, target, pid)?;

    let fn_name = "uprobe_exit_openssl_write";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_write"), 0, target, pid)?;

    let fn_name = "uprobe_enter_openssl_read";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_read"), 0, target, pid)?;

    let fn_name = "uprobe_exit_openssl_read";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_read"), 0, target, pid)?;
    return Ok(());
}
