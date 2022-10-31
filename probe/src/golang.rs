use anyhow::Ok;
use aya::{programs::UProbe, Bpf};
use object::{Object, ObjectSymbol};
use std::{fs, io};
use thiserror::Error;

const SEGMENT_START: u64 = 0x400000;

#[derive(Debug, Clone)]
struct DoubleError;

#[derive(Error, Debug)]
enum ResolveSymbolError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("error parsing ELF")]
    Object(#[from] object::Error),

    #[error("unknown symbol `{0}`")]
    Unknown(String),
}

fn resolve_symbol(path: &str, symbol: &str) -> Result<u64, ResolveSymbolError> {
    let data = fs::read(path)?;
    let obj = object::read::File::parse(&*data)?;

    obj.symbols()
        .chain(obj.symbols())
        .find(|sym| sym.name().map(|name| name == symbol).unwrap_or(false))
        .map(|s| s.address())
        .ok_or_else(|| ResolveSymbolError::Unknown(symbol.to_string()))
}

pub(super) fn load_and_attach(bpf: &mut Bpf, opt: &mut crate::Opt) -> Result<(), anyhow::Error> {
    let pid = match opt.pid {
        Some(v) => v,
        None => return Ok(()),
    };

    let symbol = "runtime.casgstatus";
    let target = format!("/proc/{}/exe", pid);
    let offset = resolve_symbol(&target, symbol)?;

    let fn_name = "golang_runtime_casgstatus";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(None, offset - SEGMENT_START, target, None)?;
    return Ok(());
}
