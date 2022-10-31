use aya::{
    programs::{ProgramError, UProbe},
    Bpf,
};

use object::{Object, ObjectSymbol};
use std::{fs, io};
use thiserror::Error;

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

pub(super) fn load_and_attach(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let target = "/path/to/go/elf";
    let symbol = "runtime.casgstatus";
    let offset = resolve_symbol(&target, symbol).unwrap();

    let fn_name = "golang_runtime_casgstatus";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(None, offset - 0x400000, target, None)?;
    return Ok(());
}
