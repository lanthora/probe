use aya_bpf::programs::TracePointContext;

pub fn fd_to_socket(_ctx: &TracePointContext, _fd: i32) -> Result<usize, i32> {
    // TODO: 返回 fd 对应的 socket, 如果 fd 对应的不是 socket 返回 Err
    Ok(0)
}
