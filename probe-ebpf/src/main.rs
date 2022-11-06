#![no_std]
#![no_main]

mod golang;
mod openssl;
mod socket;
mod syscall;

const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EINVAL: i32 = 22;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
