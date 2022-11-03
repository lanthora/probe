#![no_std]
#![no_main]

const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EINVAL: i32 = 22;

mod golang;
mod openssl;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
