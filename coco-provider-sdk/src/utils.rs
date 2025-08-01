use libc::uid_t;
use rand::RngCore;

/// Generates 64 bytes of random data
/// Always guaranted to return something (ie, unwrap() can be safely called)
pub fn generate_random_data() -> [u8; 64] {
    let mut data = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

/// Generates a random u32 number.
pub fn generate_random_number() -> u32 {
    rand::thread_rng().next_u32()
}

pub fn get_current_uid() -> uid_t {
    unsafe { libc::getuid() }
}
