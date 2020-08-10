pub fn panic_if_one(v: u32) -> u32 {
    if v == 1 {
        panic!("oops");
    } else {
        v
    }
}
