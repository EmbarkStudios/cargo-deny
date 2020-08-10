pub fn safety_first(v: u32) -> u32 {
    if v != 1 {
        dangerous_dep::panic_if_one(v)
    } else {
        v
    }
}
