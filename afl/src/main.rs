use afl::fuzz;
#[path = "../../fuzz/common.rs"]
mod common;

fn main() {
    fuzz!(|data: &[u8]| {
        common::exercise(data);
    });
}
