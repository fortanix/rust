// main crate content:
use one::call_with_type;

macro_rules! type_matcher {
    (u64) => { u64 };
}

fn main() {
    let _x: call_with_type!(type_matcher) = 42;
}
