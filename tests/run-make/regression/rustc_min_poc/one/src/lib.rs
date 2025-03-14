
macro_rules! define_call_with_type {
    // if you replace `ty` with `tt` here, it compiles with the latest nightly
    ($ty: ty) => {
        #[macro_export]
        macro_rules! call_with_type {
            ($m:ident) => { $m! { $ty } }
        }
    };
}

define_call_with_type!(u64);
