fn main() {
    #[cfg(all(feature = "alloc", feature = "heapless"))]
    compile_error!("Features `alloc` and `heapless` work with different implementations of String and are mutually exclusive");
}
