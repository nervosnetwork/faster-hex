use std::alloc::{GlobalAlloc,Layout,System};
use std::sync::atomic::{AtomicUsize,Ordering::Relaxed};
use serde::Deserialize;
struct Count;
#[global_allocator] static A:Count=Count;
static N:AtomicUsize=AtomicUsize::new(0);
static S:AtomicUsize=AtomicUsize::new(0);
unsafe impl GlobalAlloc for Count {
    unsafe fn alloc(&self,l:Layout)->*mut u8 { N.fetch_add(1,Relaxed);S.fetch_add(l.size(),Relaxed); unsafe{System.alloc(l)} }
    unsafe fn alloc_zeroed(&self,l:Layout)->*mut u8 { N.fetch_add(1,Relaxed);S.fetch_add(l.size(),Relaxed);unsafe{System.alloc_zeroed(l)} }
    unsafe fn realloc(&self,p:*mut u8,l:Layout,s:usize)->*mut u8 { N.fetch_add(1,Relaxed);S.fetch_add(s,Relaxed);unsafe{System.realloc(p,l,s)} }
    unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
}
fn count<T>(f:impl FnOnce()->T) -> (T,usize,usize) {
    N.store(0,Relaxed);S.store(0,Relaxed);
    let res=std::hint::black_box(f());
    (res,N.load(Relaxed),S.load(Relaxed))
}
#[derive(Deserialize)]
struct Fixed<const LEN:usize>{ #[serde(with="faster_hex::array")] bytes:[u8;LEN] }
#[derive(Deserialize)]
struct Grow{ #[serde(with="faster_hex")] bytes:Vec<u8> }
fn compare<const LEN:usize>() {
    let digits="ab".repeat(LEN);let p=format!(r#"{{"bytes":"0x{digits}"}}"#);
    let e=format!(r#"{{"bytes":"\u0030x{digits}"}}"#);
    for kind in ["plain","escaped","reader"] {
        let input=if kind=="escaped"{e.as_bytes()}else{p.as_bytes()};
        let (a,an,asize)=count(|| if kind=="reader"{serde_json::from_reader::<_,Fixed<LEN>>(input)}else{serde_json::from_slice::<Fixed<LEN>>(input)}.unwrap());
        let(v,vn,vsize)=count(|| if kind=="reader"{serde_json::from_reader::<_,Grow>(input)}else{serde_json::from_slice::<Grow>(input)}.unwrap());
        assert_eq!(a.bytes,[0xab;LEN]);assert_eq!(v.bytes,a.bytes);
        println!("{LEN} {kind} array {an} {asize} vec {vn} {vsize}");
    }
}
fn main(){ compare::<32>();compare::<4096>(); }
