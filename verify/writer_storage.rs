use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering::Relaxed};

const TEXT: usize = 2*4096+2;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static FIXED: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static SYSTEM: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static LAST: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);
struct Monitor;
#[global_allocator]
static ALLOCATOR: Monitor = Monitor;

// The timed program has one thread. For the one live string allocation, always call
// System.alloc/dealloc. Experimental cases substitute an exclusive, aligned range
// in the caller's preallocated arena only for the lifetime of that string.
unsafe impl GlobalAlloc for Monitor {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let original = unsafe { System.alloc(layout) };
        if original.is_null() || layout.size()!=TEXT || layout.align()!=1 || !ACTIVE.load(Relaxed) {
            return original;
        }
        if !SYSTEM.swap(original,Relaxed).is_null() { std::process::abort(); }
        LAST.store(original as usize, Relaxed);
        ALLOCS.fetch_add(1,Relaxed);
        let fixed=FIXED.load(Relaxed);
        if fixed.is_null() { original } else { fixed }
    }
    unsafe fn dealloc(&self, p:*mut u8, layout:Layout) {
        if layout.size()==TEXT && layout.align()==1 && ACTIVE.load(Relaxed) {
            let original=SYSTEM.swap(ptr::null_mut(),Relaxed);
            let fixed=FIXED.load(Relaxed);
            if original.is_null() || p!=if fixed.is_null(){original}else{fixed} {
                std::process::abort();
            }
            FREES.fetch_add(1,Relaxed);
            unsafe { System.dealloc(original,layout) };
        } else {
            unsafe { System.dealloc(p,layout) };
        }
    }
}
fn one_write(bytes:&[u8], output:&mut Vec<u8>, slot:*mut u8) -> Duration {
    FIXED.store(slot,Relaxed);
    ACTIVE.store(true,Relaxed);
    let start=Instant::now();
    common_json_writer(black_box(bytes),output);
    let elapsed=start.elapsed();
    ACTIVE.store(false,Relaxed);
    FIXED.store(ptr::null_mut(),Relaxed);
    elapsed
}

fn run<T: AsRef<[u8]>>(
    left: fn(&[u8])->T, right: fn(&[u8])->T, input:&[u8], expected:&[u8], count:usize, cycles:usize,
) {
    let mut output=Vec::with_capacity(input.len());
    let reference=serde_json::to_vec(&Output{bytes:expected}).unwrap();
    let mut arena=vec![0xa5_u8; TEXT+8192];
    let arena_start=arena.as_mut_ptr();
    let aligned=arena_start.align_offset(4096);
    assert!(aligned+4095+TEXT<=arena.len());
    let readers=[left,right,left];
    let output_ptr=output.as_ptr();
    let mut expected_total=0usize;
    let mut natural=[0;2];
    for (i,read) in [left,right].into_iter().enumerate() {
        let mut histogram=[0usize;4096];
        for _ in 0..96 {
            let decoded=read(black_box(input));
            assert_eq!(decoded.as_ref(),expected);
            one_write(black_box(expected),&mut output,ptr::null_mut());
            black_box(decoded);
            histogram[LAST.load(Relaxed)&4095]+=1;
            expected_total+=1;
        }
        natural[i]=histogram.iter().enumerate().max_by_key(|e|e.1).unwrap().0;
        assert_eq!(output,reference);
    }
    let mut locations=vec![None,Some(natural[0]),Some(natural[1]),Some(0),Some(16),Some(32),Some(48),Some((output_ptr as usize)&4095)];
    let mut unique=Vec::new();
    locations.retain(|pos| if unique.contains(pos){false}else{unique.push(*pos);true});
    println!("meta {} {} {} {} {}",natural[0],natural[1],output_ptr as usize&4095,expected.as_ptr() as usize&4095,
             locations.iter().map(|v|v.map_or_else(||"natural".to_string(),|x|x.to_string())).collect::<Vec<_>>().join(","));
    let mut rng=as_seed(input);
    let mut hists=vec![[0usize;256];locations.len()*3];
    let mut order:Vec<usize>=(0..locations.len()*3).collect();
    let mut row=vec![0.0;order.len()];
    for turn in 0..=cycles {
        for j in (1..order.len()).rev() {
            rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;
            order.swap(j,rng as usize%(j+1));
        }
        row.fill(0.);
        for &i in order.iter().chain(order.iter().rev()) {
            let read=black_box(readers[i%3]);
            // The same address is loaned to both readers' writer; the three holding
            // buffers (source bytes, final JSON, private scratch arena) stay live.
            let slot=locations[i/3].map_or(ptr::null_mut(),|o| unsafe{arena_start.add(aligned+o)});
            let mut total=Duration::ZERO;
            for _ in 0..count {
                let decoded=read(black_box(input));
                total+=one_write(black_box(expected),&mut output,slot);
                black_box(&decoded);
                hists[i][(LAST.load(Relaxed)&4095)/16]+=1;
            }
            row[i]+=total.as_nanos() as f64 / (count as f64*2.);
            expected_total+=count;
            if let Some(o)=locations[i/3] {
                let payload=&reference[b"{\"bytes\":\"".len()..reference.len()-2];
                assert_eq!(payload.len(),TEXT);
                assert_eq!(&arena[aligned+o..aligned+o+TEXT],payload);
            }
        }
        assert_eq!(output,reference);
        assert_eq!(output.as_ptr(),output_ptr);
        assert_eq!(ALLOCS.load(Relaxed),expected_total);
        assert_eq!(FREES.load(Relaxed),expected_total);
        assert!(SYSTEM.load(Relaxed).is_null());
        if turn>0 { println!("row {}",row.iter().map(|v|format!("{v:.5}")).collect::<Vec<_>>().join(" ")); }
    }
    for (i,h) in hists.iter().enumerate() {
        let mut nonzero:Vec<_>=h.iter().enumerate().filter(|entry|*entry.1>0).collect();
        nonzero.sort_by_key(|entry|std::cmp::Reverse(*entry.1));
        println!("hist {i} {}",nonzero.iter().take(4).map(|(offset,n)|format!("{}={n}",offset*16)).collect::<Vec<_>>().join(","));
    }
    println!("allocs {expected_total}");
}
