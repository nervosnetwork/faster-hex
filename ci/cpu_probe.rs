//! Native validation records the CPU that ran, not the runner label alone.
#[cfg(target_arch = "x86_64")]
fn main() {
    let vendor = std::arch::x86_64::__cpuid_count(0, 0);
    let bytes: Vec<_> = [vendor.ebx, vendor.edx, vendor.ecx]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    println!("arch={}", std::env::consts::ARCH);
    println!("vendor={}", String::from_utf8(bytes).unwrap());
    println!("sse41={}", std::arch::is_x86_feature_detected!("sse4.1"));
    println!("avx2={}", std::arch::is_x86_feature_detected!("avx2"));
    println!("avx512f={}", std::arch::is_x86_feature_detected!("avx512f"));
    println!(
        "avx512bw={}",
        std::arch::is_x86_feature_detected!("avx512bw")
    );
    println!(
        "avx512vl={}",
        std::arch::is_x86_feature_detected!("avx512vl")
    );
    println!(
        "avx512vbmi={}",
        std::arch::is_x86_feature_detected!("avx512vbmi")
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("native Intel/AMD validation requires an x86_64 target");
    std::process::exit(1);
}
