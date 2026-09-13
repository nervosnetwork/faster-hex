//! Replay the exact shared harness, with LLVM source coverage instead of an engine.

#[path = "../fuzz/common.rs"]
mod common;

fn main() {
    let mut expected = vec!["scalar"];
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::arch::is_x86_feature_detected!("sse4.1") {
            expected.push("sse41");
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            expected.push("avx2");
        }
        if std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512bw")
        {
            expected.push("avx512");
        }
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        expected.push("neon");
    }
    let actual: Vec<_> = faster_hex::fuzzing::backends().map(|b| b.name()).collect();
    assert_eq!(
        actual, expected,
        "backend detection must not silently skip an ISA"
    );
    for name in actual {
        println!("backend={name}");
    }

    // Empty input must also enter the core; neither engine needs to find magic
    // headers, a valid length/capacity combination or valid text by mutation.
    common::exercise(&[]);
    let mut count = 0;
    for directory in std::env::args_os().skip(1) {
        let mut paths: Vec<_> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.is_file()
                    && !path
                        .file_name()
                        .unwrap()
                        .as_encoded_bytes()
                        .starts_with(b".")
            })
            .collect();
        paths.sort();
        for path in paths {
            common::exercise(&std::fs::read(path).unwrap());
            count += 1;
        }
    }
    assert!(count > 0, "a nonempty minimized corpus must be replayed");
    println!("inputs={count}");
}
