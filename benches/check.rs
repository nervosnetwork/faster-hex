use criterion::{black_box, criterion_group, criterion_main, Criterion};
use faster_hex::hex_check_fallback;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use faster_hex::hex_check_sse;

fn bench(c: &mut Criterion) {
    let s1 = "Bf9E2d38aceDeeCbbAfccc4B4B7AE";
    let s2 = "ed136fFDdCcC1DbaFE8CB6Df1AdDBAea44aCcC17b0DbC2741F9CeEeaFbE7A51D";
    let s3 = " \u{0} 𐀀G\u{0}𐀀 GG\u{0}𐀀G\u{0}Gࠀ\u{0} 𐀀   \u{0}:\u{0}\u{0}gࠀG  G::GG::g𐀀G𐀀\u{0}\u{0}¡𐀀ࠀ\u{0}:GGG Gg𐀀 :\u{0}:gG ¡";
    let s4 = "ed136fFDdCcC1DbaFE8CB6Df1AdDBAea44aCcC17b0DbC2741F9CeEeaFbE7A51D\u{0} 𐀀G\u{0}𐀀 GG\u{0}𐀀G\u{0}Gࠀ\u{0} 𐀀   \u{0}:\u{0}\u{0}gࠀG  G::GG::g𐀀G𐀀\u{0}\u{0}¡𐀀ࠀ\u{0}:GGG Gg𐀀 :\u{0}:gG ¡";

    c.bench_function("bench_check_fallback", move |b| {
        b.iter(|| {
            let ret1 = hex_check_fallback(s1.as_bytes());
            black_box(ret1);
            let ret2 = hex_check_fallback(s2.as_bytes());
            black_box(ret2);
            let ret3 = hex_check_fallback(s3.as_bytes());
            black_box(ret3);
            let ret4 = hex_check_fallback(s4.as_bytes());
            black_box(ret4);
        })
    });

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("sse4.1") {
            c.bench_function("bench_check_sse", move |b| {
                b.iter(|| {
                    let ret1 = unsafe { hex_check_sse(s1.as_bytes()) };
                    black_box(ret1);
                    let ret2 = unsafe { hex_check_sse(s2.as_bytes()) };
                    black_box(ret2);
                    let ret3 = unsafe { hex_check_sse(s3.as_bytes()) };
                    black_box(ret3);
                    let ret4 = unsafe { hex_check_sse(s4.as_bytes()) };
                    black_box(ret4);
                })
            });
        }
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
