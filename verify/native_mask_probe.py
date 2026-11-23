"""Check private x86 mask contracts in a disposable copy of the measured source."""
import argparse, pathlib, shutil, subprocess as sp, tempfile
from textwrap import dedent
p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('role',choices=['direct','cold']);p.add_argument('--target');args=p.parse_args()
base=args.source.resolve()
common=r'''
fn reference_nibble(b: u8, case: CheckCase) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b-b'0'),
        b'a'..=b'f' if case != CheckCase::Upper => Some(b-b'a'+10),
        b'A'..=b'F' if case != CheckCase::Lower => Some(b-b'A'+10),
        _ => None,
    }
}

pub(crate) fn verify_native_masks() {
    use std::convert::TryInto;
    let sse=std::is_x86_feature_detected!("sse4.1");
    let avx2=std::is_x86_feature_detected!("avx2") && sse;
    let avx512=avx2 && std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512bw");
    let mut checked=0usize;
    for case in [CheckCase::None,CheckCase::Lower,CheckCase::Upper] {
        let mut run=|input: &[u8;64]| {
            let expected=input.iter().enumerate().fold(0u64,|bits,(pos,&b)| bits | (u64::from(reference_nibble(b,case).is_none()) << pos));
            BODY
            checked+=1;
        };
        for pos in 0..64 {
            for byte in 0..=255 {
                let mut input=[b'5';64];input[pos]=byte;run(&input);
                input[63-pos]=b'!';run(&input);
            }
        }
        // Cover all lane pairs, including opposite halves and positions 31,32,63.
        for a in 0..64 { for b in a..64 {
            let mut input=[b'4';64];input[a]=0x80;input[b]=0xff;run(&input);
        }}
        for v in 0..1024usize {
            let mut state=(v as u64).wrapping_mul(0xd6e8feb86659fd93);
            let mut input=[b'0';64];
            for (pos,b) in input.iter_mut().enumerate() {
                state=state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let upper=b"0123456789ABCDEF";let lower=b"0123456789abcdef";
                let alphabet=if case==CheckCase::Upper || (case==CheckCase::None && pos%3==0) {upper}else{lower};
                *b=alphabet[(state>>60)as usize];
            }
            run(&input);
        }
    }
    println!("{} inputs; SSE4.1={}, AVX2={}, AVX-512BW={}",checked,sse,avx2,avx512);
}
'''
bodies={'direct':r'''
            for i in 0..2 {
                if (i==0 && !avx2) || (i==1 && !avx512) {continue}
                let mut storage=[0xa5;34];
                let dst=(&mut storage[1..33]).try_into().unwrap();
                let got=if i==0 {unsafe {decode_block_mask_avx2(input,dst,case)}}
                    else {unsafe {decode_block_mask_avx512(input,dst,case)}};
                assert_eq!(got,expected);
                if expected==0 {
                    assert_eq!(storage[0],0xa5);assert_eq!(storage[33],0xa5);
                    for (pair,&v) in input.chunks_exact(2).zip(&storage[1..33]) {
                        assert_eq!(v,reference_nibble(pair[0],case).unwrap()<<4|reference_nibble(pair[1],case).unwrap());
                    }
                } else {assert_eq!(storage,[0xa5;34]);}
            }
''','cold':r'''
            if sse {
                for n in 0..=4 {
                    let data=&input[..n*16];
                    assert_eq!(unsafe {checked_digit_prefix(data.as_chunks::<16>().0,case)},(expected.trailing_zeros() as usize).min(data.len()));
                }
            }
'''}
with tempfile.TemporaryDirectory(prefix='native-hex-mask-') as tmp:
    wd=pathlib.Path(tmp);shutil.copytree(base/'src',wd/'src')
    with (wd/'src/decode/x86.rs').open('a') as f:f.write('\n'+common.replace('BODY',bodies[args.role]).replace('    use std::convert::TryInto;','    use std::convert::TryInto;' if args.role=='direct' else ''))
    with (wd/'src/decode.rs').open('a') as f:f.write('\n#[cfg(any(target_arch="x86",target_arch="x86_64"))]\npub(crate) use self::x86::verify_native_masks;\n')
    with (wd/'src/lib.rs').open('a') as f:f.write('\n/// Exercise the native checker on independent inputs.\npub fn kernel_mask_oracle() {\n #[cfg(any(target_arch="x86",target_arch="x86_64"))] crate::decode::verify_native_masks();\n}\n')
    extra=['--target',args.target] if args.target else []
    lib=wd/'libfaster_hex.rlib'
    sp.run(['rustc','--crate-name','faster_hex','--crate-type','rlib','--edition','2018','-O','--cfg','feature="alloc"','--cfg','feature="std"',*extra,wd/'src/lib.rs','-o',lib],check=True)
    if not args.target:
        driver=wd/'main.rs';driver.write_text('fn main(){faster_hex::kernel_mask_oracle()}')
        sp.run(['rustc','--edition','2021','-O','--extern','faster_hex='+str(lib),driver,'-o',wd/'probe'],check=True)
        sp.run([wd/'probe'],check=True)
