use faster_hex::{hex_validate, hex_decode_append, hex_decode_array_with_case, hex_decode_vec_with_case, hex_decode_with_case, CheckCase, Error};

fn nibble(b: u8, case: CheckCase) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' if case != CheckCase::Upper => Some(b - b'a' + 10),
        b'A'..=b'F' if case != CheckCase::Lower => Some(b - b'A' + 10),
        _ => None,
    }
}

fn check<const N: usize>(text: &[u8], case: CheckCase) {
    let invalid = text.iter().copied().enumerate().find(|&(_, b)| nibble(b, case).is_none());
    if case == CheckCase::None {
        match (invalid, hex_validate(text)) {
            (Some((at, bad)), Err(Error::InvalidChar { index, byte, .. })) => {
                assert_eq!((index, byte), (at, bad));
            }
            (None, Ok(())) => {}
            mismatch => panic!("standalone validation disagrees with the scalar result: {mismatch:?}"),
        }
        if let Some((_, odd)) = text.split_last() {
            assert_eq!(hex_validate(odd), Err(Error::OddLength));
        }
    }
    let mut dst = [0xa5; N];
    let slice = hex_decode_with_case(text, &mut dst, case);
    let owned = hex_decode_vec_with_case(text, case);
    let fixed = hex_decode_array_with_case::<N>(text, case);
    let mut prefix=vec![4, 7, 2];
    if let Some((at,bad)) = invalid {
        for error in [slice.unwrap_err(), owned.unwrap_err(), fixed.unwrap_err()] {
            assert!(matches!(error, Error::InvalidChar { index, byte, .. } if index==at && byte==bad));
        }
        assert_eq!(dst, [0xa5;N]);
        if case==CheckCase::None {
            let error=hex_decode_append(text,&mut prefix).unwrap_err();
            assert!(matches!(error, Error::InvalidChar {index,byte,..} if index==at && byte==bad));
            assert_eq!(prefix,[4,7,2]);
        }
    } else {
        let expect: Vec<_>=text.chunks_exact(2).map(|p|nibble(p[0],case).unwrap()*16+nibble(p[1],case).unwrap()).collect();
        assert_eq!(slice.unwrap(), expect.as_slice());
        assert_eq!(owned.unwrap(),expect);
        assert_eq!(fixed.unwrap().as_slice(),expect.as_slice());
        if case==CheckCase::None {
            assert_eq!(hex_decode_append(text,&mut prefix).unwrap(),expect.as_slice());
            assert_eq!(&prefix[..3], [4,7,2]);
        }
    }
}

fn boundaries<const N: usize>() -> usize {
    let mut checks=0;
    for case in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
        let mut text=vec![b'9';2*N];
        check::<N>(&text,case);
        checks+=1;
        for at in (0..text.len()).filter(|i| *i<5 || i.saturating_add(6)>=2*N || matches!(i%64,0|1|31|32|62|63)) {
            let bad=match case { CheckCase::Lower=>b'F',CheckCase::Upper=>b'f',_=>0xff };
            let later=(at+3).min(text.len()-1);
            text[later]=b'!';
            text[at]=bad;
            check::<N>(&text,case);
            checks+=1;
            text[at]=b'9';
            text[later]=b'9';
        }
    }
    checks
}
fn main(){
    let mut count=0usize;
    let mut text=[b'3';64];
    for case in [CheckCase::None,CheckCase::Lower,CheckCase::Upper] {
        for at in 0..64 {
            for byte in 0..=u8::MAX {
                text[at]=byte;
                check::<32>(&text,case);
                count+=1;
            }
            text[at]=b'3';
        }
    }
    count+=boundaries::<0>()+boundaries::<1>()+boundaries::<31>()+boundaries::<32>()+
           boundaries::<33>()+boundaries::<63>()+boundaries::<64>()+boundaries::<65>()+
           boundaries::<255>()+boundaries::<256>()+boundaries::<1024>()+boundaries::<1025>()+boundaries::<4096>();
    println!("{count} public input/policy combinations passed");
}
