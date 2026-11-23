
use faster_hex::{hex_check_with_case, CheckCase};
#[test]
fn every_input_in_every_lane_and_case() {
    assert!(std::arch::is_aarch64_feature_detected!("neon"));
    let mut tested = 0;
    for case in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
        for len in [15, 16, 31, 32, 63, 64, 65, 79, 95, 127, 128, 129, 191, 192, 193] {
            let mut text = vec![b'7'; len];
            for pos in 0..len {
                for byte in 0..=u8::MAX {
                    let valid = byte.is_ascii_digit() || match case {
                        CheckCase::Lower => matches!(byte,b'a'..=b'f'),
                        CheckCase::Upper => matches!(byte,b'A'..=b'F'),
                        CheckCase::None => matches!(byte,b'a'..=b'f' | b'A'..=b'F'),
                    };
                    text[pos] = byte;
                    assert_eq!(hex_check_with_case(&text, case), valid, "{case:?} {byte:02x} at {pos}/{len}");
                    tested += 1;
                }
                text[pos] = b'7';
            }
        }
    }
    println!("{tested} byte, policy and position checks passed");
}
