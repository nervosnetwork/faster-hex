#[test]
fn selected_prefix_writes_only_visible_digits_at_page_boundaries() {
    use crate::Hex;
    let mut source = Guarded::new();
    let mut result = Guarded::new();
    let mut cases = 0usize;
    for len in (0..=80).chain([127, 128, 129, 511, 512, 513]) {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
        let encoded = hex::encode(&bytes);
        let maximum = encoded.len();
        for end in [false, true] {
            let input = source.slice_mut(len, end);
            input.copy_from_slice(&bytes);
            for count in (0..=maximum + 1).chain([usize::MAX]) {
                let used = count.min(maximum);
                for cap in [used.saturating_sub(1), used, used + 1] {
                    for output_end in [false, true] {
                        let dst = result.slice_mut(cap, output_end);
                        dst.fill(0xcb);
                        let written = Hex::new(input).leading_digits(count).encode_to(dst);
                        if cap < used {
                            assert_eq!(written, Err(Error::OutputTooSmall { required: used }));
                            assert!(dst.iter().all(|&v| v == 0xcb));
                        } else {
                            let text = written.unwrap();
                            assert_eq!(text.as_bytes(), &encoded.as_bytes()[..used]);
                            assert!(dst[used..].iter().all(|&v| v == 0xcb));
                        }
                        cases += 1;
                    }
                }
            }
        }
    }
    println!("{cases} selected prefix outcomes matched guarded source and output");
}
