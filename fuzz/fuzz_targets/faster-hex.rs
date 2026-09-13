#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::exercise(data);
    {
        let alphabet = b"0123456789abcdef";
        let expected: Vec<u8> = data
            .iter()
            .flat_map(|byte| {
                [
                    alphabet[(byte >> 4) as usize],
                    alphabet[(byte & 15) as usize],
                ]
            })
            .collect();
        let view = faster_hex::Hex::new(data);
        // Array convenience must enforce its exact output length even when a
        // short prefix would otherwise be a valid checked slice conversion.
        if let Some(bytes) = data.get(..32) {
            let encoded = &expected[..64];
            assert_eq!(
                faster_hex::hex_decode_array::<32>(encoded)
                    .unwrap()
                    .as_slice(),
                bytes
            );
        }
        let array = faster_hex::hex_decode_array::<32>(data);
        if !data.len().is_multiple_of(2) {
            assert_eq!(array, Err(faster_hex::Error::OddLength));
        } else if data.len() != 64 {
            assert!(
                matches!(array, Err(faster_hex::Error::LengthMismatch { expected: 32, actual, .. }) if actual == data.len() / 2)
            );
        } else {
            let mut output = [0; 32];
            let slice = faster_hex::hex_decode(data, &mut output).map(|bytes| {
                let mut result = [0; 32];
                result.copy_from_slice(bytes);
                result
            });
            assert_eq!(array, slice);
        }
        assert_eq!(format!("{view}").as_bytes(), expected);
        assert_eq!(
            format!("{view:X}").as_bytes(),
            expected.to_ascii_uppercase()
        );
        // Independently assemble sign-aware zero padding, including empty input.
        let width = data.first().copied().unwrap_or(0) as usize;
        let zeros = width.saturating_sub(3 + expected.len());
        let mut padded = String::from("+0x");
        padded.extend(core::iter::repeat_n('0', zeros));
        padded.push_str(core::str::from_utf8(&expected).unwrap());
        assert_eq!(format!("{view:+#0width$x}"), padded);
        #[cfg(feature = "alloc")]
        {
            assert_eq!(faster_hex::hex_decode_vec(&expected).unwrap(), data);
            let mut decoded = vec![0; data.len() / 2];
            let slice = faster_hex::hex_decode(data, &mut decoded).map(|bytes| bytes.to_vec());
            assert_eq!(faster_hex::hex_decode_vec(data), slice);
            assert_eq!(faster_hex::hex_string(data).as_bytes(), expected);
            let mut output = String::with_capacity(data.first().copied().unwrap_or(0) as usize);
            output.push_str("前缀:");
            assert_eq!(
                faster_hex::hex_append(data, &mut output).as_bytes(),
                expected
            );
            assert_eq!(&output.as_bytes()["前缀:".len()..], expected);
            assert!(output.starts_with("前缀:"));
            let upper = expected.to_ascii_uppercase();
            assert_eq!(faster_hex::hex_string_upper(data).as_bytes(), upper);
            assert_eq!(
                faster_hex::hex_append_upper(data, &mut output).as_bytes(),
                upper
            );
            assert!(output.starts_with("前缀:"));
            assert_eq!(
                &output.as_bytes()["前缀:".len().."前缀:".len() + expected.len()],
                expected
            );
        }
        #[cfg(feature = "heapless-08")]
        {
            let result = faster_hex::heapless_08::hex_string::<64>(data);
            if data.len() <= 32 {
                assert_eq!(result.unwrap().as_bytes(), expected);
            } else {
                assert!(matches!(result,
                    Err(faster_hex::Error::OutputTooSmall { required, .. }) if required == data.len() * 2));
            }
        }
    }
});
