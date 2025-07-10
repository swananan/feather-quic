use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Instant;

// https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
// Variable-Length Integer Encoding
pub(crate) fn decode_variable_length<W>(cursor: &mut W) -> Result<u64>
where
    W: Read,
{
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-a.1

    let first_byte = cursor.read_u8()?;
    let length = 1 << (first_byte >> 6);
    let mut res = (first_byte & 0x3f) as u64;

    for _ in 0..(length - 1) {
        res = (res << 8) + cursor.read_u8()? as u64;
    }

    Ok(res)
}

pub(crate) fn remaining_bytes<W>(source: &mut W) -> Result<u64>
where
    W: Seek,
{
    let current_pos = source.stream_position()?;
    let total_len = source.seek(SeekFrom::End(0))?;
    source.seek(SeekFrom::Start(current_pos))?;
    Ok(total_len.saturating_sub(current_pos))
}

pub(crate) fn get_variable_length(len: u64) -> Result<u8> {
    if len < (1 << 6) {
        Ok(1)
    } else if len < (1 << 14) {
        Ok(2)
    } else if len < (1 << 30) {
        Ok(4)
    } else if len < (1 << 62) {
        Ok(8)
    } else {
        return Err(anyhow!("Length is so big more then 1<<62 {}", len));
    }
}

pub(crate) fn encode_variable_length_force_two_bytes<W>(cursor: &mut W, len: u64) -> Result<u8>
where
    W: Write + Seek + Read,
{
    if len >= 1 << 14 {
        return Err(anyhow!("Can not encode length {} with in two bytes", len));
    }

    cursor.write_u16::<BigEndian>(len as u16)?;
    modify_first_byte(cursor, 2, 0x40 | ((len >> 8) as u8))?;

    Ok(2)
}

pub(crate) fn encode_variable_length<W>(cursor: &mut W, len: u64) -> Result<u8>
where
    W: Write + Seek + Read,
{
    let written;

    if len < (1 << 6) {
        // 1-byte encoding
        cursor.write_u8(len as u8)?;
        written = 1;
    } else if len < (1 << 14) {
        // 2-byte encoding
        cursor.write_u16::<BigEndian>(len as u16)?;
        modify_first_byte(cursor, 2, 0x40 | ((len >> 8) as u8))?;
        written = 2;
    } else if len < (1 << 30) {
        // 4-byte encoding
        cursor.write_u32::<BigEndian>(len as u32)?;
        modify_first_byte(cursor, 4, 0x80 | ((len >> 24) as u8))?;
        written = 4;
    } else if len < (1 << 62) {
        // 8-byte encoding
        cursor.write_u64::<BigEndian>(len)?;
        modify_first_byte(cursor, 8, 0xc0 | ((len >> 56) as u8))?;
        written = 8;
    } else {
        return Err(anyhow!(
            "Length exceeds maximum allowed value (1 << 62): {}",
            len
        ));
    }

    Ok(written)
}

fn modify_first_byte<W>(cursor: &mut W, size: u64, prefix: u8) -> Result<()>
where
    W: Write + Seek + Read,
{
    // Move back to the start of the value
    cursor.seek(SeekFrom::Current(-(size as i64)))?;

    // Read the first byte
    let mut first_byte = [0u8; 1];
    cursor.read_exact(&mut first_byte)?;
    first_byte[0] |= prefix;

    // Write the modified byte back
    cursor.seek(SeekFrom::Current(-1))?;
    cursor.write_all(&first_byte)?;

    // Return to the original position
    cursor.seek(SeekFrom::Current(size as i64 - 1))?;

    Ok(())
}

pub(crate) fn write_cursor_bytes_with_pos<W>(cursor: &mut W, pos: u64, bytes: &[u8]) -> Result<()>
where
    W: Write + Seek,
{
    // Save the current position
    let cur_pos = cursor.stream_position()?;

    // Move to the desired position
    cursor.seek(SeekFrom::Start(pos))?;
    cursor.write_all(bytes)?;

    // Restore the original position
    cursor.seek(SeekFrom::Start(cur_pos))?;

    Ok(())
}

pub(crate) fn format_instant(instant: Instant, current_ts: Instant) -> String {
    if instant == current_ts {
        return "now".to_string();
    }

    let duration = if instant > current_ts {
        instant.duration_since(current_ts)
    } else {
        current_ts.duration_since(instant)
    };

    let ms = duration.as_secs_f64() * 1000.0;
    if instant > current_ts {
        format!("+{ms:.3}ms")
    } else {
        format!("-{ms:.3}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::{Duration, Instant};

    #[test]
    fn test_decode_variable_length() {
        let test_cases = vec![
            (vec![0x25], 0x25),                                           // 1-byte
            (vec![0x40, 0x25], 0x25),                                     // 2-byte
            (vec![0x80, 0x00, 0x00, 0x25], 0x25),                         // 4-byte
            (vec![0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25], 0x25), // 8-byte
        ];

        for (input, expected) in test_cases {
            let mut cursor = Cursor::new(input.as_slice());
            let result = decode_variable_length(&mut cursor).unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_get_remain_length() -> Result<()> {
        let data = vec![1, 2, 3, 4, 5];
        let mut cursor = Cursor::new(data.as_slice());

        assert_eq!(remaining_bytes(&mut cursor)?, 5);

        cursor.set_position(2);
        assert_eq!(remaining_bytes(&mut cursor)?, 3);

        cursor.set_position(5);
        assert_eq!(remaining_bytes(&mut cursor)?, 0);
        Ok(())
    }

    #[test]
    fn test_get_variable_length() {
        assert_eq!(get_variable_length(0x25).unwrap(), 1);
        assert_eq!(get_variable_length(0x3FFF).unwrap(), 2);
        assert_eq!(get_variable_length(0x3FFFFFFF).unwrap(), 4);
        assert_eq!(get_variable_length(0x3FFFFFFFFFFFFFFF).unwrap(), 8);

        // Test error case
        assert!(get_variable_length(1u64 << 62).is_err());
    }

    #[test]
    fn test_encode_variable_length() {
        let test_cases = vec![
            (0x25, 1),               // 1-byte
            (0x3FFF, 2),             // 2-byte
            (0x3FFFFFFF, 4),         // 4-byte
            (0x3FFFFFFFFFFFFFFF, 8), // 8-byte
        ];

        for (input, expected_size) in test_cases {
            let mut cursor = Cursor::new(Vec::new());
            let written = encode_variable_length(&mut cursor, input).unwrap();
            assert_eq!(written, expected_size);

            // Verify decoding
            cursor.set_position(0);
            let decoded = decode_variable_length(&mut cursor).unwrap();
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn test_encode_variable_length_force_two_bytes() {
        let mut cursor = Cursor::new(Vec::new());
        let written = encode_variable_length_force_two_bytes(&mut cursor, 0x25).unwrap();
        assert_eq!(written, 2);

        cursor.set_position(0);
        let decoded = decode_variable_length(&mut cursor).unwrap();
        assert_eq!(decoded, 0x25);

        // Test error case
        let mut cursor = Cursor::new(Vec::new());
        assert!(encode_variable_length_force_two_bytes(&mut cursor, 1u64 << 14).is_err());
    }

    #[test]
    fn test_format_instant() {
        let now = Instant::now();

        // Test "now"
        assert_eq!(format_instant(now, now), "now");

        // Test future
        let future = now + Duration::from_millis(100);
        assert_eq!(format_instant(future, now), "+100.000ms");

        // Test past
        let past = now - Duration::from_millis(100);
        assert_eq!(format_instant(past, now), "-100.000ms");
    }

    #[test]
    fn test_write_cursor_bytes_with_pos() {
        let mut cursor = Cursor::new(vec![0; 10]);

        // Write some bytes at position 2
        write_cursor_bytes_with_pos(&mut cursor, 2, &[1, 2, 3]).unwrap();

        // Verify the write
        let data = cursor.into_inner();
        assert_eq!(&data[2..5], &[1, 2, 3]);
        assert_eq!(&data[0..2], &[0, 0]);
        assert_eq!(&data[5..], &[0, 0, 0, 0, 0]);
    }
}
