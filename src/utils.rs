use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

// https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
// Variable-Length Integer Encoding
pub(crate) fn decode_variable_length(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-a.1

    let first_byte = cursor.read_u8()?;
    let length = 1 << (first_byte >> 6);
    let mut res = (first_byte & 0x3f) as u64;

    for _ in 0..(length - 1) {
        res = (res << 8) + cursor.read_u8()? as u64;
    }

    Ok(res)
}

pub(crate) fn get_remain_length(cursor: &mut Cursor<&[u8]>) -> Option<u64> {
    (cursor.get_ref().len() as u64).checked_sub(cursor.position())
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
    modify_first_byte(cursor, 2, 0x40)?;

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
        modify_first_byte(cursor, 2, 0x40)?;
        written = 2;
    } else if len < (1 << 30) {
        // 4-byte encoding
        cursor.write_u32::<BigEndian>(len as u32)?;
        modify_first_byte(cursor, 4, 0x80)?;
        written = 4;
    } else if len < (1 << 62) {
        // 8-byte encoding
        cursor.write_u64::<BigEndian>(len)?;
        modify_first_byte(cursor, 8, 0x90)?;
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
