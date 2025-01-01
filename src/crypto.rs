use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{anyhow, Result};
use ring::aead::{self};
use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};
use std::io::Cursor;
use std::rc::Rc;
use tracing::{info, trace};

use crate::connection::QuicLevel;
use crate::packet::is_long_header;
use crate::tls::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384};
use crate::utils::write_cursor_bytes_with_pos;

// Constants for QUIC secret lengths
pub(crate) const QUIC_SHA256_SECRET_LENGTH: usize = 32;
// pub(crate) const QUIC_SHA384_SECRET_LENGTH: usize = 48;

// Key lengths for different AEAD algorithms
const QUIC_AES128_KEY_LENGTH: usize = 16;
const QUIC_AES256_KEY_LENGTH: usize = 32;
// const QUIC_CHACHA20_POLY1305_KEY_LENGTH: usize = 32;

// Header protection key lengths
const QUIC_AES128_HP_LENGTH: usize = 16;
const QUIC_AES256_HP_LENGTH: usize = 32;

// QUIC uses a fixed IV length of 12 bytes for both AES-GCM and ChaCha20-Poly1305
const QUIC_IV_LENGTH: usize = 12;

// Common lengths for cryptographic operations
const QUIC_SAMPLE_LENGTH: usize = 16; // Sample size for AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305
const QUIC_HP_MASK_LENGTH: usize = 5; // Header protection mask length
const QUIC_NONCE_LENGTH: usize = 12; // AEAD nonce length
const MAX_PACKET_NUMBER_LENGTH: usize = 4; // Maximum encoded packet number length
pub(crate) const QUIC_TAG_LENGTH: usize = 16; // Authentication tag length for all supported AEAD algorithms

// TLS 1.3 secret derivation labels
const CLIENT_SECRET_LABEL: &[u8] = b"tls13 client in";
const SERVER_SECRET_LABEL: &[u8] = b"tls13 server in";

// QUIC specific HKDF labels
const QUIC_KEY_LABEL: &[u8] = b"tls13 quic key";
const QUIC_IV_LABEL: &[u8] = b"tls13 quic iv";
const QUIC_HP_LABEL: &[u8] = b"tls13 quic hp";

// Initial salt for QUIC version 1 (RFC 9001)
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

// Retry integrity tag parameters (RFC 9001 Section 5.8)
const QUIC_RETRY_SECRET_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const QUIC_RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

#[derive(Default, Debug)]
pub(crate) struct QuicCrypto {
    initial_client: QuicKeys,
    initial_server: QuicKeys,
    handshake_client: QuicKeys,
    handshake_server: QuicKeys,
    application_client: QuicKeys,
    application_server: QuicKeys,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct QuicKeys {
    key: QuicKey,
    iv: QuicIv,
    hp: Option<Rc<QuicHp>>, // TLS key update doesn't change hp
}

#[derive(Debug, Default, Clone)]
struct QuicKey(Vec<u8>);
impl KeyType for QuicKey {
    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Default, Clone)]
struct QuicIv([u8; QUIC_IV_LENGTH]);
impl KeyType for QuicIv {
    fn len(&self) -> usize {
        QUIC_IV_LENGTH
    }
}

#[derive(Debug, Default)]
struct QuicHp(Vec<u8>);
impl KeyType for QuicHp {
    fn len(&self) -> usize {
        self.0.len()
    }
}

struct KeyTypeForOutput {
    length: usize,
}

impl KeyType for KeyTypeForOutput {
    fn len(&self) -> usize {
        self.length
    }
}

pub fn hkdf_expand(prk: &Prk, output: &mut [u8], label: &[u8], content: &[u8]) -> Result<()> {
    let output_len = u16::to_be_bytes(output.len() as u16);
    let label_len = u8::to_be_bytes(label.len() as u8);
    let content_len = u8::to_be_bytes(content.len() as u8);

    let info = &[
        &output_len[..],
        &label_len[..],
        label,
        &content_len[..],
        content,
    ];
    let secret_key_type = KeyTypeForOutput {
        length: output.len(),
    };

    trace!(
        "HKDF expand, prk {:?}, output size {}, label size {}, label {:?}, content size {}",
        prk,
        output.len(),
        label.len(),
        std::str::from_utf8(label),
        content.len()
    );

    // Why is the hkdf::expand call so difficult to use?
    // I spent few hours trying to figure out the meanings of the info argument
    // Of course, I am not familiy with HKDF algorithms
    // https://docs.rs/ring/latest/ring/hkdf/struct.Prk.html#method.expand
    // https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
    prk.expand(info, secret_key_type)
        .map_err(|e| anyhow!("Failed to expand hkdf due to {e}"))?
        .fill(output)
        .map_err(|e| anyhow!("Failed to fill output due to {e}"))?;

    Ok(())
}

fn get_mask_by_aes_ecb(
    key: &[u8],
    sample: &mut [u8],
    mask: &mut [u8; QUIC_HP_MASK_LENGTH],
) -> Result<()> {
    // Note: While AES-ECB is generally insecure for data encryption,
    // it is safely used here as a pseudorandom function for header protection,
    // as specified in RFC 9001 Section 5.4.3.
    // The ring crate doesn't support AES-ECB directly since it focuses on
    // secure cryptographic primitives for general use cases.

    let aes = Aes128::new(key.into());
    aes.encrypt_block(sample.into());
    mask.copy_from_slice(&sample[..5]);

    Ok(())
}

impl QuicCrypto {
    pub(crate) fn create_initial_secrets(&mut self, secret: &[u8]) -> Result<()> {
        // Initialize QUIC initial secrets using HKDF-SHA256 as specified in RFC 9001 Section 5.1-5.2
        let salt = Salt::new(HKDF_SHA256, &QUIC_V1_SALT);
        let initial_prk: Prk = salt.extract(secret);
        trace!("Initial PRK extraction complete, secret: {:x?}", secret);

        // Derive client initial secret
        let mut client_secret = [0u8; QUIC_SHA256_SECRET_LENGTH];
        hkdf_expand(&initial_prk, &mut client_secret, CLIENT_SECRET_LABEL, &[])?;
        let prk_client_initial = Prk::new_less_safe(HKDF_SHA256, &client_secret);
        trace!("Client initial secret derived: {:x?}", client_secret);

        // Derive server initial secret
        let mut server_secret = [0u8; QUIC_SHA256_SECRET_LENGTH];
        hkdf_expand(&initial_prk, &mut server_secret, SERVER_SECRET_LABEL, &[])?;
        let prk_server_initial = Prk::new_less_safe(HKDF_SHA256, &server_secret);
        trace!("Server initial secret derived: {:x?}", server_secret);

        // Create initial encryption keys for both client and server
        self.create_quic_secrets(
            QuicLevel::Initial,
            TLS_AES_128_GCM_SHA256,
            &prk_client_initial,
            &prk_server_initial,
        )?;

        Ok(())
    }

    fn create_quic_secrets(
        &mut self,
        level: QuicLevel,
        cipher: u16,
        client_secret: &Prk,
        server_secret: &Prk,
    ) -> Result<()> {
        // Determine key and HP lengths based on cipher suite
        let (key_length, hp_length) = match cipher {
            TLS_AES_256_GCM_SHA384 => (QUIC_AES256_KEY_LENGTH, QUIC_AES256_HP_LENGTH),
            TLS_AES_128_GCM_SHA256 => (QUIC_AES128_KEY_LENGTH, QUIC_AES128_HP_LENGTH),
            _ => return Err(anyhow!("Unsupported TLS cipher suite: {:x}", cipher)),
        };

        // Derive client keys
        let client_keys = match level {
            QuicLevel::Initial => &mut self.initial_client,
            QuicLevel::Handshake => &mut self.handshake_client,
            QuicLevel::Application => &mut self.application_client,
        };

        // Generate client key, IV, and header protection key
        client_keys.key.0.clear();
        client_keys.key.0.extend(vec![0u8; key_length]);
        hkdf_expand(client_secret, &mut client_keys.key.0, QUIC_KEY_LABEL, &[])?;
        hkdf_expand(client_secret, &mut client_keys.iv.0, QUIC_IV_LABEL, &[])?;

        if level == QuicLevel::Initial || client_keys.hp.is_none() {
            let mut hp_key = vec![0u8; hp_length];
            hkdf_expand(client_secret, &mut hp_key, QUIC_HP_LABEL, &[])?;
            client_keys.hp = Some(Rc::new(QuicHp(hp_key)));
        }

        info!("Generated {:?} client keys", level);

        // Derive server keys using the same process
        let server_keys = match level {
            QuicLevel::Initial => &mut self.initial_server,
            QuicLevel::Handshake => &mut self.handshake_server,
            QuicLevel::Application => &mut self.application_server,
        };

        server_keys.key.0.clear();
        server_keys.key.0.extend(vec![0u8; key_length]);
        hkdf_expand(server_secret, &mut server_keys.key.0, QUIC_KEY_LABEL, &[])?;
        hkdf_expand(server_secret, &mut server_keys.iv.0, QUIC_IV_LABEL, &[])?;

        if level == QuicLevel::Initial || server_keys.hp.is_none() {
            let mut hp_key = vec![0u8; hp_length];
            hkdf_expand(server_secret, &mut hp_key, QUIC_HP_LABEL, &[])?;
            server_keys.hp = Some(Rc::new(QuicHp(hp_key)));
        }

        info!("Generated {:?} server keys", level);

        Ok(())
    }

    pub(crate) fn encrypt_packet(
        &mut self,
        level: QuicLevel,
        cipher: u16,
        plain_text: &[u8],
        aad: &[u8],
        packet_num: u64,
    ) -> Result<Vec<u8>> {
        // Construct AEAD nonce by XORing padded packet number with IV
        let mut nonce = [0u8; QUIC_NONCE_LENGTH];
        let part_nonce: &mut [u8; 8] =
            (&mut nonce[QUIC_NONCE_LENGTH - 8..QUIC_NONCE_LENGTH]).try_into()?;
        *part_nonce = packet_num.to_be_bytes();

        let client_keys = match level {
            QuicLevel::Initial => &mut self.initial_client,
            QuicLevel::Handshake => &mut self.handshake_client,
            QuicLevel::Application => &mut self.application_client,
        };

        nonce
            .iter_mut()
            .zip(client_keys.iv.0.iter())
            .for_each(|(nonce, iv)| {
                *nonce ^= *iv;
            });
        trace!(
            "Now we have computed our nonce {:x?} for encryption, from iv {:x?}, packet number {}",
            nonce,
            client_keys.iv,
            packet_num
        );

        trace!("Encrypted: aad size {}, aad data {:x?}", aad.len(), aad);

        // The input plaintext, P, for the AEAD is the payload of the QUIC packet, as described in [QUIC-TRANSPORT].
        let aead_algo = match cipher {
            TLS_AES_256_GCM_SHA384 => &aead::AES_256_GCM,
            TLS_AES_128_GCM_SHA256 => &aead::AES_128_GCM,
            _ => return Err(anyhow!("Unsupported TLS cipher {:x}", cipher)),
        };
        let plain_text_len = plain_text.len();
        let mut in_out_buffer = Vec::from(plain_text);
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(aead_algo, &client_keys.key.0)
                .map_err(|e| anyhow!("Failed to create sealing key, due to {e}"))?,
        );
        sealing_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut in_out_buffer,
            )
            .map_err(|e| anyhow!("Failed to append tag, due to {e}"))?;

        trace!(
            "Encryption: plaintext size {}, ciphertext size {}, first 30 bytes: {:x?}",
            plain_text_len,
            in_out_buffer.len(),
            &in_out_buffer[..in_out_buffer.len().min(30)]
        );

        Ok(in_out_buffer)
    }

    pub(crate) fn add_header_protection(
        &mut self,
        level: QuicLevel,
        data: &mut [u8],
        pn_offset: u64,
        pn_length: u8,
    ) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2
        // Sample is taken from 4 bytes after packet number field start
        // The sample of ciphertext is taken starting from an offset of 4 bytes after the start of the Packet Number field.
        // That is, in sampling packet ciphertext for header protection, the Packet Number field is assumed to be 4 bytes long
        // (its maximum possible encoded length).
        let mut cursor = Cursor::new(data);
        let mut sample = [0u8; QUIC_SAMPLE_LENGTH];
        sample.copy_from_slice(
            &cursor.get_ref()[pn_offset as usize + 4..pn_offset as usize + 4 + QUIC_SAMPLE_LENGTH],
        );
        trace!(
            "Header protection sample at offset {}: {:x?}",
            pn_offset + 4,
            sample
        );

        let client_keys = match level {
            QuicLevel::Initial => &mut self.initial_client,
            QuicLevel::Handshake => &mut self.handshake_client,
            QuicLevel::Application => &mut self.application_client,
        };

        // Generate header protection mask
        let mut mask = [0u8; QUIC_HP_MASK_LENGTH];
        let hp = client_keys
            .hp
            .as_ref()
            .ok_or_else(|| anyhow!("Missing header protection key for {:?} level", level))?;
        get_mask_by_aes_ecb(&hp.0, &mut sample, &mut mask)?;
        trace!("Generated header protection mask: {:x?}", mask);

        // Apply header protection to first byte (flags)
        let mut flag = cursor.get_ref()[0];
        trace!("Before add header protection, flag {:x?}", flag);
        if is_long_header(flag) {
            flag ^= mask[0] & 0x0f; // Mask bits 0-3 for long header
        } else {
            flag ^= mask[0] & 0x1f; // Mask bits 0-4 for short header
        }
        write_cursor_bytes_with_pos(&mut cursor, 0, &[flag])?;
        trace!("After add header protection, flag {:x?}", flag);

        // Apply header protection to packet number
        let mut pn = [0u8; MAX_PACKET_NUMBER_LENGTH];
        pn.copy_from_slice(
            &cursor.get_ref()[pn_offset as usize..pn_offset as usize + MAX_PACKET_NUMBER_LENGTH],
        );

        // XOR packet number with remaining mask bytes
        pn.iter_mut()
            .take(pn_length as usize)
            .zip(mask[1..].iter())
            .for_each(|(p, m)| *p ^= *m);

        write_cursor_bytes_with_pos(&mut cursor, pn_offset, &pn)?;
        trace!(
            "Applied header protection: PN={:x?}, length={}",
            pn,
            pn_length
        );

        Ok(())
    }

    pub fn decrypt_packet(
        &mut self,
        level: QuicLevel,
        cipher: u16,
        encrypted_text: &[u8],
        aad: &[u8],
        packet_num: u64,
    ) -> Result<Vec<u8>> {
        // Construct AEAD nonce by XORing padded packet number with IV
        // As specified in RFC 9001 Section 5.3:
        // - Packet number is left-padded with zeros to IV size
        // - Final nonce is XOR of padded packet number and IV
        let mut nonce = [0u8; QUIC_NONCE_LENGTH];
        let part_nonce: &mut [u8; 8] =
            (&mut nonce[QUIC_NONCE_LENGTH - 8..QUIC_NONCE_LENGTH]).try_into()?;
        *part_nonce = packet_num.to_be_bytes();

        let server_keys = match level {
            QuicLevel::Initial => &self.initial_server,
            QuicLevel::Handshake => &self.handshake_server,
            QuicLevel::Application => &self.application_server,
        };

        nonce
            .iter_mut()
            .zip(server_keys.iv.0.iter())
            .for_each(|(nonce, iv)| {
                *nonce ^= *iv;
            });
        trace!("Computed AEAD nonce for decryption: {:x?}", nonce);

        trace!("Decryption AAD length: {}, content: {:x?}", aad.len(), aad);

        // Select AEAD algorithm based on cipher suite
        let aead_algo = match cipher {
            TLS_AES_256_GCM_SHA384 => &aead::AES_256_GCM,
            TLS_AES_128_GCM_SHA256 => &aead::AES_128_GCM,
            _ => return Err(anyhow!("Unsupported TLS cipher suite: {:x}", cipher)),
        };

        // Decrypt ciphertext in-place
        let encrypted_text_len = encrypted_text.len();
        let mut in_out_buffer = Vec::from(encrypted_text);
        let opening_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(aead_algo, &server_keys.key.0)
                .map_err(|e| anyhow!("Failed to create decryption key: {e}"))?,
        );
        opening_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut in_out_buffer,
            )
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        trace!(
            "Decryption complete - input length: {}, output length: {}, first 30 bytes: {:x?}",
            encrypted_text_len,
            in_out_buffer.len(),
            &in_out_buffer[..in_out_buffer.len().min(30)]
        );

        // Verify minimum size and remove authentication tag
        if in_out_buffer.len() < QUIC_TAG_LENGTH {
            return Err(anyhow!(
                "Decrypted data too short: {} bytes, minimum required: {}",
                in_out_buffer.len(),
                QUIC_TAG_LENGTH
            ));
        }
        in_out_buffer.truncate(in_out_buffer.len() - QUIC_TAG_LENGTH);

        Ok(in_out_buffer)
    }

    pub fn remove_header_protection(
        &mut self,
        level: QuicLevel,
        cursor: &Cursor<&[u8]>,
        pn_offset: u64,
    ) -> Result<(u8, u32, u8)> {
        // Sample ciphertext for header protection
        // Sample is taken from 4 bytes after the start of packet number field
        let mut sample = [0u8; QUIC_SAMPLE_LENGTH];
        sample.copy_from_slice(
            &cursor.get_ref()[pn_offset as usize + 4..pn_offset as usize + 4 + QUIC_SAMPLE_LENGTH],
        );
        trace!(
            "Header protection sample at offset {}: {:x?}",
            pn_offset + 4,
            sample
        );

        let server_keys = match level {
            QuicLevel::Initial => &mut self.initial_server,
            QuicLevel::Handshake => &mut self.handshake_server,
            QuicLevel::Application => &mut self.application_server,
        };

        // Generate header protection mask using AES-ECB
        let mut mask = [0u8; QUIC_HP_MASK_LENGTH];
        let hp = server_keys
            .hp
            .as_ref()
            .ok_or_else(|| anyhow!("Missing header protection key for {:?} level", level))?;
        get_mask_by_aes_ecb(&hp.0, &mut sample, &mut mask)?;
        trace!("Generated header protection mask: {:x?}", mask);

        // Remove protection from first byte (flags)
        let mut flag = cursor.get_ref()[0];
        trace!("Flag before removing protection: {:x?}", flag);
        if is_long_header(flag) {
            flag ^= mask[0] & 0x0f; // Unmask bits 0-3 for long header
        } else {
            flag ^= mask[0] & 0x1f; // Unmask bits 0-4 for short header
        }
        trace!("Flag after removing protection: {:x?}", flag);

        // Extract and unprotect packet number
        let pn_length = (flag & 0x02) + 1;
        let mut pn_buf = [0u8; MAX_PACKET_NUMBER_LENGTH];
        let start = 4 - pn_length;
        pn_buf[start as usize..].copy_from_slice(
            &cursor.get_ref()[pn_offset as usize..pn_offset as usize + pn_length as usize],
        );

        trace!(
            "Protected packet number: {:x?}, length: {}",
            pn_buf,
            pn_length
        );

        // Unmask packet number bytes
        pn_buf
            .iter_mut()
            .skip(start as usize)
            .zip(mask[1..].iter())
            .for_each(|(p, m)| *p ^= *m);

        let truncated_pn = u32::from_be_bytes(pn_buf);
        trace!(
            "Unprotected packet number: {}, raw bytes: {:x?}",
            truncated_pn,
            pn_buf
        );

        Ok((flag, truncated_pn, pn_length))
    }

    pub(crate) fn validate_retry_packet_tag(aad: &[u8], received_tag: &[u8]) -> Result<bool> {
        // https://www.rfc-editor.org/rfc/rfc9001#section-5.8
        // No need to compute secret key and the nonce, since RFC has already done this for us

        let mut computed_tag = vec![];
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &QUIC_RETRY_SECRET_KEY)
                .map_err(|e| anyhow!("Failed to create retry sealing key: {e}"))?,
        );

        sealing_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(QUIC_RETRY_NONCE),
                aead::Aad::from(aad),
                &mut computed_tag,
            )
            .map_err(|e| anyhow!("Failed to append retry tag: {e}"))?;

        Ok(computed_tag == received_tag)
    }
}
