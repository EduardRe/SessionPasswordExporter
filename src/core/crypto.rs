use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::config::constants::{
    ERROR_INVALID_HEX, ERROR_INVALID_PASSWORD_UTF8, ERROR_TRUNCATED_PASSWORD,
    ERROR_UNSUPPORTED_PASSWORD, ERROR_WRONG_SESSION_KEY, MASTER_PASSWORD_AES_BLOCK_LENGTH,
    MASTER_PASSWORD_EXTERNAL_PREFIX_LENGTH, MASTER_PASSWORD_MAC_LENGTH,
    MASTER_PASSWORD_MODE_1_KEY_LENGTH, MASTER_PASSWORD_MODE_1_SALT_LENGTH,
    MASTER_PASSWORD_MODE_2_KEY_LENGTH, MASTER_PASSWORD_MODE_2_SALT_LENGTH,
    MASTER_PASSWORD_MODE_3_KEY_LENGTH, MASTER_PASSWORD_MODE_3_SALT_LENGTH,
    MASTER_PASSWORD_PBKDF2_ITERATIONS, MASTER_PASSWORD_SCRAMBLE_BLOCK_LENGTH,
    MASTER_PASSWORD_SCRAMBLE_HEADER_LENGTH, MASTER_PASSWORD_VERIFIER_PROOF_LENGTH, PASSWORD_FLAG,
    PASSWORD_HEX_DIGITS, PASSWORD_MAGIC, PASSWORD_VERSION_EXTERNAL, PASSWORD_VERSION_INTERNAL,
    PASSWORD_VERSION_INTERNAL_LONG,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordDecodeError {
    InvalidHex,
    Truncated,
    Unsupported,
    WrongSessionKey,
    InvalidUtf8,
}

#[derive(Clone, Copy)]
struct MasterPasswordMode {
    key_length: usize,
    salt_length: usize,
}

impl MasterPasswordMode {
    const fn verifier_length(self) -> usize {
        self.salt_length * 2 + MASTER_PASSWORD_MAC_LENGTH
    }
}

const MASTER_PASSWORD_MODES: [MasterPasswordMode; 3] = [
    MasterPasswordMode {
        key_length: MASTER_PASSWORD_MODE_1_KEY_LENGTH,
        salt_length: MASTER_PASSWORD_MODE_1_SALT_LENGTH,
    },
    MasterPasswordMode {
        key_length: MASTER_PASSWORD_MODE_2_KEY_LENGTH,
        salt_length: MASTER_PASSWORD_MODE_2_SALT_LENGTH,
    },
    MasterPasswordMode {
        key_length: MASTER_PASSWORD_MODE_3_KEY_LENGTH,
        salt_length: MASTER_PASSWORD_MODE_3_SALT_LENGTH,
    },
];

impl std::fmt::Display for PasswordDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidHex => ERROR_INVALID_HEX,
            Self::Truncated => ERROR_TRUNCATED_PASSWORD,
            Self::Unsupported => ERROR_UNSUPPORTED_PASSWORD,
            Self::WrongSessionKey => ERROR_WRONG_SESSION_KEY,
            Self::InvalidUtf8 => ERROR_INVALID_PASSWORD_UTF8,
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PasswordDecodeError {}

pub fn decrypt_password(
    encrypted_hex: &str,
    session_key: &str,
) -> Result<String, PasswordDecodeError> {
    let encrypted = decode_hex(encrypted_hex)?;
    let mut decoded = encrypted
        .into_iter()
        .map(|byte| !(byte ^ PASSWORD_MAGIC))
        .collect::<Vec<_>>();
    let mut cursor = 0;
    let flag = take_byte(&decoded, &mut cursor)?;

    let length = if flag == PASSWORD_FLAG {
        match take_byte(&decoded, &mut cursor)? {
            PASSWORD_VERSION_INTERNAL => usize::from(take_byte(&decoded, &mut cursor)?),
            PASSWORD_VERSION_INTERNAL_LONG => {
                let high = usize::from(take_byte(&decoded, &mut cursor)?);
                let low = usize::from(take_byte(&decoded, &mut cursor)?);
                (high << 8) | low
            }
            PASSWORD_VERSION_EXTERNAL => return Err(PasswordDecodeError::Unsupported),
            _ => return Err(PasswordDecodeError::Unsupported),
        }
    } else {
        usize::from(flag)
    };

    let shift = usize::from(take_byte(&decoded, &mut cursor)?);
    cursor = cursor
        .checked_add(shift)
        .ok_or(PasswordDecodeError::Truncated)?;
    let end = cursor
        .checked_add(length)
        .ok_or(PasswordDecodeError::Truncated)?;
    let mut password_bytes = decoded
        .get(cursor..end)
        .ok_or(PasswordDecodeError::Truncated)?
        .to_vec();

    if flag == PASSWORD_FLAG {
        let key_bytes = session_key.as_bytes();
        if !password_bytes.starts_with(key_bytes) {
            password_bytes.zeroize();
            decoded.zeroize();
            return Err(PasswordDecodeError::WrongSessionKey);
        }
        password_bytes.drain(..key_bytes.len());
    }

    decoded.zeroize();
    String::from_utf8(password_bytes).map_err(|error| {
        let mut bytes = error.into_bytes();
        bytes.zeroize();
        PasswordDecodeError::InvalidUtf8
    })
}

pub fn is_master_password_encoded(value: &str) -> bool {
    let value = value.trim();
    value.len() >= MASTER_PASSWORD_EXTERNAL_PREFIX_LENGTH
        && value.len().is_multiple_of(2)
        && decode_simple_byte(&value.as_bytes()[..2]) == Some(PASSWORD_FLAG)
        && decode_simple_byte(&value.as_bytes()[2..4]) == Some(PASSWORD_VERSION_EXTERNAL)
}

pub fn decrypt_master_password(
    encoded: &str,
    master_password: &str,
) -> Result<String, PasswordDecodeError> {
    let mut payload = decode_external_password(encoded)?;
    let has_candidate_mode = MASTER_PASSWORD_MODES
        .iter()
        .any(|mode| payload.len() > mode.salt_length + MASTER_PASSWORD_MAC_LENGTH);
    if !has_candidate_mode {
        payload.zeroize();
        return Err(PasswordDecodeError::Truncated);
    }

    for mode in MASTER_PASSWORD_MODES {
        if payload.len() <= mode.salt_length + MASTER_PASSWORD_MAC_LENGTH {
            continue;
        }

        let cipher_end = payload.len() - MASTER_PASSWORD_MAC_LENGTH;
        let salt = &payload[..mode.salt_length];
        let ciphertext = &payload[mode.salt_length..cipher_end];
        let supplied_mac = &payload[cipher_end..];
        let mut derived_key = pbkdf2_sha1(
            master_password.as_bytes(),
            salt,
            MASTER_PASSWORD_PBKDF2_ITERATIONS,
            mode.key_length * 2 + MASTER_PASSWORD_VERIFIER_PROOF_LENGTH,
        );
        let mut expected_mac = hmac_sha1(
            &derived_key[mode.key_length..mode.key_length * 2],
            ciphertext,
        );
        let valid = constant_time_eq(&expected_mac[..MASTER_PASSWORD_MAC_LENGTH], supplied_mac);
        expected_mac.zeroize();
        if !valid {
            derived_key.zeroize();
            continue;
        }

        let mut plaintext = ciphertext.to_vec();
        aes_ctr_xor(&mut plaintext, &derived_key[..mode.key_length]);
        derived_key.zeroize();
        payload.zeroize();

        let result = unscramble_master_password(&mut plaintext);
        plaintext.zeroize();
        return result;
    }

    payload.zeroize();
    Err(PasswordDecodeError::WrongSessionKey)
}

pub fn matches_master_password(encrypted: &str, candidate: &str) -> bool {
    match decrypt_master_password(encrypted, candidate) {
        Ok(mut plaintext) => {
            plaintext.zeroize();
            true
        }
        Err(_) => false,
    }
}

pub fn verify_master_password(password: &str, verifier_hex: &str) -> bool {
    let Ok(mut verifier) = decode_hex(verifier_hex) else {
        return false;
    };
    let Some(mode) = MASTER_PASSWORD_MODES
        .iter()
        .copied()
        .find(|mode| mode.verifier_length() == verifier.len())
    else {
        verifier.zeroize();
        return false;
    };

    let salt = &verifier[..mode.salt_length];
    let dummy = &verifier[mode.salt_length..mode.salt_length * 2];
    let supplied_mac = &verifier[mode.salt_length * 2..];
    let mut derived_key = pbkdf2_sha1(
        password.as_bytes(),
        salt,
        MASTER_PASSWORD_PBKDF2_ITERATIONS,
        mode.key_length * 2 + MASTER_PASSWORD_VERIFIER_PROOF_LENGTH,
    );
    let mut encrypted_dummy = dummy.to_vec();
    aes_ctr_xor(&mut encrypted_dummy, &derived_key[..mode.key_length]);
    let mut expected_mac = hmac_sha1(
        &derived_key[mode.key_length..mode.key_length * 2],
        &encrypted_dummy,
    );
    let valid = constant_time_eq(&expected_mac[..MASTER_PASSWORD_MAC_LENGTH], supplied_mac);

    expected_mac.zeroize();
    encrypted_dummy.zeroize();
    derived_key.zeroize();
    verifier.zeroize();
    valid
}

fn decode_external_password(encoded: &str) -> Result<Vec<u8>, PasswordDecodeError> {
    let encoded = encoded.trim();
    if !encoded.len().is_multiple_of(2) {
        return Err(PasswordDecodeError::InvalidHex);
    }
    if !is_master_password_encoded(encoded) {
        return Err(PasswordDecodeError::Unsupported);
    }
    decode_hex(&encoded[MASTER_PASSWORD_EXTERNAL_PREFIX_LENGTH..])
}

fn decode_simple_byte(pair: &[u8]) -> Option<u8> {
    if pair.len() != 2 {
        return None;
    }
    let high = hex_digit(pair[0])?;
    let low = hex_digit(pair[1])?;
    Some(!(((high << 4) | low) ^ PASSWORD_MAGIC))
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    const SHA1_BLOCK_LENGTH: usize = 64;
    let mut normalized_key = [0_u8; SHA1_BLOCK_LENGTH];
    if key.len() > SHA1_BLOCK_LENGTH {
        normalized_key[..20].copy_from_slice(&Sha1::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = normalized_key.map(|byte| byte ^ 0x36);
    let mut outer_pad = normalized_key.map(|byte| byte ^ 0x5c);
    let mut inner = Sha1::new();
    inner.update(inner_pad);
    inner.update(data);
    let mut inner_hash = inner.finalize().to_vec();

    let mut outer = Sha1::new();
    outer.update(outer_pad);
    outer.update(&inner_hash);
    inner_hash.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    normalized_key.zeroize();
    outer.finalize().to_vec()
}

fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, output_length: usize) -> Vec<u8> {
    let block_count = output_length.div_ceil(20);
    let mut output = Vec::with_capacity(block_count * 20);
    for block_number in 1..=block_count {
        let mut block_input = Vec::with_capacity(salt.len() + 4);
        block_input.extend_from_slice(salt);
        block_input.extend_from_slice(&(block_number as u32).to_be_bytes());
        let mut u = hmac_sha1(password, &block_input);
        block_input.zeroize();
        let mut accumulator = u.clone();
        for _ in 1..iterations {
            let next = hmac_sha1(password, &u);
            u.zeroize();
            u = next;
            for (target, value) in accumulator.iter_mut().zip(&u) {
                *target ^= value;
            }
        }
        output.extend_from_slice(&accumulator);
        u.zeroize();
        accumulator.zeroize();
    }
    output[output_length..].zeroize();
    output.truncate(output_length);
    output
}

fn aes_ctr_xor(data: &mut [u8], key: &[u8]) {
    match key.len() {
        MASTER_PASSWORD_MODE_1_KEY_LENGTH => aes_ctr_xor_with::<Aes128>(data, key),
        MASTER_PASSWORD_MODE_2_KEY_LENGTH => aes_ctr_xor_with::<Aes192>(data, key),
        MASTER_PASSWORD_MODE_3_KEY_LENGTH => aes_ctr_xor_with::<Aes256>(data, key),
        _ => unreachable!("WinSCP AES key length is defined by its encryption mode"),
    }
}

fn aes_ctr_xor_with<C>(data: &mut [u8], key: &[u8])
where
    C: BlockEncrypt + KeyInit,
{
    let cipher = C::new_from_slice(key).expect("WinSCP AES key has fixed length");
    let mut counter = [0_u8; MASTER_PASSWORD_AES_BLOCK_LENGTH];
    let mut offset = 0;
    while offset < data.len() {
        for byte in counter.iter_mut().take(8) {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
        let mut stream = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut stream);
        let count = (data.len() - offset).min(MASTER_PASSWORD_AES_BLOCK_LENGTH);
        for index in 0..count {
            data[offset + index] ^= stream[index];
        }
        stream.fill(0);
        offset += count;
    }
    counter.zeroize();
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn unscramble_master_password(bytes: &mut [u8]) -> Result<String, PasswordDecodeError> {
    let mut reverse_table = [0_u8; 256];
    for (index, scrambled) in WIN_SCP_SCRAMBLE_TABLE.iter().enumerate() {
        reverse_table[usize::from(*scrambled)] = index as u8;
    }

    let mut last = 31_usize;
    for byte in bytes.iter_mut() {
        let mut value = i32::from(reverse_table[usize::from(*byte)]) - 1 - (last % 255) as i32;
        if value <= 0 {
            value += 255;
        }
        *byte = value as u8;
        last = (last + value as usize) % 255 + 1;
    }

    let Some(length_position) = bytes.iter().position(u8::is_ascii_digit) else {
        return Err(PasswordDecodeError::InvalidUtf8);
    };
    if bytes.len().saturating_sub(length_position) < MASTER_PASSWORD_SCRAMBLE_HEADER_LENGTH {
        return Err(PasswordDecodeError::Truncated);
    }
    let digits = &bytes[length_position..length_position + MASTER_PASSWORD_SCRAMBLE_HEADER_LENGTH];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(PasswordDecodeError::InvalidUtf8);
    }
    let password_length = usize::from(digits[0] - b'0')
        + usize::from(digits[1] - b'0') * 10
        + usize::from(digits[2] - b'0') * 100;
    let expected_total = scrambled_password_total_length(password_length);
    if expected_total != bytes.len()
        || bytes
            .len()
            .saturating_sub(length_position + MASTER_PASSWORD_SCRAMBLE_HEADER_LENGTH)
            != password_length
    {
        return Err(PasswordDecodeError::InvalidUtf8);
    }
    String::from_utf8(bytes[length_position + MASTER_PASSWORD_SCRAMBLE_HEADER_LENGTH..].to_vec())
        .map_err(|error| {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            PasswordDecodeError::InvalidUtf8
        })
}

fn scrambled_password_total_length(password_length: usize) -> usize {
    ((password_length + MASTER_PASSWORD_SCRAMBLE_HEADER_LENGTH)
        / MASTER_PASSWORD_SCRAMBLE_BLOCK_LENGTH)
        * MASTER_PASSWORD_SCRAMBLE_BLOCK_LENGTH
        + MASTER_PASSWORD_SCRAMBLE_BLOCK_LENGTH
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub(crate) fn encrypt_test_master_password(password: &str, master_password: &str) -> String {
        encrypt_test_master_password_with_mode(password, master_password, 2)
    }

    pub(crate) fn encrypt_test_master_password_with_mode(
        password: &str,
        master_password: &str,
        mode_index: usize,
    ) -> String {
        let mode = MASTER_PASSWORD_MODES[mode_index];
        let mut scrambled = password.as_bytes().to_vec();
        let total_length = scrambled_password_total_length(scrambled.len());
        let padding = total_length - MASTER_PASSWORD_SCRAMBLE_HEADER_LENGTH - scrambled.len();
        let mut plain = vec![b'~'; padding];
        let length = scrambled.len();
        plain.extend_from_slice(&[
            b'0' + (length % 10) as u8,
            b'0' + ((length / 10) % 10) as u8,
            b'0' + ((length / 100) % 10) as u8,
        ]);
        plain.append(&mut scrambled);
        let mut last = 31_usize;
        for byte in &mut plain {
            last = (last + usize::from(*byte)) % 255 + 1;
            *byte = WIN_SCP_SCRAMBLE_TABLE[last];
        }

        let mut salt = (1_u8..=mode.salt_length as u8).collect::<Vec<_>>();
        let mut key = pbkdf2_sha1(
            master_password.as_bytes(),
            &salt,
            MASTER_PASSWORD_PBKDF2_ITERATIONS,
            mode.key_length * 2 + MASTER_PASSWORD_VERIFIER_PROOF_LENGTH,
        );
        aes_ctr_xor(&mut plain, &key[..mode.key_length]);
        let mut mac = hmac_sha1(&key[mode.key_length..mode.key_length * 2], &plain);
        let mut payload = std::mem::take(&mut salt);
        payload.append(&mut plain);
        payload.extend_from_slice(&mac[..MASTER_PASSWORD_MAC_LENGTH]);
        mac.zeroize();
        key.zeroize();
        let mut result = format!(
            "{}{}",
            encode_simple_byte(PASSWORD_FLAG),
            encode_simple_byte(PASSWORD_VERSION_EXTERNAL)
        );
        result.push_str(&encode_hex(&payload));
        payload.zeroize();
        result
    }

    pub(crate) fn create_test_verifier(master_password: &str) -> String {
        create_test_verifier_with_mode(master_password, 2)
    }

    pub(crate) fn create_test_verifier_with_mode(
        master_password: &str,
        mode_index: usize,
    ) -> String {
        let mode = MASTER_PASSWORD_MODES[mode_index];
        let salt = (1_u8..=mode.salt_length as u8).collect::<Vec<_>>();
        let dummy = (33_u8..33 + mode.salt_length as u8).collect::<Vec<_>>();
        let mut key = pbkdf2_sha1(
            master_password.as_bytes(),
            &salt,
            MASTER_PASSWORD_PBKDF2_ITERATIONS,
            mode.key_length * 2 + MASTER_PASSWORD_VERIFIER_PROOF_LENGTH,
        );
        let mut encrypted_dummy = dummy.clone();
        aes_ctr_xor(&mut encrypted_dummy, &key[..mode.key_length]);
        let mut mac = hmac_sha1(&key[mode.key_length..mode.key_length * 2], &encrypted_dummy);
        let mut verifier = salt;
        verifier.extend_from_slice(&dummy);
        verifier.extend_from_slice(&mac[..MASTER_PASSWORD_MAC_LENGTH]);
        mac.zeroize();
        encrypted_dummy.zeroize();
        key.zeroize();
        encode_hex(&verifier)
    }

    fn encode_simple_byte(value: u8) -> String {
        let encoded = (!value) ^ PASSWORD_MAGIC;
        format!(
            "{}{}",
            &PASSWORD_HEX_DIGITS[usize::from(encoded >> 4)..=usize::from(encoded >> 4)],
            &PASSWORD_HEX_DIGITS[usize::from(encoded & 0x0F)..=usize::from(encoded & 0x0F)]
        )
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02X}")).collect()
    }
}

// The substitution table originates from WinSCP's Cryptography.cpp.
// Its required redistribution notice is preserved in THIRD_PARTY_NOTICES.md.
const WIN_SCP_SCRAMBLE_TABLE: [u8; 256] = [
    0, 223, 235, 233, 240, 185, 88, 102, 22, 130, 27, 53, 79, 125, 66, 201, 90, 71, 51, 60, 134,
    104, 172, 244, 139, 84, 91, 12, 123, 155, 237, 151, 192, 6, 87, 32, 211, 38, 149, 75, 164, 145,
    52, 200, 224, 226, 156, 50, 136, 190, 232, 63, 129, 209, 181, 120, 28, 99, 168, 94, 198, 40,
    238, 112, 55, 217, 124, 62, 227, 30, 36, 242, 208, 138, 174, 231, 26, 54, 214, 148, 37, 157,
    19, 137, 187, 111, 228, 39, 110, 17, 197, 229, 118, 246, 153, 80, 21, 128, 69, 117, 234, 35,
    58, 67, 92, 7, 132, 189, 5, 103, 10, 15, 252, 195, 70, 147, 241, 202, 107, 49, 20, 251, 133,
    76, 204, 73, 203, 135, 184, 78, 194, 183, 1, 121, 109, 11, 143, 144, 171, 161, 48, 205, 245,
    46, 31, 72, 169, 131, 239, 160, 25, 207, 218, 146, 43, 140, 127, 255, 81, 98, 42, 115, 173,
    142, 114, 13, 2, 219, 57, 56, 24, 126, 3, 230, 47, 215, 9, 44, 159, 33, 249, 18, 93, 95, 29,
    113, 220, 89, 97, 182, 248, 64, 68, 34, 4, 82, 74, 196, 213, 165, 179, 250, 108, 254, 59, 14,
    236, 175, 85, 199, 83, 106, 77, 178, 167, 225, 45, 247, 163, 158, 8, 221, 61, 191, 119, 16,
    253, 105, 186, 23, 170, 100, 216, 65, 162, 122, 150, 176, 154, 193, 206, 222, 188, 152, 210,
    243, 96, 41, 86, 180, 101, 177, 166, 141, 212, 116,
];

fn decode_hex(value: &str) -> Result<Vec<u8>, PasswordDecodeError> {
    let value = value.trim();
    if !value.len().is_multiple_of(2) {
        return Err(PasswordDecodeError::InvalidHex);
    }

    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or(PasswordDecodeError::InvalidHex)?;
            let low = hex_digit(pair[1]).ok_or(PasswordDecodeError::InvalidHex)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    let character = char::from(value).to_ascii_uppercase();
    PASSWORD_HEX_DIGITS.find(character).map(|index| index as u8)
}

fn take_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, PasswordDecodeError> {
    let value = bytes
        .get(*cursor)
        .copied()
        .ok_or(PasswordDecodeError::Truncated)?;
    *cursor += 1;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::constants::{PASSWORD_FLAG, PASSWORD_MAGIC, PASSWORD_VERSION_INTERNAL};

    const TEST_SESSION_KEY: &str = "demo@example.comhost.example.test";
    const TEST_PASSWORD: &str = "pässword-123";

    fn encode_simple_password(password: &str, session_key: &str) -> String {
        let mut payload = vec![
            PASSWORD_FLAG,
            PASSWORD_VERSION_INTERNAL,
            (session_key.len() + password.len()) as u8,
            0,
        ];
        payload.extend_from_slice(session_key.as_bytes());
        payload.extend_from_slice(password.as_bytes());

        payload
            .into_iter()
            .map(|byte| {
                let encoded = !(byte) ^ PASSWORD_MAGIC;
                let high = usize::from(encoded >> 4);
                let low = usize::from(encoded & 0x0F);
                format!(
                    "{}{}",
                    &PASSWORD_HEX_DIGITS[high..=high],
                    &PASSWORD_HEX_DIGITS[low..=low]
                )
            })
            .collect()
    }

    #[test]
    fn decrypts_session_password_with_utf8() {
        let encrypted = encode_simple_password(TEST_PASSWORD, TEST_SESSION_KEY);
        assert_eq!(
            decrypt_password(&encrypted, TEST_SESSION_KEY),
            Ok(TEST_PASSWORD.to_owned())
        );
    }

    #[test]
    fn rejects_a_password_for_a_different_session_key() {
        let encrypted = encode_simple_password(TEST_PASSWORD, TEST_SESSION_KEY);
        assert_eq!(
            decrypt_password(&encrypted, "different-userdifferent-host"),
            Err(PasswordDecodeError::WrongSessionKey)
        );
    }

    #[test]
    fn rejects_malformed_hex() {
        assert_eq!(
            decrypt_password("0G", "key"),
            Err(PasswordDecodeError::InvalidHex)
        );
        assert_eq!(
            decrypt_password("0", "key"),
            Err(PasswordDecodeError::InvalidHex)
        );
    }

    #[test]
    fn rejects_truncated_password_data() {
        assert_eq!(
            decrypt_password("", "key"),
            Err(PasswordDecodeError::Truncated)
        );
    }

    #[test]
    fn rejects_external_password_encoding() {
        let mut payload = vec![
            PASSWORD_FLAG,
            crate::config::constants::PASSWORD_VERSION_EXTERNAL,
        ];
        let encrypted = payload
            .drain(..)
            .map(|byte| {
                let encoded = !(byte) ^ PASSWORD_MAGIC;
                let high = usize::from(encoded >> 4);
                let low = usize::from(encoded & 0x0F);
                format!(
                    "{}{}",
                    &PASSWORD_HEX_DIGITS[high..=high],
                    &PASSWORD_HEX_DIGITS[low..=low]
                )
            })
            .collect::<String>();
        assert_eq!(
            decrypt_password(&encrypted, "key"),
            Err(PasswordDecodeError::Unsupported)
        );
    }

    #[test]
    fn derives_keys_with_rfc2898_pbkdf2_hmac_sha1() {
        let derived = pbkdf2_sha1(b"password", b"salt", 1, 20);
        assert_eq!(
            derived,
            [
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
                0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
            ]
        );
    }

    #[test]
    fn uses_winscp_floor_division_for_scrambled_password_length() {
        assert_eq!(scrambled_password_total_length(12), 17);
        assert_eq!(scrambled_password_total_length(13), 17);
        assert_eq!(scrambled_password_total_length(14), 34);
        assert_eq!(scrambled_password_total_length(30), 34);
        assert_eq!(scrambled_password_total_length(31), 51);
    }

    #[test]
    fn decrypts_win_scp_master_password_data_and_rejects_wrong_passwords() {
        let encrypted = tests_support::encrypt_test_master_password("пароль-123", "master-pass");
        assert!(is_master_password_encoded(&encrypted));
        assert_eq!(
            decrypt_master_password(&encrypted, "master-pass"),
            Ok("пароль-123".to_owned())
        );
        assert!(decrypt_master_password(&encrypted, "wrong").is_err());
    }

    #[test]
    fn validates_win_scp_master_password_verifier() {
        let verifier = tests_support::create_test_verifier("master-pass");
        assert!(verify_master_password("master-pass", &verifier));
        assert!(!verify_master_password("wrong", &verifier));
    }

    #[test]
    fn decrypts_passwords_and_validates_verifiers_for_all_winscp_aes_modes() {
        for mode_index in 0..MASTER_PASSWORD_MODES.len() {
            let encrypted = tests_support::encrypt_test_master_password_with_mode(
                "legacy пароль",
                "master-pass",
                mode_index,
            );
            let verifier = tests_support::create_test_verifier_with_mode("master-pass", mode_index);

            assert_eq!(
                decrypt_master_password(&encrypted, "master-pass"),
                Ok("legacy пароль".to_owned()),
                "failed to decrypt with historical AES mode {}",
                mode_index + 1,
            );
            assert!(
                verify_master_password("master-pass", &verifier),
                "failed to verify with historical AES mode {}",
                mode_index + 1,
            );
            assert!(!verify_master_password("wrong", &verifier));
        }
    }
}
