use std::{
    error::Error,
    fs::File,
    io::{Cursor, Read, Write},
};

use binread::{BinRead, BinReaderExt, until_eof};

use aes::Aes256;
use cbc::Decryptor;
use cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;

type Aes256CbcDec = Decryptor<Aes256>;

#[derive(BinRead)]
#[br(magic = b"\x89TFF")]
struct TffFile {
    version: u32,

    encryption: u32,

    #[br(if(encryption > 0 && version == 2))]
    salt_len: u32,

    #[br(if(encryption > 0 && version == 2), count = salt_len)]
    salt: Vec<u8>,

    #[br(parse_with = until_eof)]
    data: Vec<u8>,
}

struct TffFileData {}

fn main() {
    if let Ok(tff) = read_tff() {
        write_tff(tff);
    }
}

fn read_tff() -> Result<TffFile, Box<dyn Error>> {
    let mut f = File::open("firm.tff")?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let mut cursor = Cursor::new(buffer);
    let mut tff: TffFile = cursor.read_ne()?;

    if tff.encryption > 1 {
        let data = decrypt(&mut tff.data, Some(&tff.salt))?;
        tff.data = data.to_vec();
    }

    return Ok(tff);
}

fn write_tff(tff: TffFile) -> Result<(), Box<dyn Error>> {
    let mut f = File::create("firm.dec.tff")?;
    f.write_all(b"\x89TFF");
    f.write_all(b"\x02\x00\x00\x00");
    f.write_all(b"\x00\x00\x00\x00");
    f.write_all(&tff.data);
    Ok(())
}

fn decrypt<'a>(cipher_text: &'a mut [u8], salt: Option<&'a [u8]>) -> Result<&'a [u8], Box<dyn Error>> {
    let password = b"hKie/63L@aF!93Qm";
    let default_salt = b"8Zx0#aX(0$pr<7hN";

    let salt = salt.unwrap_or_else(|| default_salt);
    let derive = pbkdf2_hmac_array::<Sha1, 48>(password, &salt, 1000);

    let key = derive[0..32].as_array().unwrap();
    let iv = derive[32..48].as_array().unwrap();

    let dec = Aes256CbcDec::new(key.into(), iv.into());
    let data = dec.decrypt_padded::<NoPadding>(cipher_text)?;

    Ok(data)
}
