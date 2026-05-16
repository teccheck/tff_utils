use std::{
    error::Error,
    fmt::Display,
    fs::File,
    io::{Cursor, Read},
};

use aes::Aes256;
use binread::{BinRead, BinReaderExt};
use byteorder::{ByteOrder, LittleEndian};
use cbc::Decryptor;
use cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;

const CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::Algorithm {
    width: 32,
    poly: 0x04C11DB7,
    init: 0xFFFFFFFF,
    refin: true,
    refout: true,
    xorout: 0x00,
    check: 0xCBF43926,
    residue: 0x00,
});

type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Debug)]
pub struct TffFile {
    header: TffHeader,
    records: Vec<TffRecord>,
}

impl Display for TffFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "TFF ({})", self.header)?;
        for record in &self.records {
            writeln!(f, "{}", record)?;
        }
        Ok(())
    }
}

#[derive(BinRead, Debug)]
#[br(magic = b"\x89TFF", assert(version <= 2))]
pub struct TffHeader {
    version: u32,

    encryption: TffEncryptionType,

    #[br(if(has_salt(version, encryption)))]
    salt_len: u32,

    #[br(if(has_salt(version, encryption)), count = salt_len)]
    salt: Vec<u8>,
}

impl Display for TffHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ver {}, {:?}", self.version, self.encryption)?;
        Ok(())
    }
}

#[derive(BinRead, Debug)]
#[br(assert(record_checksum(record_type, &data) == crc))]
pub struct TffRecord {
    data_len: u32,

    record_type: TffRecordType,

    #[br(count = data_len)]
    data: Vec<u8>,

    crc: u32,
}

impl Display for TffRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({})", self.record_type, self.data_len)?;
        Ok(())
    }
}

#[derive(BinRead, Copy, Clone, Debug)]
#[br(repr(u32))]
#[repr(u32)]
enum TffEncryptionType {
    Unencrypted = 0,
    Aes256Cbc = 1,
}

#[derive(BinRead, Copy, Clone, Debug)]
#[br(repr(u32))]
#[repr(u32)]
enum TffRecordType {
    EndOfFile = 0,
    FirmwareDataPhoenix,
    PrintPartIndex,
    FirmwareVersion,
    FirmwareVersionMask,
    FirmwareCreationDate,
    CompatabilityId,
    FlasherVersion,
    FirmwareDataSamurai,
    ProductStringMaybe,
    UpdateCommand = 10,
    EncodedUpdateHeaderMaybe = 11,
    ProductString = 15,
    EncodedUpdateHeader,
    PcmAudio,
    FirmwareDataSubprint,
    CapabilityData,
    FirmwareSignature,
    FirmwareDataHydra = 21,
}

fn record_checksum(record_type: TffRecordType, data: &[u8]) -> u32 {
    let mut vec = vec![0_u8, 0, 0, 0];
    LittleEndian::write_u32(&mut vec, record_type as u32);
    vec.extend_from_slice(data);
    CRC32.checksum(&vec)
}

fn has_salt(version: u32, encryption: TffEncryptionType) -> bool {
    is_encrypted(encryption) && version == 2
}

fn is_encrypted(encryption: TffEncryptionType) -> bool {
    !matches!(encryption, TffEncryptionType::Unencrypted)
}

fn read_header(buffer: &[u8]) -> Result<(TffHeader, u64), Box<dyn Error>> {
    let mut cursor = Cursor::new(&buffer);
    let header: TffHeader = cursor.read_ne()?;
    Ok((header, cursor.position()))
}

fn aes_decrypt<'a, 'b>(
    cipher_text: &'a mut [u8],
    salt: Option<&'b [u8]>,
) -> Result<&'a [u8], Box<dyn Error>> {
    let password = b"hKie/63L@aF!93Qm";
    let default_salt = b"8Zx0#aX(0$pr<7hN";

    let derive = pbkdf2_hmac_array::<Sha1, 48>(password, salt.unwrap_or(default_salt), 1000);
    let key = derive[0..32].as_array().unwrap();
    let iv = derive[32..48].as_array().unwrap();

    let dec = Aes256CbcDec::new(key.into(), iv.into());
    let data = dec.decrypt_padded::<NoPadding>(cipher_text)?;

    Ok(data)
}

fn decrypt_data<'a>(data: &'a mut [u8], header: &TffHeader) -> Result<&'a [u8], Box<dyn Error>>  {
    Ok(if is_encrypted(header.encryption) {
        let salt = if has_salt(header.version, header.encryption) {
            Some(header.salt.as_slice())
        } else {
            None
        };

        aes_decrypt(data, salt)?
    } else {
        data
    })
}

fn read_records(data: &[u8]) -> Result<Vec<TffRecord>, Box<dyn Error>> {
    let mut cursor = Cursor::new(data);
    let mut records = Vec::new();

    loop {
        let record: TffRecord = cursor.read_ne()?;
        if matches!(record.record_type, TffRecordType::EndOfFile) {
            break;
        }

        records.push(record);
    }

    Ok(records)
}

pub fn read_tff(path: &str) -> Result<TffFile, Box<dyn Error>> {
    let mut f = File::open(path)?;
    let mut file_content = Vec::new();
    f.read_to_end(&mut file_content)?;

    let (header, position) = read_header(&file_content)?;
    let data = decrypt_data(&mut file_content[position as usize..], &header)?;
    let records = read_records(&data)?;

    Ok(TffFile { header, records })
}
