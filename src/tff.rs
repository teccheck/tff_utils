use std::{
    error::Error,
    fmt::Display,
    fs::File,
    io::{Cursor, Read, Write},
    path::Path,
};

use aes::Aes256;
use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, WriteBytesExt};
use cbc::Decryptor;
use cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;

const TFF_MAGIC: &[u8; 4] = b"\x89TFF";

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
        for (i, record) in self.records.iter().enumerate() {
            writeln!(f, "{:02} | {}", i, record)?;
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
//#[br(assert(record_checksum(record_type, &data) == crc))]
pub struct TffRecord {
    data_len: u32,

    #[br(args(data_len))]
    record_type: TffRecordType,

    crc: u32,
}

impl Display for TffRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.record_type)?;
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

#[derive(BinRead, Debug)]
#[br(import(len: u32))]
#[repr(u32)]
enum TffRecordType {
    #[br(magic(0u32), assert(len == 0))]
    EndOfFile {} = 0,

    #[br(magic(1u32))]
    FirmwareDataPhoenix {
        start_address: u64,
        #[br(count(len - 8))]
        data: Vec<u8>,
    },

    #[br(magic(2u32), assert(len == 2))]
    PrintPartIndex { print_index: u8, part_index: u8 },

    #[br(magic(3u32))]
    FirmwareVersion {
        #[br(count(len), map(parse_string))]
        version: String,
    },

    #[br(magic(4u32))]
    FirmwareVersionMask {
        #[br(count(len), map(parse_string))]
        mask: String,
    },

    #[br(magic(5u32), assert(len == 7))]
    FirmwareCreationDate {
        day: u8,
        month: u8,
        year: u16,
        hour: u8,
        minute: u8,
        second: u8,
    },

    #[br(magic(6u32), assert(len == 7))]
    CompatabilityId {
        #[br(count = len)]
        data: Vec<u8>,
    },

    #[br(magic(7u32), assert(len == 12))]
    FlasherVersion { major: u32, minor: u32, build: u32 },

    #[br(magic(8u32))]
    FirmwareDataSamurai {
        #[br(count(len))]
        data: Vec<u8>,
    },

    #[br(magic(9u32))]
    ProductString {
        #[br(count(len), map(parse_string))]
        main_product_string: String,
    },

    #[br(magic(10u32))]
    UpdateCommand {
        #[br(count(len), map(parse_string))]
        command: String,
    },
    #[br(magic(11u32))]
    EncodedUpdateHeader {
        #[br(count(len), assert(len == 1024))]
        main_header: Vec<u8>,
    } = 11,

    // TODO (list of strings of len 21, at least one main (first))
    #[br(magic(15u32))]
    ProductStrings {
        #[br(count(len))]
        unknown: Vec<u8>,
    } = 15,

    // TODO (list of u8 arrays of len 1024, at least one main (first))
    #[br(magic(16u32))]
    EncodedUpdateHeaders {
        #[br(count(len))]
        unknown: Vec<u8>,
    },

    // TODO: list of (unkn: i32, len: i32, segm: u8[len])
    #[br(magic(17u32))]
    PcmAudio {
        #[br(count(len))]
        unknown: Vec<u8>,
    },

    #[br(magic = 18u32)]
    FirmwareDataSubprint {
        image_type: ImageTypeSubprint,

        #[br(count(len - 1))]
        data: Vec<u8>,
    },

    #[br(magic(19u32))]
    CapabilityData {
        // This is gzipped data
        #[br(count = len)]
        unknown: Vec<u8>,
    },

    #[br(magic(20u32))]
    FirmwareSignature {
        #[br(count(len))]
        signature: Vec<u8>,
    },

    #[br(magic(21u32))]
    FirmwareDataHydra {
        id: i32,

        hash_len: i32,

        #[br(count(hash_len))]
        hash: Vec<u8>,

        #[br(count(len - hash_len as u32 - 8))]
        data: Vec<u8>,
    } = 21,
}

impl Display for TffRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TffRecordType::EndOfFile {} => write!(f, "End Of File")?,
            TffRecordType::PrintPartIndex {
                print_index,
                part_index,
            } => write!(f, "Print Index: {print_index}, Part Index: {part_index}")?,
            TffRecordType::FirmwareVersion { version } => write!(f, "Firmware Version: {version}")?,
            TffRecordType::FirmwareVersionMask { mask } => {
                write!(f, "Firmware Version Mask: {mask}")?
            }
            TffRecordType::FirmwareCreationDate {
                day,
                month,
                year,
                hour,
                minute,
                second,
            } => write!(
                f,
                "Firmware Creation Date: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                year, month, day, hour, minute, second
            )?,
            TffRecordType::CompatabilityId { data } => write!(f, "Compatability Id: {:X?}", data)?,
            TffRecordType::FlasherVersion {
                major,
                minor,
                build,
            } => write!(f, "Flasher Version: {major}.{minor}.{build}")?,
            TffRecordType::ProductString {
                main_product_string,
            } => write!(f, "Product String: {}", main_product_string)?,
            TffRecordType::UpdateCommand { command } => write!(f, "Update Command: {}", command)?,
            TffRecordType::EncodedUpdateHeader { main_header: _ } => {
                write!(f, "Encoded Update Header (TODO)")?
            }
            TffRecordType::ProductStrings { unknown: _ } => todo!(),
            TffRecordType::EncodedUpdateHeaders { unknown: _ } => {
                write!(f, "Encoded Update Headers (TODO)")?
            }
            TffRecordType::PcmAudio { unknown: _ } => todo!(),
            TffRecordType::CapabilityData { unknown } => {
                write!(f, "Capability Data (Len {})", unknown.len())?
            }
            TffRecordType::FirmwareSignature { signature } => {
                write!(f, "Firmware Signature (Len {})", signature.len())?
            }
            TffRecordType::FirmwareDataPhoenix {
                start_address,
                data,
            } => write!(
                f,
                "Firmware Data Phoenix (Start {:X}, End: {:X}, Len {})",
                start_address,
                *start_address as usize + data.len() - 1,
                data.len()
            )?,
            TffRecordType::FirmwareDataSamurai { data } => {
                write!(f, "Firmware Data Samurai (Len {})", data.len())?
            }
            TffRecordType::FirmwareDataSubprint { image_type, data } => write!(
                f,
                "Firmware Data Subprint (Type {:?}, Len {})",
                image_type,
                data.len()
            )?,
            TffRecordType::FirmwareDataHydra {
                id,
                hash_len: _,
                hash,
                data,
            } => write!(
                f,
                "Firmware Data Hydra (ID {}, Hash {:X?}, Len {})",
                id,
                hash,
                data.len()
            )?,
        }

        Ok(())
    }
}

#[derive(BinRead, Debug)]
#[br(repr(u8))]
#[repr(u8)]
enum ImageTypeSubprint {
    Softdevice = 0,
    Bootloader,
    Application,
}

//fn record_checksum(record_type: TffRecordType, data: &[u8]) -> u32 {
//    let mut vec = vec![0_u8, 0, 0, 0];
//    LittleEndian::write_u32(&mut vec, record_type as u32);
//    vec.extend_from_slice(data);
//    CRC32.checksum(&vec)
//}

// TODO: Needs swion encoding
fn parse_string(data: Vec<u8>) -> String {
    String::from_utf8(data).unwrap()
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

fn aes_decrypt<'a>(
    cipher_text: &'a mut [u8],
    salt: Option<&[u8]>,
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

fn decrypt_data<'a>(data: &'a mut [u8], header: &TffHeader) -> Result<&'a [u8], Box<dyn Error>> {
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
        if matches!(record.record_type, TffRecordType::EndOfFile {}) {
            break;
        }

        records.push(record);
    }

    Ok(records)
}

pub fn read_tff(infile: &Path) -> Result<TffFile, Box<dyn Error>> {
    let mut f = File::open(infile)?;
    let mut file_content = Vec::new();
    f.read_to_end(&mut file_content)?;

    let (header, position) = read_header(&file_content)?;
    let data = decrypt_data(&mut file_content[position as usize..], &header)?;
    let records = read_records(data)?;

    Ok(TffFile { header, records })
}

pub fn decrypt_tff(infile: &Path, outfile: &Path) -> Result<(), Box<dyn Error>> {
    let mut infile = File::open(infile)?;
    let mut file_content = Vec::new();
    infile.read_to_end(&mut file_content)?;

    let (header, position) = read_header(&file_content)?;
    let data = decrypt_data(&mut file_content[position as usize..], &header)?;

    let mut outfile = File::create(outfile)?;
    outfile.write_all(TFF_MAGIC)?;
    outfile.write_u32::<LittleEndian>(2)?;
    outfile.write_u32::<LittleEndian>(TffEncryptionType::Unencrypted as u32)?;
    outfile.write_all(data)?;

    Ok(())
}

pub fn dump_records(infile: &Path, outdir: &Path) -> Result<(), Box<dyn Error>> {
    let tff = read_tff(infile)?;

    for (i, record) in tff.records.iter().enumerate() {
        match &record.record_type {
            TffRecordType::FirmwareDataPhoenix {
                start_address,
                data,
            } => {
                let out = outdir.join(format!("{:02}_firm_{:06X}.bin", i, start_address));
                let mut outfile = File::create(out)?;
                outfile.write_all(&data)?;
            }

            TffRecordType::FirmwareSignature { signature } => {
                let out = outdir.join(format!("{:02}_signature.bin", i));
                let mut outfile = File::create(out)?;
                outfile.write_all(&signature)?;
            }

            TffRecordType::CapabilityData { unknown } => {
                let out = outdir.join(format!("{:02}_capability_data.bin", i));
                let mut outfile = File::create(out)?;
                outfile.write_all(&unknown)?;
            }
            _ => {}
        }
    }

    Ok(())
}
