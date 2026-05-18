use binread::{BinRead, BinReaderExt};
use std::{
    error::Error,
    fmt::Display,
    fs::File,
    io::{Cursor, Write},
    path::Path,
};

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

#[derive(BinRead, Debug)]
#[br(import(len: u32))]
#[repr(u32)]
pub enum TffRecordType {
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
            TffRecordType::ProductStrings { unknown: _ } => write!(f, "Product Strings (TODO)")?,
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
pub enum ImageTypeSubprint {
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

pub fn read_records(data: &[u8]) -> Result<Vec<TffRecord>, Box<dyn Error>> {
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

pub fn dump_record(i: usize, outdir: &Path, record: &TffRecord) -> Result<(), Box<dyn Error>> {
    match &record.record_type {
        TffRecordType::FirmwareDataPhoenix {
            start_address,
            data,
        } => {
            let out = outdir.join(format!("{:02}_firm_phoenix_{:06X}.bin", i, start_address));
            let mut outfile = File::create(out)?;
            outfile.write_all(&data)?;
        }

        TffRecordType::FirmwareDataSamurai { data } => {
            let out = outdir.join(format!("{:02}_firm_samurai.bin", i));
            let mut outfile = File::create(out)?;
            outfile.write_all(&data)?;
        }

        TffRecordType::FirmwareDataHydra {
            id,
            hash_len: _,
            hash: _,
            data,
        } => {
            let out = outdir.join(format!("{:02}_firm_hydra_{:06X}.bin", i, id));
            let mut outfile = File::create(out)?;
            outfile.write_all(&data)?;
        }

        TffRecordType::FirmwareDataSubprint { image_type, data } => {
            let out = outdir.join(format!("{:02}_firm_subprint_{:?}.bin", i, image_type));
            let mut outfile = File::create(out)?;
            outfile.write_all(&data)?;
        }

        TffRecordType::FirmwareSignature { signature } => {
            let out = outdir.join(format!("{:02}_signature.bin", i));
            let mut outfile = File::create(out)?;
            outfile.write_all(&signature)?;
        }

        TffRecordType::CapabilityData { unknown } => {
            let out = outdir.join(format!("{:02}_capability_data.xml.gz", i));
            let mut outfile = File::create(out)?;
            outfile.write_all(&unknown)?;
        }

        TffRecordType::EncodedUpdateHeader { main_header } => {
            let out = outdir.join(format!("{:02}_header.bin", i));
            let mut outfile = File::create(out)?;
            outfile.write_all(&main_header)?;
        }

        TffRecordType::EncodedUpdateHeaders { unknown } => {
            let out = outdir.join(format!("{:02}_headers.bin", i));
            let mut outfile = File::create(out)?;
            outfile.write_all(&unknown)?;
        }

        TffRecordType::PcmAudio { unknown } => {
            let out = outdir.join(format!("{:02}_pcm_audio.bin", i));
            let mut outfile = File::create(out)?;
            outfile.write_all(&unknown)?;
        }

        _ => {}
    }

    Ok(())
}
