mod record;
mod tff;

use std::{error::Error, path::Path};

use crate::tff::{decrypt_tff, dump_records, read_tff};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CmdArgs {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Print info about this tff file
    Info { file: String },

    /// Decrypt a tff and save it as unencrypted
    Decrypt {
        /// The file to decrypt
        infile: String,

        /// If none is given, the output file will be infile.dec.tff
        outfile: Option<String>,
    },

    /// Dumps all data blobs into outdir named
    Dump {
        /// The file to decrypt
        infile: String,

        /// The director to output all blobs to
        outdir: String,
    },
}

fn main() {
    let args = CmdArgs::parse();

    let result = match args.command {
        Commands::Info { file } => info(file),
        Commands::Decrypt { infile, outfile } => decrypt(infile, outfile),
        Commands::Dump { infile, outdir } => dump(infile, outdir),
    };

    match result {
        Ok(_) => {},
        Err(e) => println!("Error: {}", e),
    }
}

fn info(infile: String) -> Result<(), Box<dyn Error>> {
    let tff = read_tff(Path::new(&infile))?;
    println!("{}", tff);
    Ok(())
}

fn decrypt(infile: String, outfile: Option<String>) -> Result<(), Box<dyn Error>> {
    let inpath = Path::new(&infile);

    if let Some(out) = outfile {
        decrypt_tff(&inpath, &Path::new(&out))?;
    } else {
        decrypt_tff(&inpath, inpath.with_extension("dec.tff").as_path())?;
    }

    Ok(())
}

fn dump(infile: String, outdir: String) -> Result<(), Box<dyn Error>> {
    let inpath = Path::new(&infile);
    let outpath = Path::new(&outdir);
    dump_records(&inpath, &outpath)?;
    Ok(())
}
