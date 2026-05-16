mod tff;

use std::error::Error;

use crate::tff::read_tff;
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
    Info {
        file: String,
    },
}

fn main() {
    let args = CmdArgs::parse();

    let result = match args.command {
        Commands::Info { file } => info(file)
    };

    match result {
        Ok(_) => println!("Successful"),
        Err(e) => println!("Error: {}", e),
    }

    //match read_tff() {
    //    Ok(f) => println!("Ok: {}", f),
    //    Err(e) => println!("Err: {:?}", e),
    //}
}

fn info(file: String) -> Result<(), Box<dyn Error>> {
    let tff = read_tff(&file)?;
    println!("{}", tff);
    Ok(())
}

//fn write_tff(tff: TffFile) -> Result<(), Box<dyn Error>> {
//    let mut f = File::create("firm.dec.tff")?;
//    f.write_all(b"\x89TFF");
//    f.write_all(b"\x02\x00\x00\x00");
//    f.write_all(b"\x00\x00\x00\x00");
//    f.write_all(&tff.data);
//    Ok(())
//}
