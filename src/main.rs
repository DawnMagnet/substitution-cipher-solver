use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};
use substitution_cipher_solver::ciphey::{decrypt, encrypt, get_input, get_output};
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decrypts the input file
    Decrypt {
        /// Path to the encrypted file
        #[clap(short, long)]
        input: Option<String>,

        /// Path to the decrypted file
        #[clap(short, long)]
        output: Option<String>,
    },
    /// Encrypts the input file
    Encrypt {
        /// Path to the encrypted file
        #[clap(short, long)]
        input: Option<String>,

        /// Path to the decrypted file
        #[clap(short, long)]
        output: Option<String>,
    },
}

fn main() -> io::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Decrypt { input, output } => {
            let mut input_file: Box<dyn Read> = get_input(input);
            let mut output_file: Box<dyn Write> = get_output(output);
            decrypt(&mut input_file, &mut output_file)?;
        }
        Commands::Encrypt { input, output } => {
            let mut input_file: Box<dyn Read> = get_input(input);
            let mut output_file: Box<dyn Write> = get_output(output);
            encrypt(&mut input_file, &mut output_file)?;
        }
    }

    Ok(())
}
