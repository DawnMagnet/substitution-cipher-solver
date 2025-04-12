use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};
use substitution_cipher_solver::ciphey::{
    decrypt, encrypt, get_input, get_output, set_max_bad_words_rate, set_max_goodness_level,
};
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
        #[clap(value_parser)]
        input: Option<String>,

        /// Path to the decrypted file
        #[clap(value_parser)]
        output: Option<String>,

        #[arg(long, short, default_value_t = 0.06)]
        badword_percent: f32,

        #[arg(long, short, default_value_t = 2)]
        goodness_level: usize,
    },
    /// Encrypts the input file
    Encrypt {
        /// Path to the encrypted file
        #[clap(value_parser)]
        input: Option<String>,

        /// Path to the decrypted file
        #[clap(value_parser)]
        output: Option<String>,
    },
}

fn main() -> io::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Decrypt {
            input,
            output,
            badword_percent,
            goodness_level,
        } => {
            let mut input_file: Box<dyn Read> = get_input(input);
            let mut output_file: Box<dyn Write> = get_output(output);
            let badword_rate = (badword_percent * 100.0) as usize;
            let goodness_level = *goodness_level;
            set_max_bad_words_rate(badword_rate);
            set_max_goodness_level(goodness_level);

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
