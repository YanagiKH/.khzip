use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use khzip::{
    create_archive, extract_archive, list_archive, verify_archive, ArchiveFormat, CompressionMode,
    CreateOptions, CustomCompression, UnlockOptions,
};
use std::{env, path::PathBuf, str::FromStr};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "khzip",
    version,
    about = "Secure versioned compressed archives"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Create(CreateCommand),
    Extract(ExtractCommand),
    List(ReadCommand),
    Verify(ReadCommand),
    Formats,
    Doctor,
    DeviceKey {
        #[command(subcommand)]
        command: DeviceKeyCommand,
    },
}

#[derive(Debug, Args)]
struct CreateCommand {
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    #[arg(short, long)]
    output: PathBuf,
    #[arg(
        long,
        help = "khz, khpak, khx, khaz, or khcz; defaults to output extension"
    )]
    format: Option<String>,
    #[arg(long, default_value = "balanced")]
    mode: String,
    #[arg(
        long,
        help = "Prompt for a password without exposing it in process arguments"
    )]
    password: bool,
    #[arg(
        long,
        value_name = "NAME",
        help = "Read password from an environment variable"
    )]
    password_env: Option<String>,
    #[arg(long, default_value_t = 104_857_600)]
    split_size: u64,
    #[arg(long, default_value_t = 9)]
    zstd_level: i32,
    #[arg(long, default_value_t = 7)]
    brotli_quality: u32,
    #[arg(long, default_value_t = 7)]
    lzma_level: u32,
    #[arg(long, default_value_t = 262_144)]
    min_chunk: usize,
    #[arg(long, default_value_t = 1_048_576)]
    avg_chunk: usize,
    #[arg(long, default_value_t = 8_388_608)]
    max_chunk: usize,
}

#[derive(Debug, Args)]
struct ExtractCommand {
    archive: PathBuf,
    #[arg(short, long, default_value = ".")]
    output: PathBuf,
    #[command(flatten)]
    unlock: UnlockArgs,
    #[arg(long)]
    overwrite: bool,
}

#[derive(Debug, Args)]
struct ReadCommand {
    archive: PathBuf,
    #[command(flatten)]
    unlock: UnlockArgs,
}

#[derive(Debug, Args)]
struct UnlockArgs {
    #[arg(long, help = "Prompt for a password")]
    password: bool,
    #[arg(
        long,
        value_name = "NAME",
        help = "Read password from an environment variable"
    )]
    password_env: Option<String>,
}

#[derive(Debug, Subcommand)]
enum DeviceKeyCommand {
    Init {
        #[arg(long)]
        force: bool,
    },
    Path,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Create(command) => {
            let format = match command.format {
                Some(value) => ArchiveFormat::from_str(&value)?,
                None => ArchiveFormat::from_output(&command.output)
                    .context("cannot infer format from output extension")?,
            };
            let mode = CompressionMode::from_str(&command.mode)?;
            let password = read_password(
                command.password,
                command.password_env.as_deref(),
                format.requires_password(),
            )?;
            let summary = create_archive(&CreateOptions {
                inputs: command.inputs,
                output: command.output.clone(),
                format,
                mode,
                password: password.map(|value| value.to_string()),
                custom: CustomCompression {
                    zstd_level: command.zstd_level,
                    brotli_quality: command.brotli_quality,
                    lzma_level: command.lzma_level,
                    min_chunk: command.min_chunk,
                    avg_chunk: command.avg_chunk,
                    max_chunk: command.max_chunk,
                },
                split_size: command.split_size,
            })?;
            println!(
                "created {}: {} files, {} unique chunks, {} original bytes, {} unique bytes",
                command.output.display(),
                summary.files,
                summary.chunks,
                summary.original_bytes,
                summary.unique_bytes
            );
        }
        Command::Extract(command) => {
            let unlock = unlock_options(&command.unlock)?;
            let summary = extract_archive(
                &command.archive,
                &command.output,
                &unlock,
                command.overwrite,
            )?;
            println!(
                "extracted {} files to {}",
                summary.files,
                command.output.display()
            );
        }
        Command::List(command) => {
            let unlock = unlock_options(&command.unlock)?;
            let (summary, files) = list_archive(&command.archive, &unlock)?;
            println!(
                "format: .{} | files: {} | chunks: {} | original bytes: {} | unique bytes: {}",
                summary.format,
                summary.files,
                summary.chunks,
                summary.original_bytes,
                summary.unique_bytes
            );
            for entry in files {
                println!("{:>10}  {}", entry.size, entry.path);
            }
        }
        Command::Verify(command) => {
            let unlock = unlock_options(&command.unlock)?;
            let summary = verify_archive(&command.archive, &unlock)?;
            println!(
                "verified .{} archive: {} files, {} chunks, Merkle root {}",
                summary.format,
                summary.files,
                summary.chunks,
                hex::encode(summary.merkle_root)
            );
        }
        Command::Formats => print_formats(),
        Command::Doctor => doctor()?,
        Command::DeviceKey { command } => match command {
            DeviceKeyCommand::Init { force } => println!(
                "device key initialized at {}",
                khzip::crypto::init_device_key(force)?.display()
            ),
            DeviceKeyCommand::Path => {
                println!("{}", khzip::crypto::device_key_path()?.display());
            }
        },
    }
    Ok(())
}

fn unlock_options(args: &UnlockArgs) -> Result<UnlockOptions> {
    Ok(UnlockOptions {
        password: read_password(args.password, args.password_env.as_deref(), false)?
            .map(|value| value.to_string()),
    })
}

fn read_password(
    prompt: bool,
    env_name: Option<&str>,
    required: bool,
) -> Result<Option<Zeroizing<String>>> {
    if let Some(name) = env_name {
        return Ok(Some(Zeroizing::new(env::var(name).with_context(|| {
            format!("environment variable {name} is not set")
        })?)));
    }
    if prompt || required {
        let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
        anyhow::ensure!(!password.is_empty(), "password cannot be empty");
        return Ok(Some(password));
    }
    Ok(None)
}

fn print_formats() {
    println!(".khz   general-purpose archive; optional password encryption");
    println!(".khpak readable unencrypted asset/package archive");
    println!(".khx   split archive; optional password encryption");
    println!(".khaz  extreme compression plus two authenticated encryption layers");
    println!(".khcz  extreme device-bound archive using the local device key");
}

fn doctor() -> Result<()> {
    println!("khzip {}", env!("CARGO_PKG_VERSION"));
    println!(
        "device key: {}",
        khzip::crypto::device_key_path()?.display()
    );
    println!("unsafe Rust: forbidden");
    println!("container version: 1");
    Ok(())
}
