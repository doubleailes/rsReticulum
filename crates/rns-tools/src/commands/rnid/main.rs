//! rnid-rs - identity create/inspect/sign/verify/encrypt/decrypt.
//!
//! Python reference: `RNS/Utilities/rnid.py` from Reticulum 1.2.2.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
#[cfg(feature = "hardware")]
use clap::Subcommand;
use clap::{CommandFactory, Parser};
use rns_identity::destination::{DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_transport::messages::{
    OutboundRequest, TransportMessage, TransportQuery, TransportQueryResponse,
};

#[cfg(feature = "hardware")]
mod hw_commands;

const RETICULUM_COMPAT_VERSION: &str = "1.2.2";
const SIG_EXT: &str = "rsg";
const ENCRYPT_EXT: &str = "rfe";
const CHUNK_SIZE: usize = 16 * 1024 * 1024;
const BLOCK_SIZE: usize = 16;
// Python rnid decrypts fixed 16 MiB ciphertext chunks. Cap plaintext so each
// full encrypted token lands on that boundary after identity overhead + padding.
const PYTHON_COMPAT_PLAINTEXT_CHUNK_SIZE: usize =
    CHUNK_SIZE - rns_identity::identity::IDENTITY_OVERHEAD - BLOCK_SIZE;
const FULL_CHUNK_TOKEN_SIZE: usize =
    CHUNK_SIZE + rns_identity::identity::IDENTITY_OVERHEAD + BLOCK_SIZE;

#[derive(Parser)]
#[command(
    name = "rnid-rs",
    about = "Reticulum Identity & Encryption Utility",
    disable_version_flag = true
)]
struct Args {
    /// Path to alternative Reticulum config directory.
    #[arg(long)]
    config: Option<String>,

    /// Hexadecimal identity/destination hash, or path to an Identity file.
    #[arg(short = 'i', long)]
    identity: Option<String>,

    /// Generate a new Identity and write it to this file.
    #[arg(short = 'g', long)]
    generate: Option<PathBuf>,

    /// Import private Identity data in hex, base32 or base64 format.
    #[arg(short = 'm', long = "import", value_name = "identity_data")]
    import_str: Option<String>,

    /// Export private Identity data in hex, base32 or base64 format.
    #[arg(short = 'x', long)]
    export: bool,

    /// Increase verbosity.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity.
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// Announce a destination based on this Identity.
    #[arg(short = 'a', long)]
    announce: Option<String>,

    /// Show destination hash for aspects based on this Identity.
    #[arg(short = 'H', long = "hash")]
    hash: Option<String>,

    /// Encrypt file.
    #[arg(short = 'e', long)]
    encrypt: Option<PathBuf>,

    /// Decrypt file.
    #[arg(short = 'd', long)]
    decrypt: Option<PathBuf>,

    /// Sign file.
    #[arg(short = 's', long)]
    sign: Option<PathBuf>,

    /// Validate signature.
    #[arg(short = 'V', long = "validate")]
    validate: Option<PathBuf>,

    /// Input file path.
    #[arg(short = 'r', long)]
    read: Option<PathBuf>,

    /// Output file path.
    #[arg(short = 'w', long)]
    write: Option<PathBuf>,

    /// Write output even if it overwrites existing files.
    #[arg(short = 'f', long)]
    force: bool,

    /// Request unknown Identities from the network.
    #[arg(short = 'R', long = "request")]
    request: bool,

    /// Identity request timeout before giving up.
    #[arg(short = 't', value_name = "seconds", default_value_t = rns_transport::constants::PATH_REQUEST_TIMEOUT)]
    timeout: f64,

    /// Print identity info and exit.
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,

    /// Allow displaying private keys.
    #[arg(short = 'P', long = "print-private")]
    print_private: bool,

    /// Use base64-encoded input and output.
    #[arg(short = 'b', long)]
    base64: bool,

    /// Use base32-encoded input and output.
    #[arg(short = 'B', long)]
    base32: bool,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// Parsed for Python CLI parity; Reticulum 1.2.2 does not implement it.
    #[arg(short = 'I', long = "stdin", hide = true)]
    stdin: bool,

    /// Parsed for Python CLI parity; Reticulum 1.2.2 does not implement it.
    #[arg(short = 'O', long = "stdout", hide = true)]
    stdout: bool,
}

#[cfg(feature = "hardware")]
#[derive(Subcommand)]
enum HwCommands {
    Detect,
    Provision {
        #[arg(long)]
        pin: Option<String>,
        #[arg(short, long)]
        nickname: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    List {
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },
    Info {
        hwid: PathBuf,
    },
    Verify {
        hwid: PathBuf,
    },
    Test {
        hwid: PathBuf,
    },
}

#[cfg(feature = "hardware")]
#[derive(Parser)]
#[command(name = "rnid-rs hw")]
struct HwArgs {
    #[command(subcommand)]
    command: HwCommands,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
pub(crate) async fn main() -> ExitCode {
    #[cfg(feature = "hardware")]
    {
        let mut raw = std::env::args_os();
        let _program = raw.next();
        if raw.next().as_deref() == Some(std::ffi::OsStr::new("hw")) {
            let hw_args = HwArgs::parse_from(std::iter::once("rnid-rs hw".into()).chain(raw));
            hw_commands::run(hw_args.command);
            return ExitCode::SUCCESS;
        }
    }

    let args = Args::parse();
    run(args).await
}

async fn run(mut args: Args) -> ExitCode {
    if args.version {
        println!("rnid-rs {RETICULUM_COMPAT_VERSION}");
        return ExitCode::SUCCESS;
    }

    let target_loglevel = 4 + args.verbose as i32 - args.quiet as i32;
    let level = match target_loglevel {
        i32::MIN..=1 => tracing::Level::ERROR,
        2..=3 => tracing::Level::WARN,
        4 => tracing::Level::INFO,
        5 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .try_init();

    let op_count = [
        args.encrypt.is_some(),
        args.decrypt.is_some(),
        args.validate.is_some(),
        args.sign.is_some(),
    ]
    .into_iter()
    .filter(|op| *op)
    .count();
    if op_count > 1 {
        eprintln!(
            "This utility currently only supports one of the encrypt, decrypt, sign or verify operations per invocation"
        );
        return ExitCode::from(1);
    }

    if args.read.is_none() {
        args.read = args
            .encrypt
            .clone()
            .or_else(|| args.decrypt.clone())
            .or_else(|| args.sign.clone());
    }

    if let Some(import_str) = args.import_str.as_deref() {
        return import_identity(&args, import_str);
    }

    if let Some(path) = args.generate.as_ref() {
        return generate_identity(path, args.force);
    }

    let Some(identity_arg) = args.identity.as_deref() else {
        println!("\nNo identity provided, cannot continue\n");
        let mut cmd = Args::command();
        let _ = cmd.print_help();
        println!("\n");
        return ExitCode::from(2);
    };

    let identity = match resolve_identity(identity_arg, &args).await {
        Ok(identity) => identity,
        Err((code, msg)) => {
            eprintln!("{msg}");
            return ExitCode::from(code);
        }
    };

    if let Some(aspects) = args.hash.as_deref() {
        return hash_destination(&identity, aspects);
    }

    if let Some(aspects) = args.announce.as_deref() {
        return announce_destination(&identity, aspects, &args).await;
    }

    if args.print_identity {
        print_identity(&identity, &args);
        return ExitCode::SUCCESS;
    }

    if args.export {
        return export_identity(&identity, &args);
    }

    if args.validate.is_some() {
        return validate_signature(&identity, &args);
    }

    if args.sign.is_some() {
        return sign_file(&identity, &args);
    }

    if args.encrypt.is_some() {
        return encrypt_file(&identity, &args);
    }

    if args.decrypt.is_some() {
        return decrypt_file(&identity, &args);
    }

    ExitCode::SUCCESS
}

fn generate_identity(path: &Path, force: bool) -> ExitCode {
    if let Err(e) = ensure_output_allowed(path, force) {
        eprintln!("{e}");
        return ExitCode::from(3);
    }
    let identity = Identity::new();
    match identity.to_file(path) {
        Ok(()) => {
            println!(
                "New identity {} written to {}",
                hex::encode(identity.hash),
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("An error occurred while saving the generated Identity: {e}");
            ExitCode::from(4)
        }
    }
}

fn import_identity(args: &Args, import_str: &str) -> ExitCode {
    let identity_bytes = match decode_key_text(import_str, args) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Invalid identity data specified for import: {e}");
            return ExitCode::from(41);
        }
    };
    let identity = match Identity::from_private_key(&identity_bytes) {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("Could not create Reticulum identity from specified data: {e}");
            return ExitCode::from(42);
        }
    };

    println!("Identity imported");
    print_identity(&identity, args);

    if let Some(path) = args.write.as_ref() {
        if path.is_file() && !args.force {
            eprintln!("File {} already exists, not overwriting", path.display());
            return ExitCode::from(43);
        }
        if let Err(e) = identity.to_file(path) {
            eprintln!("Error while saving identity to {}", path.display());
            eprintln!("The contained exception was: {e}");
        }
        println!("Wrote imported identity to {}", path.display());
    }

    ExitCode::SUCCESS
}

async fn resolve_identity(identity_arg: &str, args: &Args) -> Result<Identity, (u8, String)> {
    let path = Path::new(identity_arg);
    if path.is_file() {
        // Python rnid calls `RNS.Identity.from_file()`, which returns None
        // for malformed files. The CLI does not check that None before
        // falling through with exit 0, so preserve that compatibility quirk.
        return load_identity_file(path).map_err(|e| (0, e));
    }

    if identity_arg.len() == 32 {
        let hash = parse_hash16(identity_arg)
            .ok_or((7, "Invalid hexadecimal hash provided".to_string()))?;
        match recall_identity_from_python_known_destinations(hash, args) {
            Ok(Some(identity)) => {
                println!("Recalled Identity {}", hex::encode(identity.hash));
                return Ok(identity);
            }
            Ok(None) => {}
            Err(msg) => return Err((7, msg)),
        }
        if !args.request {
            return Err((
                5,
                format!(
                    "Could not recall Identity for {}. You can query the network for unknown Identities with the -R option.",
                    hex::encode(hash)
                ),
            ));
        }
        return request_identity(hash, args).await;
    }

    Err((8, "Specified Identity file not found".to_string()))
}

fn load_identity_file(path: &Path) -> Result<Identity, String> {
    match Identity::from_file(path) {
        Ok(identity) => Ok(identity),
        Err(private_err) => {
            let data = std::fs::read(path).map_err(|_| {
                format!("Could not decode Identity from specified file: {private_err}")
            })?;
            Identity::from_public_key(&data).map_err(|public_err| {
                format!(
                    "Could not decode Identity from specified file: {private_err}; public key: {public_err}"
                )
            })
        }
    }
}

async fn request_identity(hash: [u8; 16], args: &Args) -> Result<Identity, (u8, String)> {
    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let foreground = Arc::new(AtomicBool::new(true));
    let handle =
        rns_runtime::reticulum::init(args.config.as_deref(), None, shutdown.clone(), foreground)
            .await
            .map_err(|e| (1, format!("Failed to initialize Reticulum runtime: {e}")))?;

    handle
        .transport_tx
        .send(TransportMessage::RequestPath {
            destination_hash: hash,
        })
        .await
        .map_err(|_| (1, "Transport closed while requesting path".to_string()))?;

    let timeout = Duration::from_secs_f64(args.timeout.max(0.0));
    let _ = handle.await_path(hash, timeout).await;

    let identity = query_recent_announces_for_hash(&handle, hash).await;
    shutdown.trigger();
    identity.ok_or((6, "Identity request timed out".to_string()))
}

async fn query_recent_announces_for_hash(
    handle: &rns_runtime::reticulum::ReticulumHandle,
    hash: [u8; 16],
) -> Option<Identity> {
    let response = handle
        .query_transport(TransportQuery::GetRecentAnnounces)
        .await?;
    let TransportQueryResponse::Announces(announces) = response else {
        return None;
    };

    for announce in announces {
        let public_key = announce.public_key?;
        if announce.dest_hash == hash {
            return Identity::from_public_key(&public_key).ok();
        }
        let identity_hash = rns_crypto::sha::truncated_hash(&public_key);
        if identity_hash == hash {
            return Identity::from_public_key(&public_key).ok();
        }
    }
    None
}

fn recall_identity_from_python_known_destinations(
    hash: [u8; 16],
    args: &Args,
) -> Result<Option<Identity>, String> {
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    let path = config_dir.join("storage/known_destinations");
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(_) => return Ok(None),
    };
    let mut cursor = std::io::Cursor::new(data);
    let value = match rmpv::decode::read_value(&mut cursor) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let rmpv::Value::Map(entries) = value else {
        return Ok(None);
    };

    for (key, value) in entries {
        let dest_hash = value_bytes(&key).and_then(hash16_from_slice);
        let Some(items) = value.as_array() else {
            continue;
        };
        if items.len() < 3 {
            continue;
        }
        let Some(public_key_vec) = value_bytes(&items[2]) else {
            continue;
        };
        let identity = match Identity::from_public_key(&public_key_vec) {
            Ok(identity) => identity,
            Err(e) if dest_hash == Some(hash) => {
                return Err(format!("Invalid hexadecimal hash provided: {e}"));
            }
            Err(_) => continue,
        };
        if dest_hash == Some(hash) || identity.hash == hash {
            return Ok(Some(identity));
        }
    }
    Ok(None)
}

fn value_bytes(value: &rmpv::Value) -> Option<Vec<u8>> {
    match value {
        rmpv::Value::Binary(bytes) => Some(bytes.clone()),
        rmpv::Value::String(s) => s.as_str().map(|s| s.as_bytes().to_vec()),
        _ => None,
    }
}

fn hash16_from_slice(bytes: Vec<u8>) -> Option<[u8; 16]> {
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn hash_destination(identity: &Identity, aspects: &str) -> ExitCode {
    if aspects.trim().is_empty() {
        eprintln!("Invalid destination aspects specified");
        return ExitCode::from(32);
    }
    let hash = Destination::hash_from_name_and_identity(aspects, Some(&identity.hash));
    println!(
        "The {aspects} destination for this Identity is {}",
        pretty_hash(&hash)
    );
    println!(
        "The full destination specifier is {}.{}",
        aspects,
        hex::encode(identity.hash)
    );
    ExitCode::SUCCESS
}

async fn announce_destination(identity: &Identity, aspects: &str, args: &Args) -> ExitCode {
    if aspects.split('.').count() <= 1 {
        eprintln!("Invalid destination aspects specified");
        return ExitCode::from(32);
    }
    if !identity.has_private_key() {
        let hash = Destination::hash_from_name_and_identity(aspects, Some(&identity.hash));
        println!(
            "The {aspects} destination for this Identity is {}",
            pretty_hash(&hash)
        );
        println!(
            "The full destination specifier is {}.{}",
            aspects,
            hex::encode(identity.hash)
        );
        println!("Cannot announce this destination, since the private key is not held");
        return ExitCode::from(33);
    }

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let foreground = Arc::new(AtomicBool::new(true));
    let handle = match rns_runtime::reticulum::init(
        args.config.as_deref(),
        None,
        shutdown.clone(),
        foreground,
    )
    .await
    {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("Failed to initialize Reticulum runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let mut destination =
        match Destination::new(Some(identity), Direction::In, DestType::Single, aspects) {
            Ok(destination) => destination,
            Err(e) => {
                eprintln!("Could not create destination: {e}");
                shutdown.trigger();
                return ExitCode::from(1);
            }
        };
    println!("Created destination {aspects}");
    println!("Announcing destination {}", pretty_hash(&destination.hash));

    let raw = match destination.announce_packet(identity, None, None, false, None, now_epoch()) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("An error occurred while attempting to send the announce: {e}");
            shutdown.trigger();
            return ExitCode::from(1);
        }
    };
    let dest_hash = destination.hash;
    let _ = handle
        .transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: raw.into(),
            destination_hash: dest_hash,
        }))
        .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    shutdown.trigger();
    ExitCode::SUCCESS
}

fn print_identity(identity: &Identity, args: &Args) {
    println!(
        "Public Key  : {}",
        encode_key_text(&identity.get_public_key(), args)
    );
    if let Some(private_key) = identity.get_private_key() {
        if args.print_private {
            println!("Private Key : {}", encode_key_text(&*private_key, args));
        } else {
            println!("Private Key : Hidden");
        }
    }
}

fn export_identity(identity: &Identity, args: &Args) -> ExitCode {
    let Some(private_key) = identity.get_private_key() else {
        eprintln!("Identity doesn't hold a private key, cannot export");
        return ExitCode::from(50);
    };
    println!(
        "Exported Identity : {}",
        encode_key_text(&*private_key, args)
    );
    ExitCode::SUCCESS
}

fn sign_file(identity: &Identity, args: &Args) -> ExitCode {
    if !identity.has_private_key() {
        eprintln!("Specified Identity does not hold a private key. Cannot sign.");
        return ExitCode::from(14);
    }
    let Some(input_path) = args.read.as_ref() else {
        eprintln!("Signing requested, but no input data specified");
        return ExitCode::from(17);
    };
    let data = match read_input(input_path, args.stdin) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(12);
        }
    };
    let Some(output_path) = args
        .write
        .clone()
        .or_else(|| (!args.stdout).then(|| append_extension(input_path, SIG_EXT)))
    else {
        if !args.stdout {
            eprintln!("Signing requested, but no output specified");
        }
        return ExitCode::from(18);
    };
    if let Err(e) = ensure_output_allowed(&output_path, args.force) {
        eprintln!("{e}");
        return ExitCode::from(15);
    }

    let Some(signature) = identity.sign(&data) else {
        eprintln!("Specified Identity does not hold a private key. Cannot sign.");
        return ExitCode::from(16);
    };
    if let Err(e) = write_output(&output_path, &signature, args.stdout) {
        eprintln!("{e}");
        return ExitCode::from(18);
    }

    if !args.stdout {
        println!(
            "File {} signed with {} to {}",
            input_path.display(),
            hex::encode(identity.hash),
            output_path.display()
        );
    }
    ExitCode::SUCCESS
}

fn validate_signature(identity: &Identity, args: &Args) -> ExitCode {
    let Some(sig_path) = args.validate.as_ref() else {
        return ExitCode::from(20);
    };
    let input_path = args.read.clone().unwrap_or_else(|| {
        let s = sig_path.to_string_lossy();
        if let Some(stripped) = s.strip_suffix(&format!(".{SIG_EXT}")) {
            PathBuf::from(stripped)
        } else {
            sig_path.clone()
        }
    });

    let sig_bytes = match std::fs::read(sig_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!(
                "An error occurred while opening {}: {e}",
                sig_path.display()
            );
            return ExitCode::from(10);
        }
    };
    let data = match read_input(&input_path, args.stdin) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(11);
        }
    };
    if sig_bytes.len() != 64 {
        eprintln!("Signature file {} is invalid", sig_path.display());
        return ExitCode::from(22);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_bytes);
    if identity.verify(&data, &signature) {
        println!(
            "Signature {} for file {} made by Identity {} is valid",
            sig_path.display(),
            input_path.display(),
            hex::encode(identity.hash)
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "Signature {} for file {} is invalid",
            sig_path.display(),
            input_path.display()
        );
        ExitCode::from(22)
    }
}

fn encrypt_file(identity: &Identity, args: &Args) -> ExitCode {
    let Some(input_path) = args.read.as_ref() else {
        eprintln!("Encryption requested, but no input data specified");
        return ExitCode::from(24);
    };
    let mut input: Box<dyn Read> = match std::fs::File::open(input_path) {
        Ok(file) => Box::new(file),
        Err(e) => {
            eprintln!("Input file {} not found: {e}", input_path.display());
            return ExitCode::from(12);
        }
    };
    let Some(output_path) = args
        .write
        .clone()
        .or_else(|| (!args.stdout).then(|| append_extension(input_path, ENCRYPT_EXT)))
    else {
        if !args.stdout {
            eprintln!("Encryption requested, but no output specified");
        }
        return ExitCode::from(25);
    };
    if let Err(e) = ensure_output_allowed(&output_path, args.force) {
        eprintln!("{e}");
        return ExitCode::from(15);
    };
    let mut output = match create_output(&output_path, args.stdout) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(25);
        }
    };

    let mut buffer = vec![0u8; PYTHON_COMPAT_PLAINTEXT_CHUNK_SIZE];
    loop {
        let n = match input.read(&mut buffer) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Could not read input file: {e}");
                return ExitCode::from(24);
            }
        };
        if n == 0 {
            break;
        }
        let ciphertext = match identity.encrypt(&buffer[..n], None) {
            Ok(ciphertext) => ciphertext,
            Err(e) => {
                eprintln!("An error occurred while encrypting data: {e}");
                return ExitCode::from(26);
            }
        };
        if let Err(e) = output.write_all(&ciphertext) {
            eprintln!("Could not write encrypted output: {e}");
            return ExitCode::from(25);
        }
    }

    if !args.stdout {
        println!(
            "File {} encrypted for {} to {}",
            input_path.display(),
            hex::encode(identity.hash),
            output_path.display()
        );
    }
    ExitCode::SUCCESS
}

fn decrypt_file(identity: &Identity, args: &Args) -> ExitCode {
    if !identity.has_private_key() {
        eprintln!("Specified Identity does not hold a private key. Cannot decrypt.");
        return ExitCode::from(27);
    }
    let Some(input_path) = args.read.as_ref() else {
        eprintln!("Decryption requested, but no input data specified");
        return ExitCode::from(28);
    };
    let ciphertext = match read_input(input_path, args.stdin) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(28);
        }
    };
    let Some(output_path) = args.write.clone().or_else(|| {
        if args.stdout {
            None
        } else {
            default_decrypt_output_path(input_path)
        }
    }) else {
        if !args.stdout {
            eprintln!("Decryption requested, but no output specified");
        }
        return ExitCode::from(29);
    };
    if let Err(e) = ensure_output_allowed(&output_path, args.force) {
        eprintln!("{e}");
        return ExitCode::from(15);
    }

    let plaintext = match decrypt_ciphertext(identity, &ciphertext) {
        Ok(plaintext) => plaintext,
        Err(()) => {
            eprintln!("Data could not be decrypted with the specified Identity");
            return ExitCode::from(30);
        }
    };

    if let Err(e) = write_output(&output_path, &plaintext, args.stdout) {
        eprintln!("{e}");
        return ExitCode::from(29);
    }
    if !args.stdout {
        println!(
            "File {} decrypted with {} to {}",
            input_path.display(),
            hex::encode(identity.hash),
            output_path.display()
        );
    }
    ExitCode::SUCCESS
}

fn decrypt_ciphertext(identity: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(plaintext) = identity.decrypt(ciphertext, None, false) {
        return Ok(plaintext);
    }

    if ciphertext.len() > CHUNK_SIZE {
        if let Ok(plaintext) =
            decrypt_ciphertext_chunks(identity, ciphertext, FULL_CHUNK_TOKEN_SIZE)
        {
            return Ok(plaintext);
        }
        if let Ok(plaintext) = decrypt_ciphertext_chunks(identity, ciphertext, CHUNK_SIZE) {
            return Ok(plaintext);
        }
    }

    Err(())
}

fn decrypt_ciphertext_chunks(
    identity: &Identity,
    ciphertext: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, ()> {
    let mut plaintext = Vec::new();
    let mut pos = 0usize;
    while pos < ciphertext.len() {
        let end = (pos + chunk_size).min(ciphertext.len());
        let chunk = identity
            .decrypt(&ciphertext[pos..end], None, false)
            .map_err(|_| ())?;
        plaintext.extend_from_slice(&chunk);
        pos = end;
    }
    Ok(plaintext)
}

fn read_input(path: &Path, _use_stdin: bool) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("Input file {} not found: {e}", path.display()))
}

fn create_output(path: &Path, _use_stdout: bool) -> Result<Box<dyn Write>, String> {
    let file = std::fs::File::create(path).map_err(|e| {
        format!(
            "Could not open output file {} for writing: {e}",
            path.display()
        )
    })?;
    Ok(Box::new(file))
}

fn write_output(path: &Path, data: &[u8], use_stdout: bool) -> Result<(), String> {
    let mut output = create_output(path, use_stdout)?;
    output
        .write_all(data)
        .map_err(|e| format!("Could not write output: {e}"))
}

fn ensure_output_allowed(path: &Path, force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "Output file {} already exists. Not overwriting.",
            path.display()
        ));
    }
    Ok(())
}

fn append_extension(path: &Path, ext: &str) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.to_string_lossy(), ext))
}

fn default_decrypt_output_path(path: &Path) -> Option<PathBuf> {
    let s = path.to_string_lossy();
    if s.to_lowercase().ends_with(&format!(".{ENCRYPT_EXT}")) {
        Some(PathBuf::from(s.replace(&format!(".{ENCRYPT_EXT}"), "")))
    } else {
        None
    }
}

fn parse_hash16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    hash16_from_slice(bytes)
}

fn decode_key_text(input: &str, args: &Args) -> Result<Vec<u8>, String> {
    if args.base64 {
        URL_SAFE.decode(input).map_err(|e| e.to_string())
    } else if args.base32 {
        decode_base32(input)
    } else {
        hex::decode(input).map_err(|e| e.to_string())
    }
}

fn encode_key_text(bytes: &[u8], args: &Args) -> String {
    if args.base64 {
        URL_SAFE.encode(bytes)
    } else if args.base32 {
        encode_base32(bytes)
    } else {
        hex::encode(bytes)
    }
}

fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | (*byte as u16);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}

fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = match ch {
            'A'..='Z' => ch as u8 - b'A',
            'a'..='z' => ch as u8 - b'a',
            '2'..='7' => ch as u8 - b'2' + 26,
            c if c.is_whitespace() => continue,
            _ => return Err(format!("invalid base32 character {ch:?}")),
        };
        buffer = (buffer << 5) | u32::from(val);
        bits += 5;
        while bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

fn pretty_hash(hash: &[u8; 16]) -> String {
    format!("<{}>", hex::encode(hash))
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
