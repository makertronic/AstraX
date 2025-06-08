/*
 * Project: AstraX - ASIC-Resistant & Post-Quantum File Hasher
 * Description: A command-line tool that hashes files using Argon2id (memory-hard, ASIC-resistant) followed by SHAKE256 (post-quantum secure).
 * Author: Makertronic
 * License: MIT
 * Date: 2025
 */

use clap::Parser;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString, Params};
use sha2::{Digest, Sha256};

/// Hash a file using Argon2id followed by SHAKE256 (ASIC-resistant + post-quantum)
#[derive(Parser, Debug)]
struct Args {
    /// Path to the input file
    #[arg(short, long)]
    input: PathBuf,
    
    /// Length of the output hash in bytes (default: 64)
    #[arg(short, long, default_value_t = 64)]
    output_len: usize,
}

fn argon2id_then_shake256_hash_file(path: &PathBuf, output_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Read file content into memory
    let mut file = File::open(path)?;
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;
    
    // Derive salt from SHA256 of file content (to make hash deterministic)
    let file_digest = Sha256::digest(&file_data);
    let salt = SaltString::encode_b64(&file_digest[..16])
        .map_err(|e| format!("Salt encoding failed: {}", e))?;
    
    // Apply Argon2id
    let params = Params::new(64 * 1024, 3, 1, None)
        .map_err(|e| format!("Invalid Argon2 params: {}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    
    let password_hash = argon2
        .hash_password(&file_data, &salt)
        .map_err(|e| format!("Argon2 hashing failed: {}", e))?;
    
    let hash_bytes = password_hash
        .hash
        .ok_or("Missing hash output")?
        .as_bytes()
        .to_vec();
    
    // Apply SHAKE256 on Argon2 output
    let mut hasher = Shake256::default();
    hasher.update(&hash_bytes);
    let mut xof = hasher.finalize_xof();
    
    let mut result = vec![0u8; output_len];
    XofReader::read(&mut xof, &mut result);
    
    Ok(result)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let hash = argon2id_then_shake256_hash_file(&args.input, args.output_len)?;
    println!("Argon2id+SHAKE256 hash ({} bytes): {}", args.output_len, hex::encode(hash));
    Ok(())
}