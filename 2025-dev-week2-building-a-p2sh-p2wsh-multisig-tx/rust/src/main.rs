use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, Message};
use std::fs::File;
use std::io::Write;
use bs58;
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Private keys and redeem script from the assignment
    let priv_key1 = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf";
    let priv_key2 = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d";
    let redeem_script_hex = "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae";

    // Convert hex to bytes
    let redeem_script = hex::decode(redeem_script_hex)?;

    // Calculate the witness program (SHA256 of redeem script)
    let mut hasher = Sha256::new();
    hasher.update(&redeem_script);
    let witness_program = hasher.finalize();

    // Create P2SH redeem script (0x00 + 0x20 + witness_program)
    let mut p2sh_redeem_script = Vec::new();
    p2sh_redeem_script.push(0x00); // Version 0 (P2WSH)
    p2sh_redeem_script.push(0x20); // 32 bytes (SHA256 hash length)
    p2sh_redeem_script.extend_from_slice(&witness_program);

    // Hash the P2SH redeem script to get P2SH address
    let mut hasher = Sha256::new();
    hasher.update(&p2sh_redeem_script);
    let p2sh_script_hash = hasher.finalize();
    
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(p2sh_script_hash);
    let p2sh_hash = ripemd_hasher.finalize().to_vec();
    let mut address_bytes = vec![0x05]; // P2SH version byte
    address_bytes.extend_from_slice(&p2sh_hash);
    let mut hasher = Sha256::new();
    hasher.update(&address_bytes);
    let checksum = &Sha256::digest(&hasher.finalize())[0..4];
    address_bytes.extend_from_slice(checksum);
    let p2sh_address = bs58::encode(address_bytes).into_string();
    println!("P2SH Address: {}", p2sh_address);


    // Craft the unsigned transaction
    let mut unsigned_tx = Vec::new();

    // Transaction version (4 bytes, little-endian)
    unsigned_tx.extend_from_slice(&(1u32).to_le_bytes());

    // Input count (1 byte)
    unsigned_tx.push(1);

    // Input details
    // Previous transaction ID (all zeros)
    unsigned_tx.extend_from_slice(&[0u8; 32]);
    // Previous output index
    unsigned_tx.extend_from_slice(&(0u32).to_le_bytes());
    // ScriptSig length (initially empty)
    unsigned_tx.push(0);
    // Sequence
    unsigned_tx.extend_from_slice(&(0xFFFFFFFFu32).to_le_bytes());

    // Output count (1 byte)
    unsigned_tx.push(1);

    // Output details - 0.001 BTC to 325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF
    unsigned_tx.extend_from_slice(&(100000u64).to_le_bytes()); // 0.001 BTC in satoshis

    // Decode the address to get the script
    let address = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF";
    let addr_bytes = bs58::decode(address).into_vec()?;
    let script_hash = &addr_bytes[1..21]; // Extract 20-byte hash correctly

    // Create output script: OP_HASH160 <20-byte-hash> OP_EQUAL
    let mut output_script = Vec::new();
    output_script.push(0xA9); // OP_HASH160
    output_script.push(0x14); // Push 20 bytes
    output_script.extend_from_slice(script_hash);
    output_script.push(0x87); // OP_EQUAL

    // Script length
    unsigned_tx.push(output_script.len() as u8);
    // Script bytes
    unsigned_tx.extend_from_slice(&output_script);

    // Locktime (4 bytes, little-endian)
    unsigned_tx.extend_from_slice(&(0u32).to_le_bytes());

    // Calculate the sighash
    // For P2SH-P2WSH, we need to include the redeem script in the signature hash calculation
    
    // Double hash prevouts
    let mut prevouts_preimage = Vec::new();
    prevouts_preimage.extend_from_slice(&[0u8; 32]); // txid (all zeros)
    prevouts_preimage.extend_from_slice(&(0u32).to_le_bytes()); // vout
    
    let mut hasher = Sha256::new();
    hasher.update(&prevouts_preimage);
    let hash_prevouts_1 = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(&hash_prevouts_1);
    let hash_prevouts = hasher.finalize();

    // Double hash sequence
    let sequence_preimage = (0xFFFFFFFFu32).to_le_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&sequence_preimage);
    let hash_sequence_1 = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(&hash_sequence_1);
    let hash_sequence = hasher.finalize();

    // Double hash outputs
    let mut outputs_preimage = Vec::new();
    outputs_preimage.extend_from_slice(&(100000u64).to_le_bytes());
    outputs_preimage.push(output_script.len() as u8);
    outputs_preimage.extend_from_slice(&output_script);
    
    let mut hasher = Sha256::new();
    hasher.update(&outputs_preimage);
    let hash_outputs_1 = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(&hash_outputs_1);
    let hash_outputs = hasher.finalize();

    // BIP143 signature hash calculation
    let mut sighash_preimage = Vec::new();
    sighash_preimage.extend_from_slice(&(1u32).to_le_bytes()); // version
    sighash_preimage.extend_from_slice(&hash_prevouts); // hash prevouts
    sighash_preimage.extend_from_slice(&hash_sequence); // hash sequence
    sighash_preimage.extend_from_slice(&[0u8; 32]); // outpoint txid (all zeros)
    sighash_preimage.extend_from_slice(&(0u32).to_le_bytes()); // outpoint index
    
    // Push the redeem script with its length prefix
    sighash_preimage.push(redeem_script.len() as u8);
    sighash_preimage.extend_from_slice(&redeem_script);
    
    // Amount being spent (0 for this exercise)
    sighash_preimage.extend_from_slice(&(0u64).to_le_bytes());
    
    // Sequence
    sighash_preimage.extend_from_slice(&(0xFFFFFFFFu32).to_le_bytes());
    
    // Hash outputs
    sighash_preimage.extend_from_slice(&hash_outputs);
    
    // Locktime
    sighash_preimage.extend_from_slice(&(0u32).to_le_bytes());
    
    // Sighash type (SIGHASH_ALL)
    sighash_preimage.extend_from_slice(&(1u32).to_le_bytes());

    // Double hash the preimage to get the sighash
    let mut hasher = Sha256::new();
    hasher.update(&sighash_preimage);
    let sighash_1 = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(&sighash_1);
    let sighash = hasher.finalize();

    // Sign the transaction with both private keys
    let secp = Secp256k1::new();
    let secret_key1 = SecretKey::from_slice(&hex::decode(priv_key1)?)?;
    let secret_key2 = SecretKey::from_slice(&hex::decode(priv_key2)?)?;
    
    let message = Message::from_slice(&sighash)?;
    let sig1 = secp.sign_ecdsa(&message, &secret_key1);
    let sig2 = secp.sign_ecdsa(&message, &secret_key2);

    // Create ECDSA signatures with SIGHASH_ALL appended
    let mut sig1_der = sig1.serialize_der().to_vec();
    sig1_der.push(0x01); // SIGHASH_ALL
    
    let mut sig2_der = sig2.serialize_der().to_vec();
    sig2_der.push(0x01); // SIGHASH_ALL

    // Construct the final transaction
    let mut final_tx = Vec::new();
    
    // Version
    final_tx.extend_from_slice(&(1u32).to_le_bytes());
    
    // Marker (0x00) and flag (0x01) for SegWit
    final_tx.push(0x00);
    final_tx.push(0x01);
    
    // Input count
    final_tx.push(1);
    
    // Input details
    final_tx.extend_from_slice(&[0u8; 32]); // txid (all zeros)
    final_tx.extend_from_slice(&(0u32).to_le_bytes()); // vout
    
    // The scriptsig for P2SH-P2WSH is just the P2SH redeem script
    let script_sig_len = p2sh_redeem_script.len() as u8;
    final_tx.push(script_sig_len);
    final_tx.extend_from_slice(&p2sh_redeem_script);
    
    // Sequence
    final_tx.extend_from_slice(&(0xFFFFFFFFu32).to_le_bytes());
    
    // Output count
    final_tx.push(1);
    
    // Output details
    final_tx.extend_from_slice(&(100000u64).to_le_bytes()); // 0.001 BTC in satoshis
    final_tx.push(output_script.len() as u8);
    final_tx.extend_from_slice(&output_script);
    
    // Witness
    // Witness item count (4 items)
    final_tx.push(4);
    
    // Empty byte for OP_CHECKMULTISIG bug
    final_tx.push(0); // Length 0
    
    // First signature (sig2)
    final_tx.push(sig2_der.len() as u8);
    final_tx.extend_from_slice(&sig2_der);
    
    // Second signature (sig1)
    final_tx.push(sig1_der.len() as u8);
    final_tx.extend_from_slice(&sig1_der);
    
    // Redeem script
    final_tx.push(redeem_script.len() as u8);
    final_tx.extend_from_slice(&redeem_script);
    
    // Locktime
    final_tx.extend_from_slice(&(0u32).to_le_bytes());

    // Convert final transaction to hex and save to out.txt
    let tx_hex = hex::encode(&final_tx);
    println!("{}", tx_hex);
    
    let mut file = File::create("out.txt")?;
    file.write_all(tx_hex.as_bytes())?;
    
    Ok(())
}