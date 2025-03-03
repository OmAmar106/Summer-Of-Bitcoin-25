import os
import json
import time
import hashlib

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def compute_merkle_root_from_hashes(hashes: list) -> bytes:
    if not hashes:
        return b'\x00' * 32
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(double_sha256(hashes[i] + hashes[i+1]))
        hashes = new_hashes
    return hashes[0]

def compute_wtxid(tx_hex: str) -> str:
    tx_bytes = bytes.fromhex(tx_hex)
    if len(tx_bytes) >= 5 and tx_bytes[4] == 0x00 and tx_bytes[5] == 0x01:
        return double_sha256(tx_bytes)[::-1].hex()
    return double_sha256(tx_bytes)[::-1].hex()

def build_coinbase_tx(witness_commitment: bytes):
    version = (4).to_bytes(4, 'little')
    marker = b'\x00'
    flag = b'\x01'
    input_count = b'\x01'
    prev_txid = b'\x00' * 32
    prev_index = (0xffffffff).to_bytes(4, 'little')
    coinbase_data = b"coinbase"
    coinbase_data_len = len(coinbase_data).to_bytes(1, 'little')
    sequence = (0xffffffff).to_bytes(4, 'little')
    input_data = prev_txid + prev_index + coinbase_data_len + coinbase_data + sequence

    output_count = b'\x02'
    reward = 5000000000
    
    value1 = reward.to_bytes(8, 'little')
    script_pubkey1 = bytes.fromhex("76a914000000000000000000000000000000000000000088ac")
    script_pubkey1_len = len(script_pubkey1).to_bytes(1, 'little')
    output1 = value1 + script_pubkey1_len + script_pubkey1

    value2 = (0).to_bytes(8, 'little')
    commitment_script = bytes.fromhex("6a24aa21a9ed") + witness_commitment
    script_pubkey2_len = len(commitment_script).to_bytes(1, 'little')
    output2 = value2 + script_pubkey2_len + commitment_script

    witness_reserved_value = b'\x00' * 32
    witness = bytes([1]) + len(witness_reserved_value).to_bytes(1, 'little') + witness_reserved_value

    locktime = (0).to_bytes(4, 'little')

    segwit_tx = version + marker + flag + input_count + input_data + output_count + output1 + output2 + witness + locktime
    
    legacy_tx = version + input_count + input_data + output_count + output1 + output2 + locktime
    coinbase_txid = double_sha256(legacy_tx)[::-1].hex()
    
    return segwit_tx, coinbase_txid, witness_reserved_value

def mine_block_header(prev_block_hash: str, merkle_root: bytes, timestamp: int, bits: int, difficulty_target: int):
    version = (4).to_bytes(4, 'little')
    prev_hash_le = bytes.fromhex(prev_block_hash)[::-1]
    time_bytes = timestamp.to_bytes(4, 'little')
    bits_bytes = bits.to_bytes(4, 'little')
    
    nonce = 0
    while nonce < 0xffffffff:
        header = version + prev_hash_le + merkle_root + time_bytes + bits_bytes + nonce.to_bytes(4, 'little')
        header_hash = double_sha256(header)
        if int.from_bytes(header_hash[::-1], 'big') < difficulty_target:
            return header
        nonce += 1

def load_mempool_transactions(mempool_dir: str) -> list:
    txs = []
    for filename in os.listdir(mempool_dir):
        if filename.endswith('.json'):
            path = os.path.join(mempool_dir, filename)
            try:
                with open(path, 'r') as f:
                    content = json.load(f)
                    if isinstance(content, list):
                        txs.extend([tx for tx in content if isinstance(tx, dict) and 'txid' in tx and 'hex' in tx])
                    elif isinstance(content, dict) and 'txid' in content and 'hex' in content:
                        txs.append(content)
            except Exception:
                continue
    return txs

def main():
    difficulty_target = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)
    bits = 0x1f00ffff
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    
    mempool_dir = "mempool"
    all_txs = load_mempool_transactions(mempool_dir)
    valid_txs = [tx for tx in all_txs if isinstance(tx, dict) and 'txid' in tx and 'hex' in tx]
    
    temp_commitment = b'\x00' * 32
    temp_coinbase, _, reserved_value = build_coinbase_tx(temp_commitment)
    current_weight = len(temp_coinbase) * 4
    selected_txs = []
    
    for tx in sorted(valid_txs, key=lambda x: x['txid']):
        tx_weight = len(bytes.fromhex(tx['hex'])) * 4
        if current_weight + tx_weight <= 4000000:
            selected_txs.append(tx)
            current_weight += tx_weight
    
    wtxids = ['0' * 64] + [compute_wtxid(tx['hex']) for tx in selected_txs]
    witness_hashes = [bytes.fromhex(wtxid)[::-1] for wtxid in wtxids]
    witness_merkle_root = compute_merkle_root_from_hashes(witness_hashes)
    commitment = double_sha256(witness_merkle_root + reserved_value)
    
    coinbase_tx, coinbase_txid, _ = build_coinbase_tx(commitment)
    
    txids = [coinbase_txid] + [tx['txid'] for tx in selected_txs]
    hashes = [bytes.fromhex(txid)[::-1] for txid in txids]
    merkle_root = compute_merkle_root_from_hashes(hashes)
    
    timestamp = int(time.time())
    header = mine_block_header(prev_block_hash, merkle_root, timestamp, bits, difficulty_target)
    
    file = open("out.txt","w")
    file.write(header.hex()+'\n')
    file.write(coinbase_tx.hex()+'\n')
    file.write("\n".join([coinbase_txid]+[tx['txid'] for tx in selected_txs]))
    file.close()

if __name__ == "__main__":
    main()
