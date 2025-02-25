#!/usr/bin/env python3
import hashlib, base58
from ecdsa import SigningKey, SECP256k1, util
from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction
from bitcoinlib.scripts import Script

def main():
    redeem_script_hex = "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"
    redeem_script = bytes.fromhex(redeem_script_hex)
    
    witness_hash = hashlib.sha256(redeem_script).digest()
    witness_program = bytes.fromhex("0020") + witness_hash

    unlocking_script = Script([witness_program]).as_bytes()    
    locking_script = Script([b'\xa9', bytes(hashlib.new('ripemd160', witness_hash).digest()), b'\x87']).as_bytes()
    
    txid = "0000000000000000000000000000000000000000000000000000000000000000"
    vout = 0
    sequence = 0xffffffff
    input_value = 100000
    
    expected_address = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF"
    output_value = 100000
    locktime = 0

    tx = Transaction(version=2,locktime=locktime,network='bitcoin') # here network idk what the use is , network='bitcoin'
    tx.add_input(
        prev_txid=txid,
        output_n=vout,
        sequence=sequence,
        unlocking_script=unlocking_script,
        # address=expected_address,
        witness_type="p2sh-segwit",
        value=input_value,
        locking_script=locking_script
    )
    tx.add_output(output_value, expected_address)
    

    privkey1_hex = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
    privkey2_hex = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"
    key1 = Key(import_key=privkey1_hex)
    key2 = Key(import_key=privkey2_hex)
    sk1 = SigningKey.from_string(key1.private_byte, curve=SECP256k1)
    sk2 = SigningKey.from_string(key2.private_byte, curve=SECP256k1)
    sighash_bytes = tx.signature_hash(0, hash_type=1, witness_type='segwit', as_hex=False)
    sig1 = sk1.sign_digest_deterministic(sighash_bytes, sigencode=util.sigencode_der) + b'\x01'
    sig2 = sk2.sign_digest_deterministic(sighash_bytes, sigencode=util.sigencode_der) + b'\x01'
    
    tx.inputs[0].witnesses = [b'', sig2, sig1, redeem_script]
    
    raw_tx_hex = tx.raw_hex()
    
    print("Raw tx hex:", hash(raw_tx_hex))
    with open("out.txt", "w", encoding="utf-8") as f:
        f.write(raw_tx_hex)

if __name__ == "__main__":
    main()
