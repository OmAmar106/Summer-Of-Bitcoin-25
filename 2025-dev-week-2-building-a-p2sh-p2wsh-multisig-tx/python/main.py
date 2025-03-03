import hashlib
import binascii
import ecdsa
import base58
# from bitcoinlib.keys import Key
# from bitcoinlib.transactions import Transaction
# from bitcoinlib.scripts import Script

def solve():
    # these are the constants given in the readme file
    priv_key1 = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
    priv_key2 = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"
    redeem_script_hex = "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"

    # converting the redeem_script_hex to bytes
    redeem_script = bytes.fromhex(redeem_script_hex)
    # caclculating the witness_program
    witness_program = hashlib.sha256(redeem_script).digest()
    # Create p2sh redeem script (0x00 + 0x20 + witness_program)
    p2sh_redeem_script = b"\x00\x20" + hashlib.sha256(redeem_script).digest()

    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(p2sh_redeem_script).digest())
    p2sh_hash = ripemd160.digest()

    # Transaction details that were mentioned in the readme file
    version = (1).to_bytes(4, byteorder='little')
    input_count = (1).to_bytes(1, byteorder='little')
    prev_txid = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    prev_index = (0).to_bytes(4, byteorder='little')
    sequence = (0xffffffff).to_bytes(4, byteorder='little')
    output_count = (1).to_bytes(1, byteorder='little')
    value = (100000).to_bytes(8, byteorder='little')
    address = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF"
    addr_bytes = base58.b58decode_check(address)
    script_hash = addr_bytes[1:]
    output_script = b"\xa9\x14" + script_hash + b"\x87"
    script_len = len(output_script).to_bytes(1, byteorder='little')
    locktime = (0).to_bytes(4, byteorder='little')

    # Calculating the script signature
    script_sig = len(p2sh_redeem_script).to_bytes(1, byteorder='little') + p2sh_redeem_script
    script_sig_len = len(script_sig).to_bytes(1, byteorder='little')
    hash_prevouts = hashlib.sha256(hashlib.sha256(prev_txid + prev_index).digest()).digest()
    hash_sequence = hashlib.sha256(hashlib.sha256(sequence).digest()).digest()
    hash_outputs = hashlib.sha256(hashlib.sha256(value + script_len + output_script).digest()).digest()

    # amount as mentioned in the readme file
    amount = (100000).to_bytes(8, byteorder='little')

    sighash_preimage = (
        version + hash_prevouts + hash_sequence +
        prev_txid + prev_index +
        len(redeem_script).to_bytes(1, byteorder='little') + redeem_script +
        amount + sequence + hash_outputs + locktime + (1).to_bytes(4, byteorder='little')
    )

    sighash = hashlib.sha256(hashlib.sha256(sighash_preimage).digest()).digest()

    # signature of the primary keys
    sk1 = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key1), curve=ecdsa.SECP256k1)
    sk2 = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key2), curve=ecdsa.SECP256k1)

    sig1 = sk1.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der_canonize) + b"\x01"
    sig2 = sk2.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der_canonize) + b"\x01"

    # the public keys
    pubkey1 = redeem_script[2:35]
    pubkey2 = redeem_script[36:69]

    # an empty byte so as to cancel out the op_multisig
    # sig2 and 1 in reverse order since this was the order in the redeem script
    witness = [b"", sig2, sig1, redeem_script]

    witness_encoded = len(witness).to_bytes(1, byteorder='little') + b"".join(
        len(item).to_bytes(1, byteorder='little') + item for item in witness)

    # final transaction id
    final_tx = (
        version + b"\x00\x01" + input_count +
        prev_txid + prev_index + script_sig_len + script_sig + sequence +
        output_count + value + script_len + output_script +
        witness_encoded + locktime
    )

    # converting it to hex
    tx_hex = binascii.hexlify(final_tx).decode()
    print(tx_hex)

    file = open("out.txt","w")
    file.write(tx_hex)
    file.close()

    # redeem_script_hex = "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"
    # redeem_script = bytes.fromhex(redeem_script_hex)
    
    # witness_hash = hashlib.sha256(redeem_script).digest()
    # witness_program = bytes.fromhex("0020") + witness_hash

    # unlocking_script = Script([witness_program]).as_bytes()    
    # locking_script = Script([b'\xa9', bytes(hashlib.new('ripemd160', witness_hash).digest()), b'\x87']).as_bytes()
    
    # txid = "0000000000000000000000000000000000000000000000000000000000000000"
    # vout = 0
    # sequence = 0xffffffff
    # input_value = 100000
    
    # expected_address = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF"
    # output_value = 100000
    # locktime = 0

    # tx = Transaction(version=2,locktime=locktime,network='bitcoin') # here network idk what the use is , network='bitcoin'
    # tx.add_input(
    #     prev_txid=txid,
    #     output_n=vout,
    #     sequence=sequence,
    #     unlocking_script=unlocking_script,
    #     # address=expected_address,
    #     witness_type="p2sh-segwit",
    #     value=input_value,
    #     locking_script=locking_script
    # )
    # tx.add_output(output_value, expected_address)
    

    # privkey1_hex = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
    # privkey2_hex = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"
    # key1 = Key(import_key=privkey1_hex)
    # key2 = Key(import_key=privkey2_hex)
    # sk1 = SigningKey.from_string(key1.private_byte, curve=SECP256k1)
    # sk2 = SigningKey.from_string(key2.private_byte, curve=SECP256k1)
    # sighash_bytes = tx.signature_hash(0, hash_type=1, witness_type='segwit', as_hex=False)
    # sig1 = sk1.sign_digest_deterministic(sighash_bytes, sigencode=util.sigencode_der) + b'\x01'
    # sig2 = sk2.sign_digest_deterministic(sighash_bytes, sigencode=util.sigencode_der) + b'\x01'
    
    # tx.inputs[0].witnesses = [b'', sig2, sig1, redeem_script]
    
    # raw_tx_hex = tx.raw_hex()
    
    # print("Raw tx hex:", hash(raw_tx_hex))
    # with open("out.txt", "w", encoding="utf-8") as f:
    #     f.write(raw_tx_hex)
if __name__=="__main__":
    solve()