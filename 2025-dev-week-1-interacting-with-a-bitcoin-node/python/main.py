from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import json

# Node access params
RPC_URL = "http://alice:password@127.0.0.1:18443"

def send(rpc, addr, data):
    args = [
        {addr: 100},    # recipient address
        None,           # conf target
        None,
        21,             # fee rate in sats/vb
        None            # Empty option object
    ]
    send_result = rpc.send('send', args)
    assert send_result['complete']
    return send_result['txid']

def list_wallet_dir(rpc):
    result = rpc.listwalletdir()
    return [wallet['name'] for wallet in result['wallets']]

def main():
    rpc = AuthServiceProxy(RPC_URL)

    # print(rpc.getwalletinfo())
    # print(rpc.getnetworkinfo())
    # return
    # Check connection
    info = rpc.getblockchaininfo()
    print(info)

    # Create or load the wallet    
    walletname = "testwallet"

    # this parts either creates or loads the wallet if it already exists
    try:
        rpc.createwallet(walletname)
    except:
        pass
    try:
        rpc.loadwallet(walletname)
    except:
        pass
    # rpc.loadwallet(walletname)
    print(rpc.listwallets(),rpc.listwalletdir())

    # Generate a new address
    # add = rpc.getnewaddress()
    add = rpc.getnewaddress()
    # address = rpc.getaddressesbylabel("")
    # if not address:
    #     add = rpc.getnewaddress()
    # else:
    #     add = list(address.keys())[0]

    print(add)

    print(rpc.getbalance())
    # print(rpc.listunspent())
    # print(rpc.getbalances())


    # Mine 101 blocks to the new address to activate the wallet with mined coins
    for i in range(2):
        mine = rpc.generatetoaddress(101,add)
    # for i in range(5):
    #     rpc.generatetoaddress(101,add)
    # print(mine)
    print(rpc.getbalance())
    # print(rpc.getaddressesbylabel(""))

    # Prepare a transaction to send 100 BTC
    sendto = "bcrt1qq2yshcmzdlznnpxx258xswqlmqcxjs4dssfxt2"
    amt = 100.0
    message = "We are all Satoshi!!"
    # trans = {
    #     sendto:amt,
    #     "data":message.encode('utf-8').hex()
    # }
    
    utxos = rpc.listunspent()

    # to check if total amount we have is more than the required amount
    print(sum(utxo["amount"] for utxo in utxos))
    print(rpc.getbalance())
    # Send the transaction

    # to take the higher amount first 
    utxos = sorted(utxos,key = lambda x:-x["amount"])
    input = []
    amounttaken = 0
    for i in range(len(utxos)):
        input.append({"txid":utxos[i]["txid"],"vout":utxos[i]["vout"]})
        amounttaken += utxos[i]["amount"]
        if amounttaken>amt: # as soon as we get the required amount , we break
            break
    
    # print(input)
    transac = rpc.createrawtransaction(input,[
        {sendto:amt},
        {"data":message.encode('utf-8').hex()}
    ])

    signed = rpc.signrawtransactionwithwallet(rpc.fundrawtransaction(transac, {"fee_rate": 21})["hex"]) # setting the fee rate as 21 sats/vB
    txid = rpc.sendrawtransaction(signed["hex"],0)

    # Write the txid to out.txt
    file = open("out.txt","w")
    file.write(txid)
    file.close()

if __name__ == "__main__":
    main()