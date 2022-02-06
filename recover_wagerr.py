
import sys
from bip_utils import (
    Bip39MnemonicValidator ,Bip39SeedGenerator, Bip32Secp256k1, Secp256k1PublicKey, Secp256k1PrivateKey,
    CoinsConf, P2PKHAddr, WifEncoder
)
from bit import *

import urllib3
from urllib3 import util
import json

from bip_utils.utils import mnemonic
from bit import network

def __main__():

    fee_per_kb = 200000
    verbose = False

    if len(sys.argv) > 1:
        if sys.argv[1] == "verbose":
            verbose = True

    if len(sys.argv) > 2:
        fee_per_kb = sys.argv[2]
        
    mnemonic = input("Enter 12-word mnemonic: ")
    send_to = input("Enter address to send to (CHECK IT CAREFULLY!): ")
    
    is_valid = Bip39MnemonicValidator().IsValid(mnemonic)

    if not is_valid:
        print ("ERROR: Invalid mnemonic")
        exit(1)

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)

    # iterate over all addresses
    print ("Searching normal addresses...")
    (total_normal, addresses_normal, prvkeys_normal) = derive_addresses(bip32_ctx, 0, verbose)
    print ("Searching change addresses...")
    (total_change, addresses_change, prvkeys_change) = derive_addresses(bip32_ctx, 1, verbose)
    balance = total_normal + total_change
    print ("Total balance found: " + str(balance) + " WGR")
    addresses = addresses_normal + addresses_change
    prvkeys = prvkeys_normal + prvkeys_change
    utxos = check_cryptoid(addresses)
    
    # rough fee calculation
    fee = 2* (len(utxos) * 100 + 150) * fee_per_kb / (1000*1e8)
    print ("Estimated fee: " + str(fee) + " WGR")
    
    # create transaction
    outputs = [(send_to, balance-fee, 'btc')]
    unspents = []
    for utxo in utxos:
        unspents.append(network.meta.Unspent(utxo['value'],utxo['confirmations'],utxo['script'],utxo['tx_hash'],utxo['tx_ouput_n']))

    if verbose:
        print ("List of Unspents: ")
        print(unspents)

    bit_key = Key(prvkeys[0])
    bit_tx = bit_key.create_transaction(outputs, fee=fee*1e8, absolute_fee=True, unspents=unspents)
    
    # batch sign the remaining inputs
    for prvkey in prvkeys[1:]:
        bit_key2 = Key(prvkey)
        bit_tx = bit_key2.sign_transaction(bit_tx, unspents=unspents)

    print ("")    
    print("Transaction ready. Enter the following command in the Debug RPC Console if you want to see how the transaction looks like:")
    print ("")
    print("decoderawtransaction " + bit_tx)
    print ("")
    print("Please enter the following command in the Debug RPC Console to send your funds to the destination address:")
    print ("")
    print("sendrawtransaction " + bit_tx)

                    
def check_address( address ):
    http = urllib3.PoolManager(timeout=util.Timeout(10))
    url = "https://explorer.wagerr.com/api/address/" + address
    res = http.request('GET', url, timeout=util.Timeout(10), retries=util.Retry(10))
    data = json.loads(res.data.decode('utf-8'))
    balance = data['balance']
    n_tx = len(data['txs'])
    return (balance, n_tx)

def check_cryptoid( addresses ):
    utxo_key = "552651714eae"
    http = urllib3.PoolManager(timeout=util.Timeout(10))
    url = "https://chainz.cryptoid.info/wgr/api.dws?key={}&q=unspent&active={}".format(utxo_key, "|".join(addresses))
    res = http.request('GET', url, timeout=util.Timeout(10), retries=util.Retry(10))
    data = json.loads(res.data.decode('utf-8'))
    utxos = data['unspent_outputs']
    return utxos


def derive_addresses( bip32_ctx, change = 0, verbose = False ):
    tx_found = True
    i = 0
    total = 0
    addresses = []
    prvkeys = []
    while tx_found:

        child_ctx = bip32_ctx.DerivePath("0'/"+str(change)+"/"+str(i))

        pub_key = Secp256k1PublicKey.FromBytes(child_ctx.PublicKey().RawCompressed().ToBytes())
        pub_key_str = child_ctx.PublicKey().RawCompressed().ToHex()
        prv_key = Secp256k1PrivateKey.FromBytes(child_ctx.PrivateKey().Raw().ToBytes())
    
        addr = P2PKHAddr.EncodeKey(pub_key,net_ver=CoinsConf.Wagerr.Params("p2pkh_net_ver"))
        priv = WifEncoder.Encode(prv_key,net_ver=CoinsConf.Wagerr.Params("wif_net_ver"))
    
        (balance, n_tx) = check_address(addr)
        total += balance

        if verbose or balance>0:
            print ("Address {}: {}".format(i, addr))
            #print ("Private key (WIF): " + priv)
            print ("Balance: " + str(balance) + " WGR")
            print ("Number of transactions: " + str(n_tx))
            print ("")

        if balance>0:
            addresses.append(addr)
            prvkeys.append(priv)
        else:
            sys.stdout.write("Checking Address {}: {} \r".format(i, addr))
            sys.stdout.flush()
        
        if n_tx == 0:
            print("")
            print ("No more transactions found, round finished...")
            print("")
            tx_found = False
        i += 1
        
    return (total, addresses, prvkeys)

if __name__ == "__main__":
    __main__()
