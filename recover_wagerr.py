import binascii
from bip_utils import (
    Bip39MnemonicValidator ,Bip39SeedGenerator, Bip32Secp256k1, Secp256k1PublicKey, Secp256k1PrivateKey,
    CoinsConf, P2PKHAddr, WifEncoder
)
import urllib3
from urllib3 import util
import json

from bip_utils.utils import mnemonic

def __main__():

    #mnemonic = input("Enter 12-word mnemonic: ")
    #send_to = input("Enter address to send to: ")
    
    is_valid = Bip39MnemonicValidator().IsValid(mnemonic)

    if not is_valid:
        print ("ERROR: Invalid mnemonic")
        exit(1)

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)

    # iterate over all addresses
    print ("Deriving normal addresses...")
    (total_normal, addresses_normal) = derive_addresses(bip32_ctx, 0)
    print ("Deriving change addresses...")
    (total_change, addresses_change) = derive_addresses(bip32_ctx, 1)
    print ("Total balance found: " + str(total_normal + total_change) + " WGR")
    addresses = addresses_normal + addresses_change
    utxos = check_cryptoid(addresses)
    print (utxos)
    
                    
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


def derive_addresses( bip32_ctx, change = 0):
    tx_found = True
    i = 0
    total = 0
    addresses = []
    while tx_found:
        child_ctx = bip32_ctx.DerivePath("0'/"+str(change)+"/"+str(i))

        pub_key = Secp256k1PublicKey.FromBytes(child_ctx.PublicKey().RawCompressed().ToBytes())
        prv_key = Secp256k1PrivateKey.FromBytes(child_ctx.PrivateKey().Raw().ToBytes())
    
        addr = P2PKHAddr.EncodeKey(pub_key,net_ver=CoinsConf.Wagerr.Params("p2pkh_net_ver"))
        priv = WifEncoder.Encode(prv_key,net_ver=CoinsConf.Wagerr.Params("wif_net_ver"))
    
        (balance, n_tx) = check_address(addr)
        total += balance

        if balance>0:
            print ("Address: " + addr)
            print ("Balance: " + str(balance) + " WGR")
            print ("")
            addresses.append(addr)

        if n_tx == 0:
            print ("No transactions found for this address, round finished...")
            tx_found = False
        i += 1

    return (total, addresses)

if __name__ == "__main__":
    __main__()
