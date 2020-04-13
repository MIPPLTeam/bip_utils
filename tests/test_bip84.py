# Copyright (c) 2020 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


# Imports
import binascii
import unittest
from bip_utils import (
    Bip84, Bip44Coins, Bip44Changes, Bip44DepthError, Bip32KeyError
)

# Some seeds randomly taken from Ian Coleman web page
# https://iancoleman.io/bip39/
# There are some differences from the website and the specs I found for Litecoin testnet (extended keys prefixes) so,
# in that case, the keys were generated by this library after begin tested for the correct addresses
TEST_VECTOR = \
    [
        # Bitcoin
        {
            "coin"       : Bip44Coins.BITCOIN,
            "names"      : ("Bitcoin", "BTC"),
            "is_testnet" : False,
            "seed"       : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master"  :  "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
            "wif_master" :  "5HzxC8XHHAtoC5jVvScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr",
            "account" :
                {
                    "ex_pub"  : "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
                    "ex_priv" : "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "zpub6u4KbU8TSgNuZSxzv7HaGq5Tk361gMHdZxnM4UYuwzg5CMLcNytzhobitV4Zq6vWtWHpG9QijsigkxAzXvQWyLRfLq1L7VxPP1tky1hPfD4",
                    "ex_priv" : "zprvAg4yBxbZcJpcLxtXp5kZuh8jC1FXGtZnCjrkG69JPf96KZ1TqSakA1HF3EZkNjt9yC4CTjm7txs4sRD9EoHLgDqwhUE6s1yD9nY4BCNN4hw",
                },
            "addresses" :
                [
                    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
                    "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z",
                    "bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3",
                    "bc1qm97vqzgj934vnaq9s53ynkyf9dgr05rargr04n",
                ],
        },
        # Litecoin
        {
            "coin"       : Bip44Coins.LITECOIN,
            "names"      : ("Litecoin", "LTC"),
            "is_testnet" : False,
            "seed"       : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master"  :  "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
            "wif_master" :  "6uJgfG4pBbMffTdMSGQVurdK6xBcZjhf1iDU2jtPAw5PzRdhx9m",
            "account" :
                {
                    "ex_pub"  : "zpub6rPo5mF47z5coVm5rvWv7fv181awb7Vckn5Cf3xQXBVKu18kuBHDhNi1Jrb4br6vVD3ZbrnXemEsWJoR18mZwkUdzwD8TQnHDUCGxqZ6swA",
                    "ex_priv" : "zprvAdQSgFiAHcXKb1gcktyukXyGZykTBemmPZ9brfYnxqxM2CocMdxy9aPXTbTLv7dvJgWn2Efi4vFSyPbT4QqgarYrs583WCeMXM2q3TUU8FS",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "zpub6tXPeWbUFv3G95mPgnK9zeAV3U38cedWHFixEyzFGGEaCVwpV7iRzy1tgaGH9CRhmWjQ3xwqxEkTsn4kbbjKADwF9qFu8WrRKXPbWKRN8v5",
                    "ex_priv" : "zprvAfY3F14aRYUxvbgvakn9dWDkVSCeDBuev2oMSbadhvhbKhcfwaQBTAhQqJZq7iBudjZUf3FSC9usyUbUDqwhdTUYvRQaiaNdFjBXEBqWcgR",
                },
            "addresses" :
                [
                    "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh",
                    "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn",
                    "ltc1qc6aucuznvhh9uvux246x24vf9y9ncfk729m92s",
                    "ltc1qr4uckk3jjxtknw5mtqmtwvt87955rc7ays0hsh",
                    "ltc1q8mtg60wwrnh5wjver003uewy4drfm9sses95z2",
                ],
        },
        # Bitcoin test net
        {
            "coin"       : Bip44Coins.BITCOIN_TESTNET,
            "names"      : ("Bitcoin", "BTC"),
            "is_testnet" : True,
            "seed"       : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master"  :  "vprv9DMUxX4ShgxMLfvb8sFY4xFFKyTibwTfoydH3beVutr1L3bWHhRn3f2SqSo3vdUacd6QuuUxmN8BYoGhX2J4okpwCMh4nwdq9EqbdGgioRF",
            "wif_master" :  "91mamsLpsPxwA9EnYnWT14Q6o8yrX6npaygFQBDroDVq5dZG3q3",
            "account" :
                {
                    "ex_pub"  : "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc",
                    "ex_priv" : "vprv9K7GLAaERuM58PVvbk1sMo7wzVCoPwzZpVXLRBmum93gL5pSqQCAAvZjtmz93nnnYMr9i2FwG2fqrwYLRgJmDDwFjGiamGsbRMJ5Y6siJ8H",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "vpub5baxyhXRwCQ1N4KuQfdVSfnYahk6HDRCqDhQJjgSbxo8SzP5ghgHugxZuQ9TpfGC2oTBYdVi8thxMGhqjcVbNPMBNRKMX9x1PZW4LXNyq7q",
                    "ex_priv" : "vprv9NbcaBzY6pqi9aFSJe6V5Xqp2fubskhMTzmoWMGq3dG9aC3w9AN3Mte646s59AnZaiAgg2rAgxPYusyEMm2YADoaa5nRaGoExuVVZGc7HCC",
                },
            "addresses" :
                [
                    "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
                    "tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97",
                    "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct",
                    "tb1qynpgs6wap6h9uvy7j0xlesew2w82qn038zm5km",
                    "tb1q677973lw0w796gttpy52f296jqaaksz0555pg2",
                ],
        },
        # Litecoin test net
        {
            "coin"       : Bip44Coins.LITECOIN_TESTNET,
            "names"      : ("Litecoin", "LTC"),
            "is_testnet" : True,
            "seed"       : b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "ex_master"  :  "ttpv96BtqegdxXceQk8r9KuoG5yiMACLxANu9hh98NpMwpzcCa8XfrJ7uwnRBMzsE5n9y2exs7VQBBdHNiJ66BrDUWE28WoexgbFVRkRc2abBR9",
            "wif_master" :  "91mamsLpsPxwA9EnYnWT14Q6o8yrX6npaygFQBDroDVq5dZG3q3",
            "account" :
                {
                    "ex_pub"  : "ttub4d81p5cxvtYKpLR1rpAWdWgdTEdcpRUTEjhEAwi4jFysnyYYYU6w3pRyV6gPAKZbaHoVQdDSdDJrEngpFdPnoTQM8PBSDhD552ZSfeKDEKA",
                    "ex_priv" : "ttpv9BwgDJCRgk1NCTiBcCg8YvrR1fwRkAuoADbCVxwmo5CHCcMUDZ4W3DKiEhBxMF6MtmQhfEGNfrAwgrZizqrusyLLfRqAw1q1mYCuWp2x9bA",
                },
            "chain_ext" :
                {
                    "ex_pub"  : "ttub4gcN473Gbp2xqXAXZiF8MFQVVRLRJEBEtEwhG7Cz1kCM35n2rEGpEnWKeRLHuoKq4Jr31TFBEf9nHmyGpZADExALe9NE3dcSRrZLAGnEUVH",
                    "ex_priv" : "ttpv9FS2TKcjMfW1DeThK6kkGfaH3reEDycaoiqfb8Sh5ZQkSiaxXKEPEBQ4Q24tSd68w7jEdErc6mtejnzcvvagpyCfWEu1k1kfK6QKY3E4mwh",
                },
            "addresses" :
                [
                    "tltc1q6rz28mcfaxtmd6v789l9rrlrusdprr9pesrjxk",
                    "tltc1qd7spv5q28348xl4myc8zmh983w5jx32ctl5d4h",
                    "tltc1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8fha3gz",
                    "tltc1qynpgs6wap6h9uvy7j0xlesew2w82qn0372e2xj",
                    "tltc1q677973lw0w796gttpy52f296jqaaksz0duklcr",
                ],
        },
    ]

# Tests for different key formats
TEST_KEY_FORMATS = \
    {
        "coin"            : Bip44Coins.BITCOIN,
        "seed"            : "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        "ex_priv"         : "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
        "raw_priv"        : "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67",
        "ex_pub"          : "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF",
        "raw_compr_pub"   : "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494",
        "raw_uncompr_pub" : "d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee04947d000a1345d3845dd83b4c5814f876c918305b598f066c958fad972bf59f2ec7",
    }

# Tests for extended keys with valid and invalid depths
TEST_EXKEY_DEPTHS = \
    {
        # Private key with depth 5 is fine
        "ex_priv_5" : "zprvAgXNdrVSkvLM5GpuHWL9EoqfiXCvpL8DufMAbQiyFa1RTqmqs9PMdR7dHXCqYMZnmVReq6KSPwysULotdZYhYry6BejgKdtNrEnKx91CGBP",
        # Private key with depth 6 shall raise an exception
        "ex_priv_6" : "zprvAjPYgsh8YN3eo99YLw2mPCHbu3aeGiBsotM7nYANpFss5oHg7P9a6VcVC6K5WdWf3ids32M54srqqiizzNWzUGmEWW5snNEBJopzRUTHtQD",
        # Public key with depth 2 shall raise an exception
        "ex_pub_2"  : "zpub6pNAXMNU74t5ERmvhYL68oqmkaRKPPFucgE6Vrd7Q11N712u3EFZ3X18MY9LsL48ySz5fTaetHhpft2bsPDtxK97HnnKkzR2ES2qB69sCPf",
        # Public key with depth 3 is fine
        "ex_pub_3"  : "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        # Public key with depth 5 is fine
        "ex_pub_5"  : "zpub6uWj3N2LbHteHkuNPXs9bwnQGZ3RDnr5GtGmPo8aouYQLe6zQghcBDS78p221mbYb5eVgviZ2mEkdgMvLfSmvzsSe6nMYVaALaL6rZ9pTbq",
        # Public key with depth 6 shall raise an exception
        "ex_pub_6"  : "zpub6xNu6PE2Njbx1dE1SxZmkLELT5R8gAujB7GiavZzNbQqxbcpevTpeHvy3PBcrhtf1rZNkxnpxRhU8T2sXfcZ5kxdTePWsFD3TcAqeon3Dfy",
    }


#
# Tests
#
class Bip84Tests(unittest.TestCase):
    # Test specification name
    def test_spec_name(self):
        self.assertEqual(Bip84.SpecName(), "BIP-0084")

    # Run all tests in test vector using FromSeed for construction
    def test_vector_from_seed(self):
        for test in TEST_VECTOR:
            # Create from seed
            bip_obj_ctx = Bip84.FromSeed(binascii.unhexlify(test["seed"]), test["coin"])

            # Test coin names and test net flag
            coin_names = bip_obj_ctx.CoinNames()
            self.assertEqual(test["names"], (coin_names["name"], coin_names["abbr"]))
            self.assertEqual(test["is_testnet"], bip_obj_ctx.IsTestNet())

            # Test master key
            self.assertEqual(test["ex_master"] , bip_obj_ctx.PrivateKey().ToExtended())
            self.assertEqual(test["wif_master"], bip_obj_ctx.PrivateKey().ToWif())
            self.assertTrue(bip_obj_ctx.IsMasterLevel())

            # Derive account
            bip_obj_ctx = bip_obj_ctx.Purpose().Coin().Account(0)
            # Test account keys
            self.assertEqual(test["account"]["ex_pub"] , bip_obj_ctx.PublicKey().ToExtended())
            self.assertEqual(test["account"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())
            self.assertTrue(bip_obj_ctx.IsAccountLevel())

            # Derive external chain
            bip_obj_ctx = bip_obj_ctx.Change(Bip44Changes.CHAIN_EXT)
            # Test external chain keys
            self.assertEqual(test["chain_ext"]["ex_pub"] , bip_obj_ctx.PublicKey().ToExtended())
            self.assertEqual(test["chain_ext"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())
            self.assertTrue(bip_obj_ctx.IsChangeLevel())

            # Test external chain addresses
            for i in range(len(test["addresses"])):
                bip_obj_addr_ctx = bip_obj_ctx.AddressIndex(i)
                self.assertEqual(test["addresses"][i], bip_obj_addr_ctx.PublicKey().ToAddress())
                self.assertTrue(bip_obj_addr_ctx.IsAddressIndexLevel())

    # Run all tests in test vector using FromExtendedKey for construction
    def test_vector_from_exkey(self):
        for test in TEST_VECTOR:
            # Create from private master key
            bip_obj_ctx = Bip84.FromExtendedKey(test["ex_master"], test["coin"])
            # Test master key
            self.assertTrue(bip_obj_ctx.IsMasterLevel())
            self.assertEqual(test["ex_master"], bip_obj_ctx.PrivateKey().ToExtended())

            # Create from private account key
            bip_obj_ctx = Bip84.FromExtendedKey(test["account"]["ex_priv"], test["coin"])
            # Test account keys
            self.assertTrue(bip_obj_ctx.IsAccountLevel())
            self.assertEqual(test["account"]["ex_pub"] , bip_obj_ctx.PublicKey().ToExtended())
            self.assertEqual(test["account"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())

            # Create from private change key
            bip_obj_ctx = Bip84.FromExtendedKey(test["chain_ext"]["ex_priv"], test["coin"])
            # Test external chain keys
            self.assertFalse(bip_obj_ctx.IsPublicOnly())
            self.assertTrue(bip_obj_ctx.IsChangeLevel())
            self.assertEqual(test["chain_ext"]["ex_pub"] , bip_obj_ctx.PublicKey().ToExtended())
            self.assertEqual(test["chain_ext"]["ex_priv"], bip_obj_ctx.PrivateKey().ToExtended())

            # Create from public change key
            bip_obj_ctx = Bip84.FromExtendedKey(test["chain_ext"]["ex_pub"], test["coin"])
            self.assertTrue(bip_obj_ctx.IsPublicOnly())
            self.assertTrue(bip_obj_ctx.IsChangeLevel())
            self.assertEqual(test["chain_ext"]["ex_pub"] , bip_obj_ctx.PublicKey().ToExtended())
            self.assertRaises(Bip32KeyError, bip_obj_ctx.PrivateKey)

    # Test different key formats
    def test_key_formats(self):
        test_data = TEST_KEY_FORMATS

        # Create from seed
        bip_obj_ctx = Bip84.FromSeed(binascii.unhexlify(test_data["seed"]), test_data["coin"])
        # Check private key formats
        self.assertEqual(test_data["ex_priv"] , bip_obj_ctx.PrivateKey().ToExtended())
        self.assertEqual(test_data["raw_priv"], bip_obj_ctx.PrivateKey().Raw().ToHex())
        # Check public key formats
        self.assertEqual(test_data["ex_pub"] , bip_obj_ctx.PublicKey().ToExtended())
        self.assertEqual(test_data["raw_compr_pub"], bip_obj_ctx.PublicKey().RawCompressed().ToHex())
        self.assertEqual(test_data["raw_uncompr_pub"], bip_obj_ctx.PublicKey().RawUncompressed().ToHex())
        # Invalid parameters
        self.assertRaises(TypeError, bip_obj_ctx.PrivateKey, 0)
        self.assertRaises(TypeError, bip_obj_ctx.PublicKey , 0)

    # Test construction from extended keys with valid and invalid depths
    def test_from_exkey_depth(self):
        test_data = TEST_EXKEY_DEPTHS

        # Private key with depth 5 shall not raise exception
        Bip84.FromExtendedKey(test_data["ex_priv_5"], Bip44Coins.BITCOIN)
        # Private key with depth 6 shall raise exception
        self.assertRaises(Bip44DepthError, Bip84.FromExtendedKey, test_data["ex_priv_6"], Bip44Coins.BITCOIN)

        # Public key with depth 3 shall raise exception
        self.assertRaises(Bip44DepthError, Bip84.FromExtendedKey, test_data["ex_pub_2"], Bip44Coins.BITCOIN)
        # Public key with depth 4 or 5 shall not raise exception
        Bip84.FromExtendedKey(test_data["ex_pub_3"], Bip44Coins.BITCOIN)
        Bip84.FromExtendedKey(test_data["ex_pub_5"], Bip44Coins.BITCOIN)
        # Public key with depth 6 shall raise exception
        self.assertRaises(Bip44DepthError, Bip84.FromExtendedKey, test_data["ex_pub_6"], Bip44Coins.BITCOIN)

    # Test invalid coin derivations
    def test_invalid_coins(self):
        seed_bytes = b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

        # Try to construct from not accepted coins
        self.assertRaises(ValueError, Bip84.FromSeed, binascii.unhexlify(seed_bytes), Bip44Coins.DOGECOIN)
        self.assertRaises(ValueError, Bip84.FromSeed, binascii.unhexlify(seed_bytes), Bip44Coins.DOGECOIN_TESTNET)
        self.assertRaises(ValueError, Bip84.FromSeed, binascii.unhexlify(seed_bytes), Bip44Coins.DASH)
        self.assertRaises(ValueError, Bip84.FromSeed, binascii.unhexlify(seed_bytes), Bip44Coins.DASH_TESTNET)
        self.assertRaises(ValueError, Bip84.FromSeed, binascii.unhexlify(seed_bytes), Bip44Coins.ETHEREUM)
        self.assertRaises(ValueError, Bip84.FromSeed, binascii.unhexlify(seed_bytes), Bip44Coins.RIPPLE)
        # Exception: construct from invalid type
        self.assertRaises(TypeError, Bip84.FromSeed, binascii.unhexlify(seed_bytes), 0)

        # Accepted coins
        self.assertTrue(Bip84.IsCoinAllowed(Bip44Coins.BITCOIN))
        self.assertTrue(Bip84.IsCoinAllowed(Bip44Coins.LITECOIN))
        self.assertTrue(Bip84.IsCoinAllowed(Bip44Coins.BITCOIN_TESTNET))
        self.assertTrue(Bip84.IsCoinAllowed(Bip44Coins.LITECOIN_TESTNET))
        # Not accepted coins
        self.assertFalse(Bip84.IsCoinAllowed(Bip44Coins.DOGECOIN))
        self.assertFalse(Bip84.IsCoinAllowed(Bip44Coins.DASH))
        self.assertFalse(Bip84.IsCoinAllowed(Bip44Coins.DOGECOIN_TESTNET))
        self.assertFalse(Bip84.IsCoinAllowed(Bip44Coins.DASH_TESTNET))
        self.assertFalse(Bip84.IsCoinAllowed(Bip44Coins.ETHEREUM))
        self.assertFalse(Bip84.IsCoinAllowed(Bip44Coins.RIPPLE))
        # Invalid type
        self.assertRaises(TypeError, Bip84.IsCoinAllowed, 0)

    # Test invalid path derivations
    def test_invalid_derivations(self):
        seed_bytes = b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

        # Create all the derivations
        bip_obj_mst    = Bip84.FromSeed(binascii.unhexlify(seed_bytes), Bip44Coins.BITCOIN)
        bip_obj_prp    = bip_obj_mst.Purpose()
        bip_obj_coin   = bip_obj_prp.Coin()
        bip_obj_acc    = bip_obj_coin.Account(0)
        bip_obj_change = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip_obj_addr   = bip_obj_change.AddressIndex(0)

        # Invalid change type
        self.assertRaises(TypeError, bip_obj_acc.Change, 0)
        # Invalid derivation from master
        self.assertRaises(Bip44DepthError, bip_obj_mst.Coin)
        self.assertRaises(Bip44DepthError, bip_obj_mst.Account     , 0)
        self.assertRaises(Bip44DepthError, bip_obj_mst.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(Bip44DepthError, bip_obj_mst.AddressIndex, 0)
        # Invalid derivation from purpose
        self.assertRaises(Bip44DepthError, bip_obj_prp.Purpose)
        self.assertRaises(Bip44DepthError, bip_obj_prp.Account     , 0)
        self.assertRaises(Bip44DepthError, bip_obj_prp.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(Bip44DepthError, bip_obj_prp.AddressIndex, 0)
        # Invalid derivation from coin
        self.assertRaises(Bip44DepthError, bip_obj_coin.Purpose)
        self.assertRaises(Bip44DepthError, bip_obj_coin.Coin)
        self.assertRaises(Bip44DepthError, bip_obj_coin.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(Bip44DepthError, bip_obj_coin.AddressIndex, 0)
        # Invalid derivation from account
        self.assertRaises(Bip44DepthError, bip_obj_acc.Purpose)
        self.assertRaises(Bip44DepthError, bip_obj_acc.Coin)
        self.assertRaises(Bip44DepthError, bip_obj_acc.Account     , 0)
        self.assertRaises(Bip44DepthError, bip_obj_acc.AddressIndex, 0)
        # Invalid derivation from chain
        self.assertRaises(Bip44DepthError, bip_obj_change.Purpose)
        self.assertRaises(Bip44DepthError, bip_obj_change.Coin)
        self.assertRaises(Bip44DepthError, bip_obj_change.Account, 0)
        self.assertRaises(Bip44DepthError, bip_obj_change.Change , Bip44Changes.CHAIN_EXT)
        # Invalid derivation from address index
        self.assertRaises(Bip44DepthError, bip_obj_addr.Purpose)
        self.assertRaises(Bip44DepthError, bip_obj_addr.Coin)
        self.assertRaises(Bip44DepthError, bip_obj_addr.Account     , 0)
        self.assertRaises(Bip44DepthError, bip_obj_addr.Change      , Bip44Changes.CHAIN_EXT)
        self.assertRaises(Bip44DepthError, bip_obj_addr.AddressIndex, 0)
