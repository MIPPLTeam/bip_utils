from bip_utils import (
    Bip39ChecksumError, Bip39Languages, Bip39WordsNum, Bip39MnemonicGenerator, Bip39MnemonicValidator, Bip39MnemonicDecoder,Bip39SeedGenerator, Bip32Secp256k1
)
from bip_utils.utils import mnemonic
def __main__():
    mnemonic = "excuse page hundred clock bonus gold chase album sketch talk axis ankle"
    is_valid = Bip39MnemonicValidator().IsValid(mnemonic)
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
    # Print master key in extended format
    print(bip32_ctx.PrivateKey().ToExtended())

if __name__ == "__main__":
    __main__()
