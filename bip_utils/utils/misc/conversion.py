# Copyright (c) 2021 Emanuele Bellocchia
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

"""Module with some conversion utility functions."""

# Imports
import binascii
import unicodedata
from typing import List, Optional, Union
from bip_utils.utils.misc.algo import AlgoUtils


class ConvUtils:
    """Class container for conversion utility functions."""

    @staticmethod
    def ReverseBytes(data_bytes: bytes) -> bytes:
        """
        Reverse the specified bytes.

        Args:
            data_bytes (bytes): Data bytes

        Returns:
            bytes: Original bytes in the reverse order
        """
        tmp = bytearray(data_bytes)
        tmp.reverse()
        return bytes(tmp)

    @staticmethod
    def XorBytes(data_bytes_1: bytes,
                 data_bytes_2: bytes) -> bytes:
        """
        XOR the specified bytes.

        Args:
            data_bytes_1 (bytes): Data bytes 1
            data_bytes_2 (bytes): Data bytes 2

        Returns:
            bytes: XORed bytes
        """
        res = bytearray()
        for b1, b2 in zip(data_bytes_1, data_bytes_2):
            res.append(b1 ^ b2)
        return bytes(res)

    @staticmethod
    def BytesToInteger(data_bytes: bytes,
                       endianness: str = "big") -> int:
        """
        Convert the specified bytes to integer.

        Args:
            data_bytes (bytes)        : Data bytes
            endianness (str, optional): Endianness

        Returns:
            int: Integer representation
        """
        return int.from_bytes(data_bytes, endianness)

    @staticmethod
    def IntegerToBytes(data_int: int,
                       bytes_num: Optional[int] = None,
                       endianness: str = "big") -> bytes:
        """
        Convert integer to bytes.

        Args:
            data_int (int)            : Data integer
            bytes_num (int, optional) : Number of bytes, automatic if None
            endianness (str, optional): Endianness

        Returns:
            bytes: Bytes representation
        """

        # In case gmpy is used
        if data_int.__class__.__name__ == 'mpz':
            data_int = int(data_int)

        bytes_num = bytes_num or ((data_int.bit_length() if data_int > 0 else 1) + 7) // 8
        return data_int.to_bytes(bytes_num, endianness)

    @staticmethod
    def BytesToBinaryStr(data_bytes: bytes,
                         zero_pad_bit_len: int = 0) -> str:
        """
        Convert the specified bytes to a binary string.

        Args:
            data_bytes (bytes)              : Data bytes
            zero_pad_bit_len (int, optional): Zero pad length in bits, 0 if not specified

        Returns:
            str: Binary string
        """
        return ConvUtils.IntegerToBinaryStr(ConvUtils.BytesToInteger(data_bytes), zero_pad_bit_len)

    @staticmethod
    def BinaryStrToInteger(data: Union[bytes, str]) -> int:
        """
        Convert the specified binary string to integer.

        Args:
            data (str or bytes): Data

        Returns:
            int: Integer representation
        """
        return int(AlgoUtils.Encode(data), 2)

    @staticmethod
    def BinaryStrToBytes(data: Union[bytes, str],
                         zero_pad_byte_len: int = 0) -> bytes:
        """
        Convert the specified binary string to bytes.

        Args:
            data (str or bytes)              : Data
            zero_pad_byte_len (int, optional): Zero pad length in bytes, 0 if not specified

        Returns:
            bytes: Bytes representation
        """
        return binascii.unhexlify(hex(ConvUtils.BinaryStrToInteger(data))[2:].zfill(zero_pad_byte_len))

    @staticmethod
    def BytesToHexString(data_bytes: bytes,
                         encoding: str = "utf-8") -> str:
        """
        Convert bytes to hex string.

        Args:
            data_bytes (bytes)      : Data bytes
            encoding (str, optional): Encoding type

        Returns:
            str: Bytes converted to hex string
        """
        return AlgoUtils.Decode(binascii.hexlify(data_bytes), encoding)

    @staticmethod
    def IntegerToBinaryStr(data_int: int,
                           zero_pad_bit_len: int = 0) -> str:
        """
        Convert the specified integer to a binary string.

        Args:
            data_int (int)                  : Data integer
            zero_pad_bit_len (int, optional): Zero pad length in bits, 0 if not specified

        Returns:
            str: Binary string
        """
        return bin(data_int)[2:].zfill(zero_pad_bit_len)

    @staticmethod
    def HexStringToBytes(data: Union[bytes, str]) -> bytes:
        """
        Convert hex string to bytes.

        Args:
            data (str or bytes): Data bytes

        Returns
            bytes: Hex string converted to bytes
        """
        return binascii.unhexlify(AlgoUtils.Encode(data))

    @staticmethod
    def NormalizeNfc(data_str: str) -> str:
        """
        Normalize string using NFC.

        Args:
            data_str (str): Input string

        Returns:
            str: Normalized string
        """
        return unicodedata.normalize("NFC", data_str)

    @staticmethod
    def NormalizeNfkd(data_str: str) -> str:
        """
        Normalize string using NFKD.

        Args:
            data_str (str): Input string

        Returns:
            str: Normalized string
        """
        return unicodedata.normalize("NFKD", data_str)

    @staticmethod
    def ListToBytes(data_list: List) -> bytes:
        """
        Convert the specified list to bytes.

        Args:
            data_list (list): Data list

        Returns:
            bytes: Correspondent bytes representation
        """
        return bytes(bytearray(data_list))

    @staticmethod
    def ConvertToBits(data: Union[bytes, List[int]],
                      from_bits: int,
                      to_bits: int,
                      pad: bool = True) -> Optional[List[int]]:
        """
        Perform generic bits conversion.

        Args:
            data (list or bytes): Data to be converted
            from_bits (int)     : Number of bits to start from
            to_bits (int)       : Number of bits at the end
            pad (bool, optional): True if data must be padded, false otherwise

        Returns:
            list: List of converted bits, None in case of errors
        """

        acc = 0
        bits = 0
        ret = []
        maxv = (1 << to_bits) - 1
        max_acc = (1 << (from_bits + to_bits - 1)) - 1

        for value in data:
            if value < 0 or (value >> from_bits):
                return None
            acc = ((acc << from_bits) | value) & max_acc
            bits += from_bits
            while bits >= to_bits:
                bits -= to_bits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (to_bits - bits)) & maxv)
        elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
            return None

        return ret
