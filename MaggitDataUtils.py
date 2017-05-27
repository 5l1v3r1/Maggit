
#  This file is part of Maggit.
#  
#  Maggit - ICMP tunneling for fun and no profit
#  Copyright (C) 2014 Armando Vega
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.


import base64
import hashlib
from Crypto.Cipher import AES

# set up some constants
ALGO_AES = 2
ALGO_ROT13 = 1
ALGO_PLAIN = 0
# character to use for padding (AES needs 32byte blocks)
PADDING = '{'

class DataMangler:
    '''
        Handles data encryption / decryption and encoding / decoding
    '''
    def __init__(self, data=''):
        self.raw_data = data
        # generate a temporary 128bit key
        self.cipher = AES.new('thisisa16bytekey')
    
    def obfuscate(self, password='thisisapassword', algo=0):
        # encrypting and encoding the data
        if algo == ALGO_AES:
            # AES
            # generate a 256bit hash from the 128bit password
            secret = hashlib.sha256(password).digest()
            self.cipher = AES.new(secret)
            # add padding, encrypt with 256bits and encode the data
            obfuscated = self.encode(self.AESencrypt(self.add_padding(self.raw_data)))
        elif algo == ALGO_ROT13:
            # ROT13
            # encrypt using the ROT13 supstitution cypher
            obfuscated = self.encode(self.raw_data.encode('rot13'))
        else:
            # NO ENCRYPTION
            # data is only encoded
            obfuscated = self.encode(self.raw_data)
        return obfuscated
    
    def deobfuscate(self, password='thisisapassword', algo=0):
        # decoding and decrypting the data
        if algo == ALGO_AES:
            # AES
            secret = hashlib.sha256(password).digest()
            self.cipher = AES.new(secret)
            # decode, decrypt and remove the padding
            deobfuscated = self.remove_padding(self.AESdecrypt(self.decode(self.raw_data)))
        elif algo == ALGO_ROT13:
            # ROT13
            # decrypt and decode the data
            deobfuscated = self.decode(self.raw_data).decode('rot13')
        else:
            # NO ENCRYPTION
            # just decode the data
            deobfuscated = self.decode(self.raw_data)
        return deobfuscated
    
    def add_padding(self, data):
        # pad the data for AES
        return data + (32 - len(data) % 32) * PADDING
    
    def remove_padding(self, data):
        # padding removal
        return data.rstrip(PADDING)
    
    def encode(self, data):
        # base64 encoding (64 standard ASCII characters, useful for network transfer over all textual protocols)
        return base64.b64encode(data)
    
    def decode(self, data):
        # base64 decoding
        return base64.b64decode(data)
    
    def AESencrypt(self, data):
        # AES encrypts the data
        return self.cipher.encrypt(data)
    
    def AESdecrypt(self, data):
        # AES decrypts the data
        return self.cipher.decrypt(data)
    
    

if __name__ == '__main__':
    # do nothing if run directly
    pass
    
    
