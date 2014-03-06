'''
@author: Armando Vega

Modul koji sadrzi klase i konstante potrebne za rad sa podacima (kriptografija, kodiranje podataka)
'''

import base64
import hashlib
from Crypto.Cipher import AES

# postavljamo vrijednosti konstanti
ALGO_AES = 2
ALGO_ROT13 = 1
ALGO_PLAIN = 0
# karakter koji se koristi za padding na trazenu duzinu (AES trazi 32byte blokove)
PADDING = '{'

class DataMangler:
    '''
        Klasa koja sadrzi funkcionalnost potrebnu za enkripciju/dekripciju
        te kodiranje i dekodiranje podataka
    '''
    def __init__(self, data=''):
        self.raw_data = data
        # generiramo novi kriptokljuc 128bit (privremeno samo)
        self.cipher = AES.new('thisisa16bytekey')
    
    def obfuscate(self, password='thisisapassword', algo=0):
        # enkripcija i enkodiranje podataka
        if algo == ALGO_AES:
            # AES
            # iz 128bit passworda generiramo 256bit hash
            secret = hashlib.sha256(password).digest()
            self.cipher = AES.new(secret)
            # dodajemo padding, kriptiramo 256bitnom enkripcijom i enkodiramo podatke
            obfuscated = self.encode(self.AESencrypt(self.add_padding(self.raw_data)))
        elif algo == ALGO_ROT13:
            # ROT13
            # enkripcija supstitucijskom sifrom (rotacija abecede za 13 karaktera)
            obfuscated = self.encode(self.raw_data.encode('rot13'))
        else:
            # BEZ ENKRIPCIJE
            # podatke samo enkodiramo
            obfuscated = self.encode(self.raw_data)
        return obfuscated
    
    def deobfuscate(self, password='thisisapassword', algo=0):
        # dekodiranje i dekripcija podataka
        if algo == ALGO_AES:
            # AES
            secret = hashlib.sha256(password).digest()
            self.cipher = AES.new(secret)
            # dekodiramo, dekriptiramo i skidamo padding
            deobfuscated = self.remove_padding(self.AESdecrypt(self.decode(self.raw_data)))
        elif algo == ALGO_ROT13:
            # ROT13
            # dekriptiramo i dekodiramo podatke
            deobfuscated = self.decode(self.raw_data).decode('rot13')
        else:
            # BEZ ENKRIPCIJE
            # samo dekodiramo podatke
            deobfuscated = self.decode(self.raw_data)
        return deobfuscated
    
    def add_padding(self, data):
        # dodavanje paddinga na podatke (potrebno za AES)
        return data + (32 - len(data) % 32) * PADDING
    
    def remove_padding(self, data):
        # uklanjanje paddinga
        return data.rstrip(PADDING)
    
    def encode(self, data):
        # base64 enkodiranje podataka (64 standardna ASCII znaka, pogodno za mrezni transfer preko svih tekstualnih protokola)
        return base64.b64encode(data)
    
    def decode(self, data):
        # base64 dekodiranje podataka
        return base64.b64decode(data)
    
    def AESencrypt(self, data):
        # kriptiranje podataka AES sifrom
        return self.cipher.encrypt(data)
    
    def AESdecrypt(self, data):
        # dekriptiranje podataka AES sifrom
        return self.cipher.decrypt(data)
    
    

if __name__ == '__main__':
    # ako modul nije includean nego se pozove sam ne radi nista
    pass
    
    