'''
Author: your name
Date: 2021-06-04 10:43:46
LastEditTime: 2021-06-04 15:39:14
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \第十次作业\HMAC-SHA1.py
'''
from SHA1 import SHA1
import hmac
import math
import hashlib
import struct

class HMAC_SHA1():
    
    def __init__(self) -> None:
        
        # define the blocksize
        self.blocksize = 512 # bits, also 64 bytes
    
    def process(self, key, message):
        # convert key to bits string
        key = int(key.encode('utf-8').hex(), 16)
        key = bin(key)[2:]
        key = key.zfill(math.ceil(len(key) / 8) * 8)
        

        # convert message to bits string
        message = int(message.encode('utf-8').hex(), 16)
        message = bin(message)[2:]
        message = message.zfill(math.ceil(len(message) / 8) * 8)

        # define the type of hash function
        hash = SHA1()

        # Keys longer than blockSize are shortened by hashing them
        if len(key) > self.blocksize:
            key = bin(hash.exe_sha1(key))[2:].zfill(160)
        # Keys shorter than blockSize are padded to blockSize 
        # by padding with zeros on the right
        elif len(key) < self.blocksize:
            key = self.pad(key)

        o_key_pad = bin(int(key, 2) ^ int('5c' * (self.blocksize // 8), 16))[2:]
        o_key_pad = o_key_pad.zfill(math.ceil(len(o_key_pad) / 8) * 8)
        i_key_pad = bin(int(key, 2) ^ int('36' * (self.blocksize // 8), 16))[2:]
        i_key_pad = i_key_pad.zfill(math.ceil(len(i_key_pad) / 8) * 8)

        in_digest = hash.exe_sha1(i_key_pad + message, encode=False)
        in_hashed = bin(in_digest)[2:].zfill(160)       
        
        # remember to reset the sha1 class
        hash.reset()
        out_disgest = hash.exe_sha1(o_key_pad + in_hashed, encode=False)
    
        return out_disgest

    def pad(self, key):
        
        dis = self.blocksize - len(key)
        key += '0' * dis
        return key

def test(key, message):
    digester = hmac.new(bytes(key, 'utf-8'), bytes(message, 'utf-8'), hashlib.sha1)
    print(digester.hexdigest())

if __name__ == '__main__':
    HMAC_SHA1_test = HMAC_SHA1()
    digest = HMAC_SHA1_test.process("key", "The quick brown fox jumps over the lazy dog")
    print(hex(digest))
    #test("key", "The quick brown fox jumps over the lazy dog")