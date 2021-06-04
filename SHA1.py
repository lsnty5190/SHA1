'''
Author: your name
Date: 2021-06-03 19:46:54
LastEditTime: 2021-06-04 15:38:25
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \第十次作业\SHA1.py
'''
from hashlib import sha1
import math

class SHA1():

    def __init__(self) -> None:
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0
    
    def reset(self):
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0
    '''
    @description: 
    @param {*} data is a bits string
    @return {*} preprocessed data
    '''
    def preprocess(self, data):

        # data = data.encode('utf-8').hex()
        data = data.zfill(math.ceil(len(data) / 8) * 8)

        # append the bit '1' to the message
        data += '1'

        # len_data is the length of message before pre-processing
        len_data = len(data) - 1
        dis = len(data) % 512

        # append k bits 0, where k is the minimum number >=0, 
        # such that the resulting message length (in bits) is 
        # congruent to 448 (mod 512)
        if dis < 448:
            data += '0' * (448 - dis)
        elif dis > 448:
            data += '0' * (512 - dis + 448)

        # append length of message (before pre-processing in bits)
        # as 64-bit big-endian integer
        len_data = bin(len_data)[2:].zfill(64)
        data += len_data

        return data

    '''
    @description: Process the message in succesive 512-bit chunks
    @param {*} data: Input message bits
    @return {*} result of sha1
    '''
    def process(self, data):

        # break message into 512-bit chunks
        chunks = [data[i:i+512] for i in range(0, len(data), 512)]

        for chunk in chunks:

            # break chunk into 16 * 32-bit big-endian words w[i]
            # (i from 0 to 15)
            w = [chunk[i:i+32] for i in range(0, 512, 32)]

            # extend the 16 * 32-bits words into 80 * 32-bits words
            for i in range(16, 80):
                tmp = int(w[i-3], 2) ^ int(w[i-8], 2) ^ int(w[i-14], 2) ^ int(w[i-16], 2)
                w.append(bin(tmp)[2:].zfill(32))

                # leftrotate 1 bit
                w[i] = w[i][1:] + w[i][0]

            # Initialize hash value for this chunk
            a = self.h0
            b = self.h1
            c = self.h2
            d = self.h3
            e = self.h4

            for i in range(0, 80):
                if i >= 0 and i <= 19:
                    f = (b & c) | (~b & d)
                    k = 0x5A827999
                elif i >= 20 and i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif i >= 40 and i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif i >= 60 and i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                
                # leftrotate 5 bits of a
                left_a = int(bin(a)[2:].zfill(32)[5:] + bin(a)[2:].zfill(32)[0:5], 2)
                # for tmp may be larger than 2^32
                # remember to mod 2^32 in advance
                tmp = (left_a + f + e + k + int(w[i], 2)) % (2 ** 32)

                e = d
                d = c
                c = int(bin(b)[2:].zfill(32)[30:] + bin(b)[2:].zfill(32)[0:30], 2)
                b = a
                a = tmp

            self.h0 = (self.h0 + a) % (2 ** 32)
            self.h1 = (self.h1 + b) % (2 ** 32)
            self.h2 = (self.h2 + c) % (2 ** 32)
            self.h3 = (self.h3 + d) % (2 ** 32)
            self.h4 = (self.h4 + e) % (2 ** 32)

        # Produce the final hash value
        digest = bin(self.h0)[2:].zfill(32) + bin(self.h1)[2:].zfill(32) + bin(self.h2)[2:].zfill(32) + bin(self.h3)[2:].zfill(32) + bin(self.h4)[2:].zfill(32)

        return int(digest, 2)

    '''
    @description: 
    @param {*} M is a message string
    @return {*} SHA1(M)
    '''
    def exe_sha1(self, M, encode=True):
        
        if encode:
            # encode message to bits string
            M = int(M.encode('utf-8').hex(), 16)
            M = bin(M)[2:]
        # preprocess
        data = self.preprocess(M)
        # print(data)
        # main loop
        digest = self.process(data)
        # print(hex(digest)[2:])
        return digest

def test(data):
    
    # using hashlib.sha1 for test
    # print(data.encode('utf-8').hex())
    hash = sha1()
    hash.update(data)
    re = int(hash.hexdigest(), 16)
    return re

if __name__ == '__main__':

    # M = 'School of Cyber Science and Technology'
    M = '001101110011100100100101001101110011011100110111010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111001101111001101001001001011011100110011010111011100101001001111100110100111111000001011100110101111100000110010101110111010001010011010100111011011110010000101100'
    
    sha_test = SHA1().exe_sha1(M, encode=False)
    print('Our SHA1: ', sha_test)

    M = int(M, 2).to_bytes(math.ceil(len(M) / 8), 'big')
    sha1_std = test(M)
    print('Std SHA1: ', sha1_std)

    print(hex(sha1_std))
    assert sha1_std == sha_test