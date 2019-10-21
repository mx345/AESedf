#!/usr/bin/env python
# -*- coding=utf-8 -*-
"""
AES加密解密工具类
@author jzx
@date   2018/10/24
此工具类加密解密结果与 http://tool.chacuo.net/cryptaes 结果一致
数据块128位
key 为16位
iv 为16位，且与key相等
字符集utf-8
输出为base64
AES加密模式 为cbc
填充 pkcs7padding
"""

# import base64
import sys,os
from Crypto.Cipher import AES

# import random


def padding(origin_data):
    bs = AES.block_size  # 16
    length = len(origin_data)
    padding_size = bs - length % bs
    padding_data = bytes(chr(padding_size), encoding="ASCII") * padding_size
    return origin_data + padding_data

def unpadding(origin_data):
    padding_size = origin_data[-1]
    return origin_data[:-padding_size]  

def encrypt(key, data):
    key_bytes = key.encode()
    key_bytes = key_bytes + (16 - len(key_bytes)) * b'\0'
    iv = bytes(reversed(key_bytes))
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # 处理明文
    data_padding = padding(data)
    # 加密
    encrypt_bytes = cipher.encrypt(data_padding)
    return encrypt_bytes  

def decrypt(key, data):
    key_bytes = key.encode()
    key_bytes = key_bytes + (16 - len(key_bytes)) * b'\0'
    iv = bytes(reversed(key_bytes))
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # 解密
    decrypt_bytes = cipher.decrypt(data)
    # 去除填充内容
    result = unpadding(decrypt_bytes)
    return result


def main():
    op = sys.argv[1]
    key = sys.argv[2]
    file_path = sys.argv[3]

    with open(file_path, "rb") as f:
        if op == "-e":
            data = encrypt(key, f.read())
            dst_file_path = file_path + ".dj"
            
            
        elif op == "-d":
            data = decrypt(key, f.read())

            if file_path[-3:] == ".dj":
                dst_file_path = file_path[:-3]
            else:
                dst_file_path = file_path + ".dj"
    os.remove(file_path)

    with open(dst_file_path, "wb") as f:
        f.write(data)


if __name__ == '__main__':
    main()




