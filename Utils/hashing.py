#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
哈希算法工具类
"""

import hashlib

class HashUtils:
    def __init__(self):
        """初始化哈希工具"""
        pass
    
    def calculate_hash(self, password, algorithm):
        """
        计算密码的哈希值
        
        Args:
            password (str): 原始密码
            algorithm (str): 哈希算法，支持多种哈希算法
        
        Returns:
            str: 计算得到的哈希值
        """
        # 转换为小写
        algorithm = algorithm.lower()
        
        # 计算哈希
        if algorithm == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif algorithm == 'sha224':
            return hashlib.sha224(password.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif algorithm == 'sha384':
            return hashlib.sha384(password.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        elif algorithm == 'sha3_224':
            return hashlib.sha3_224(password.encode()).hexdigest()
        elif algorithm == 'sha3_256':
            return hashlib.sha3_256(password.encode()).hexdigest()
        elif algorithm == 'sha3_384':
            return hashlib.sha3_384(password.encode()).hexdigest()
        elif algorithm == 'sha3_512':
            return hashlib.sha3_512(password.encode()).hexdigest()
        elif algorithm == 'blake2b':
            return hashlib.blake2b(password.encode()).hexdigest()
        elif algorithm == 'blake2s':
            return hashlib.blake2s(password.encode()).hexdigest()
        elif algorithm == 'md4':
            # 使用pycryptodome库的MD4实现
            try:
                from Crypto.Hash import MD4
                h = MD4.new()
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持MD4算法")
        elif algorithm == 'ripemd160':
            # 使用pycryptodome库的RIPEMD160实现
            try:
                from Crypto.Hash import RIPEMD160
                h = RIPEMD160.new()
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持RIPEMD160算法")
        elif algorithm == 'whirlpool':
            # 使用pycryptodome库的Whirlpool实现
            try:
                from Crypto.Hash import Whirlpool
                h = Whirlpool.new()
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持Whirlpool算法")
        elif algorithm == 'tiger192_3':
            # 使用pycryptodome库的Tiger实现
            try:
                from Crypto.Hash import Tiger
                h = Tiger.new()
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持Tiger算法")
        elif algorithm == 'snefru':
            # 使用pycryptodome库的Snefru实现
            try:
                from Crypto.Hash import Snefru
                h = Snefru.new()
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持Snefru算法")
        elif algorithm == 'gost':
            # 使用pycryptodome库的GOST实现
            try:
                from Crypto.Hash import GOST
                h = GOST.new()
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持GOST算法")
        elif algorithm == 'adler32':
            import zlib
            return hex(zlib.adler32(password.encode()))[2:]
        elif algorithm == 'crc32':
            import zlib
            return hex(zlib.crc32(password.encode()))[2:]
        elif algorithm == 'crc32b':
            import binascii
            return hex(binascii.crc32(password.encode()))[2:]
        elif algorithm == 'haval128_3':
            # 使用pycryptodome库的HAVAL实现
            try:
                from Crypto.Hash import HAVAL
                h = HAVAL.new(digest_bits=128, rounds=3)
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持HAVAL算法")
        elif algorithm == 'haval160_3':
            # 使用pycryptodome库的HAVAL实现
            try:
                from Crypto.Hash import HAVAL
                h = HAVAL.new(digest_bits=160, rounds=3)
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持HAVAL算法")
        elif algorithm == 'haval192_3':
            # 使用pycryptodome库的HAVAL实现
            try:
                from Crypto.Hash import HAVAL
                h = HAVAL.new(digest_bits=192, rounds=3)
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持HAVAL算法")
        elif algorithm == 'haval224_3':
            # 使用pycryptodome库的HAVAL实现
            try:
                from Crypto.Hash import HAVAL
                h = HAVAL.new(digest_bits=224, rounds=3)
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持HAVAL算法")
        elif algorithm == 'haval256_3':
            # 使用pycryptodome库的HAVAL实现
            try:
                from Crypto.Hash import HAVAL
                h = HAVAL.new(digest_bits=256, rounds=3)
                h.update(password.encode())
                return h.hexdigest()
            except ImportError:
                raise ValueError("需要安装pycryptodome库来支持HAVAL算法")
        else:
            raise ValueError(f"不支持的哈希算法: {algorithm}")
    
    def detect_hash_type(self, hash_value):
        """
        根据哈希值长度检测可能的哈希算法
        
        Args:
            hash_value (str): 哈希值
        
        Returns:
            list: 可能的哈希算法列表
        """
        hash_length = len(hash_value)
        possible_algorithms = []
        
        if hash_length == 32:
            possible_algorithms.extend(['md5', 'blake2s'])
        elif hash_length == 40:
            possible_algorithms.extend(['sha1', 'ripemd160'])
        elif hash_length == 56:
            possible_algorithms.append('sha224')
        elif hash_length == 64:
            possible_algorithms.extend(['sha256', 'sha3_256'])
        elif hash_length == 96:
            possible_algorithms.extend(['sha384', 'sha3_384'])
        elif hash_length == 128:
            possible_algorithms.extend(['sha512', 'sha3_512', 'blake2b'])
        elif hash_length == 8:
            possible_algorithms.extend(['adler32', 'crc32', 'crc32b'])
        elif hash_length == 40:
            possible_algorithms.append('tiger192_3')
        elif hash_length == 64:
            possible_algorithms.append('whirlpool')
        elif hash_length == 32:
            possible_algorithms.append('haval128_3')
        elif hash_length == 40:
            possible_algorithms.append('haval160_3')
        elif hash_length == 48:
            possible_algorithms.append('haval192_3')
        elif hash_length == 56:
            possible_algorithms.append('haval224_3')
        elif hash_length == 64:
            possible_algorithms.append('haval256_3')
        
        return possible_algorithms
