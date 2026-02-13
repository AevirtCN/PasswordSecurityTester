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
            algorithm (str): 哈希算法，支持 md5, sha1, sha256, sha512
        
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
        elif algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
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
            possible_algorithms.append('md5')
        elif hash_length == 40:
            possible_algorithms.append('sha1')
        elif hash_length == 64:
            possible_algorithms.append('sha256')
        elif hash_length == 128:
            possible_algorithms.append('sha512')
        
        return possible_algorithms
