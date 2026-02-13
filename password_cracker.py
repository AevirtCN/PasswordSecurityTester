#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码爆破模块
"""

import hashlib
import time
import itertools
from utils.wordlist import WordlistManager
from utils.hashing import HashUtils

class PasswordCracker:
    def __init__(self):
        """初始化密码破解器"""
        self.wordlist_manager = WordlistManager()
        self.hash_utils = HashUtils()
    
    def dictionary_attack(self, target_hash, wordlist_path, algorithm):
        """
        字典攻击
        
        Args:
            target_hash (str): 目标哈希值
            wordlist_path (str): 字典文件路径，使用'default'表示内置字典
            algorithm (str): 哈希算法
        
        Returns:
            dict or None: 成功返回包含密码、尝试次数和耗时的字典，失败返回None
        """
        start_time = time.time()
        attempts = 0
        
        try:
            # 获取字典
            wordlist = self.wordlist_manager.get_wordlist(wordlist_path)
            
            # 遍历字典
            for password in wordlist:
                password = password.strip()
                attempts += 1
                
                # 计算哈希
                hash_value = self.hash_utils.calculate_hash(password, algorithm)
                
                # 比较哈希
                if hash_value == target_hash:
                    end_time = time.time()
                    return {
                        'password': password,
                        'attempts': attempts,
                        'time': end_time - start_time
                    }
            
            return None
        except Exception as e:
            print(f"字典攻击出错: {e}")
            return None
    
    def brute_force_attack(self, target_hash, charset, min_length, max_length, algorithm):
        """
        暴力破解
        
        Args:
            target_hash (str): 目标哈希值
            charset (str): 字符集
            min_length (int): 最小长度
            max_length (int): 最大长度
            algorithm (str): 哈希算法
        
        Returns:
            dict or None: 成功返回包含密码、尝试次数和耗时的字典，失败返回None
        """
        start_time = time.time()
        attempts = 0
        
        try:
            # 遍历长度
            for length in range(min_length, max_length + 1):
                # 生成所有组合
                for password_tuple in itertools.product(charset, repeat=length):
                    password = ''.join(password_tuple)
                    attempts += 1
                    
                    # 计算哈希
                    hash_value = self.hash_utils.calculate_hash(password, algorithm)
                    
                    # 比较哈希
                    if hash_value == target_hash:
                        end_time = time.time()
                        return {
                            'password': password,
                            'attempts': attempts,
                            'time': end_time - start_time
                        }
            
            return None
        except Exception as e:
            print(f"暴力破解出错: {e}")
            return None
    
    def mask_attack(self, target_hash, mask, charset, algorithm):
        """
        掩码攻击
        
        Args:
            target_hash (str): 目标哈希值
            mask (str): 掩码，使用'?'表示可变字符
            charset (str): 字符集
            algorithm (str): 哈希算法
        
        Returns:
            dict or None: 成功返回包含密码、尝试次数和耗时的字典，失败返回None
        """
        start_time = time.time()
        attempts = 0
        
        try:
            # 计算掩码中的可变位置
            mask_positions = [i for i, char in enumerate(mask) if char == '?']
            mask_length = len(mask_positions)
            
            if mask_length == 0:
                # 没有可变位置，直接尝试
                password = mask
                hash_value = self.hash_utils.calculate_hash(password, algorithm)
                if hash_value == target_hash:
                    end_time = time.time()
                    return {
                        'password': password,
                        'attempts': 1,
                        'time': end_time - start_time
                    }
                return None
            
            # 生成所有组合
            for combo in itertools.product(charset, repeat=mask_length):
                attempts += 1
                
                # 构建密码
                password_list = list(mask)
                for i, char in zip(mask_positions, combo):
                    password_list[i] = char
                password = ''.join(password_list)
                
                # 计算哈希
                hash_value = self.hash_utils.calculate_hash(password, algorithm)
                
                # 比较哈希
                if hash_value == target_hash:
                    end_time = time.time()
                    return {
                        'password': password,
                        'attempts': attempts,
                        'time': end_time - start_time
                    }
            
            return None
        except Exception as e:
            print(f"掩码攻击出错: {e}")
            return None
