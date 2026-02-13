#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加密方式测试模块
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils'))

import time
from wordlist import WordlistManager
from hashing import HashUtils

class EncryptionTester:
    def __init__(self):
        """初始化加密测试器"""
        self.wordlist_manager = WordlistManager()
        self.hash_utils = HashUtils()
    
    def single_encryption_attack(self, target_hash, algorithm, wordlist_path):
        """
        单加密方式爆破
        
        Args:
            target_hash (str): 目标哈希值
            algorithm (str): 加密算法
            wordlist_path (str): 字典文件路径，使用'default'表示内置字典
        
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
            print(f"单加密攻击出错: {e}")
            return None
    
    def hybrid_encryption_attack(self, target_hash, encryption_chain, wordlist_path):
        """
        混合加密方式爆破
        
        Args:
            target_hash (str): 目标哈希值
            encryption_chain (list): 加密链，如 ['md5', 'sha256']
            wordlist_path (str): 字典文件路径，使用'default'表示内置字典
        
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
                
                # 计算混合哈希
                hash_value = self.calculate_hybrid_hash(password, encryption_chain)
                
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
            print(f"混合加密攻击出错: {e}")
            return None
    
    def calculate_hybrid_hash(self, password, encryption_chain):
        """
        计算混合哈希
        
        Args:
            password (str): 原始密码
            encryption_chain (list): 加密链
        
        Returns:
            str: 最终的哈希值
        """
        current_value = password
        
        for algorithm in encryption_chain:
            current_value = self.hash_utils.calculate_hash(current_value, algorithm)
        
        return current_value
    
    def analyze_encryption_strength(self, hash_value):
        """
        分析加密强度
        
        Args:
            hash_value (str): 哈希值
        
        Returns:
            dict: 加密强度分析结果
        """
        # 根据哈希长度判断可能的算法
        hash_length = len(hash_value)
        possible_algorithms = []
        
        if hash_length == 32:
            possible_algorithms.append('MD5')
        elif hash_length == 40:
            possible_algorithms.append('SHA1')
        elif hash_length == 64:
            possible_algorithms.append('SHA256')
        elif hash_length == 128:
            possible_algorithms.append('SHA512')
        
        # 分析强度
        if len(possible_algorithms) == 0:
            strength = "未知"
            recommendation = "无法确定加密算法，建议使用更强的加密方式"
        elif 'MD5' in possible_algorithms:
            strength = "弱"
            recommendation = "MD5已被破解，建议使用SHA256或更强的加密算法"
        elif 'SHA1' in possible_algorithms:
            strength = "中"
            recommendation = "SHA1安全性降低，建议使用SHA256或更强的加密算法"
        else:
            strength = "强"
            recommendation = "当前加密算法安全性较高"
        
        return {
            'possible_algorithms': possible_algorithms,
            'strength': strength,
            'recommendation': recommendation
        }
