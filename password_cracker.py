#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码爆破模块
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils'))

import hashlib
import time
import itertools
import multiprocessing

# 导入模块
from wordlist import WordlistManager
from hashing import HashUtils
from config import ConfigManager

class PasswordCracker:
    def __init__(self):
        """初始化密码破解器"""
        self.wordlist_manager = WordlistManager()
        self.hash_utils = HashUtils()
        self.config_manager = ConfigManager()
        self.process_count = self.config_manager.get('performance.process_count', 4)
        self.batch_size = self.config_manager.get('performance.batch_size', 1000)
    
    def _process_batch(self, batch, target_hash, algorithm):
        """
        处理一批密码
        
        Args:
            batch (list): 密码批次
            target_hash (str): 目标哈希值
            algorithm (str): 哈希算法
        
        Returns:
            tuple: (found, password, attempts)
        """
        found = False
        password = None
        attempts = 0
        
        for pwd in batch:
            pwd = pwd.strip()
            attempts += 1
            
            # 计算哈希
            hash_value = self.hash_utils.calculate_hash(pwd, algorithm)
            
            # 比较哈希
            if hash_value == target_hash:
                found = True
                password = pwd
                break
        
        return found, password, attempts
    
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
        total_attempts = 0
        
        try:
            # 获取字典
            wordlist = self.wordlist_manager.get_wordlist(wordlist_path)
            
            # 分批次处理
            batches = []
            current_batch = []
            
            for password in wordlist:
                current_batch.append(password)
                if len(current_batch) >= self.batch_size:
                    batches.append(current_batch)
                    current_batch = []
            
            if current_batch:
                batches.append(current_batch)
            
            # 使用多进程处理
            if self.process_count > 1 and len(batches) > 1:
                # 创建进程池
                with multiprocessing.Pool(processes=self.process_count) as pool:
                    # 准备任务
                    tasks = [(batch, target_hash, algorithm) for batch in batches]
                    
                    # 执行任务
                    for found, password, attempts in pool.starmap(self._process_batch, tasks):
                        total_attempts += attempts
                        if found:
                            end_time = time.time()
                            return {
                                'password': password,
                                'attempts': total_attempts,
                                'time': end_time - start_time
                            }
            else:
                # 单进程处理
                for batch in batches:
                    found, password, attempts = self._process_batch(batch, target_hash, algorithm)
                    total_attempts += attempts
                    if found:
                        end_time = time.time()
                        return {
                            'password': password,
                            'attempts': total_attempts,
                            'time': end_time - start_time
                        }
            
            return None
        except Exception as e:
            print(f"字典攻击出错: {e}")
            return None
    
    def _brute_force_worker(self, start, end, charset, length, target_hash, algorithm):
        """
        暴力破解工作线程
        
        Args:
            start (int): 起始索引
            end (int): 结束索引
            charset (str): 字符集
            length (int): 密码长度
            target_hash (str): 目标哈希值
            algorithm (str): 哈希算法
        
        Returns:
            tuple: (found, password, attempts)
        """
        found = False
        password = None
        attempts = 0
        charset_length = len(charset)
        
        for i in range(start, end):
            # 将索引转换为密码
            password_tuple = []
            num = i
            
            for _ in range(length):
                password_tuple.insert(0, charset[num % charset_length])
                num = num // charset_length
            
            password_str = ''.join(password_tuple)
            attempts += 1
            
            # 计算哈希
            hash_value = self.hash_utils.calculate_hash(password_str, algorithm)
            
            # 比较哈希
            if hash_value == target_hash:
                found = True
                password = password_str
                break
        
        return found, password, attempts
    
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
        total_attempts = 0
        
        try:
            # 遍历长度
            for length in range(min_length, max_length + 1):
                # 计算总组合数
                total_combinations = len(charset) ** length
                
                # 分任务处理
                if self.process_count > 1 and total_combinations > self.process_count:
                    # 计算每个进程的任务量
                    task_size = total_combinations // self.process_count
                    tasks = []
                    
                    for i in range(self.process_count):
                        start = i * task_size
                        end = (i + 1) * task_size if i < self.process_count - 1 else total_combinations
                        tasks.append((start, end, charset, length, target_hash, algorithm))
                    
                    # 使用多进程处理
                    with multiprocessing.Pool(processes=self.process_count) as pool:
                        for found, password, attempts in pool.starmap(self._brute_force_worker, tasks):
                            total_attempts += attempts
                            if found:
                                end_time = time.time()
                                return {
                                    'password': password,
                                    'attempts': total_attempts,
                                    'time': end_time - start_time
                                }
                else:
                    # 单进程处理
                    found, password, attempts = self._brute_force_worker(0, total_combinations, charset, length, target_hash, algorithm)
                    total_attempts += attempts
                    if found:
                        end_time = time.time()
                        return {
                            'password': password,
                            'attempts': total_attempts,
                            'time': end_time - start_time
                        }
            
            return None
        except Exception as e:
            print(f"暴力破解出错: {e}")
            return None
    
    def _mask_worker(self, start, end, mask, mask_positions, charset, target_hash, algorithm):
        """
        掩码攻击工作线程
        
        Args:
            start (int): 起始索引
            end (int): 结束索引
            mask (str): 掩码
            mask_positions (list): 可变位置
            charset (str): 字符集
            target_hash (str): 目标哈希值
            algorithm (str): 哈希算法
        
        Returns:
            tuple: (found, password, attempts)
        """
        found = False
        password = None
        attempts = 0
        charset_length = len(charset)
        mask_list = list(mask)
        
        for i in range(start, end):
            # 将索引转换为组合
            combo = []
            num = i
            
            for _ in range(len(mask_positions)):
                combo.insert(0, charset[num % charset_length])
                num = num // charset_length
            
            # 构建密码
            password_list = mask_list.copy()
            for pos, char in zip(mask_positions, combo):
                password_list[pos] = char
            password_str = ''.join(password_list)
            
            attempts += 1
            
            # 计算哈希
            hash_value = self.hash_utils.calculate_hash(password_str, algorithm)
            
            # 比较哈希
            if hash_value == target_hash:
                found = True
                password = password_str
                break
        
        return found, password, attempts
    
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
        total_attempts = 0
        
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
            
            # 计算总组合数
            total_combinations = len(charset) ** mask_length
            
            # 分任务处理
            if self.process_count > 1 and total_combinations > self.process_count:
                # 计算每个进程的任务量
                task_size = total_combinations // self.process_count
                tasks = []
                
                for i in range(self.process_count):
                    start = i * task_size
                    end = (i + 1) * task_size if i < self.process_count - 1 else total_combinations
                    tasks.append((start, end, mask, mask_positions, charset, target_hash, algorithm))
                
                # 使用多进程处理
                with multiprocessing.Pool(processes=self.process_count) as pool:
                    for found, password, attempts in pool.starmap(self._mask_worker, tasks):
                        total_attempts += attempts
                        if found:
                            end_time = time.time()
                            return {
                                'password': password,
                                'attempts': total_attempts,
                                'time': end_time - start_time
                            }
            else:
                # 单进程处理
                found, password, attempts = self._mask_worker(0, total_combinations, mask, mask_positions, charset, target_hash, algorithm)
                total_attempts += attempts
                if found:
                    end_time = time.time()
                    return {
                        'password': password,
                        'attempts': total_attempts,
                        'time': end_time - start_time
                    }
            
            return None
        except Exception as e:
            print(f"掩码攻击出错: {e}")
            return None
