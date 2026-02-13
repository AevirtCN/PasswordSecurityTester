#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
压缩包密码测试模块
"""

import zipfile
import rarfile
import time
import os
import subprocess
import tempfile

class ArchiveTester:
    """压缩包密码测试类"""
    
    def __init__(self):
        """初始化压缩包测试器"""
        pass
    
    def test_zip_password(self, zip_path, password):
        """
        测试ZIP文件密码
        
        Args:
            zip_path (str): ZIP文件路径
            password (str): 测试密码
        
        Returns:
            bool: 密码是否正确
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(path=os.path.dirname(zip_path), pwd=password.encode())
            return True
        except Exception:
            return False
    
    def test_rar_password(self, rar_path, password):
        """
        测试RAR文件密码
        
        Args:
            rar_path (str): RAR文件路径
            password (str): 测试密码
        
        Returns:
            bool: 密码是否正确
        """
        try:
            with rarfile.RarFile(rar_path, 'r') as rf:
                rf.extractall(path=os.path.dirname(rar_path), pwd=password)
            return True
        except Exception:
            return False
    
    def test_7z_password(self, seven_zip_path, password):
        """
        测试7Z文件密码
        
        Args:
            seven_zip_path (str): 7Z文件路径
            password (str): 测试密码
        
        Returns:
            bool: 密码是否正确
        """
        try:
            # 尝试使用7z命令行工具
            with tempfile.TemporaryDirectory() as temp_dir:
                cmd = ['7z', 'x', f'-p{password}', seven_zip_path, f'-o{temp_dir}']
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.returncode == 0
        except Exception:
            return False
    
    def test_tar_gz_password(self, tar_gz_path, password):
        """
        测试tar.gz文件密码
        
        Args:
            tar_gz_path (str): tar.gz文件路径
            password (str): 测试密码
        
        Returns:
            bool: 密码是否正确
        """
        try:
            # 尝试使用7z命令行工具
            with tempfile.TemporaryDirectory() as temp_dir:
                cmd = ['7z', 'x', f'-p{password}', tar_gz_path, f'-o{temp_dir}']
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.returncode == 0
        except Exception:
            return False
    
    def test_archive_password(self, archive_path, password):
        """
        测试压缩包密码（自动检测类型）
        
        Args:
            archive_path (str): 压缩包文件路径
            password (str): 测试密码
        
        Returns:
            bool: 密码是否正确
        """
        ext = os.path.splitext(archive_path)[1].lower()
        
        if ext == '.zip':
            return self.test_zip_password(archive_path, password)
        elif ext == '.rar':
            return self.test_rar_password(archive_path, password)
        elif ext == '.7z':
            return self.test_7z_password(archive_path, password)
        elif ext in ['.tar.gz', '.tgz']:
            return self.test_tar_gz_password(archive_path, password)
        else:
            raise ValueError(f"不支持的压缩包格式: {ext}")
    
    def brute_force_archive(self, archive_path, charset, min_length, max_length, algorithm=None):
        """
        暴力破解压缩包密码
        
        Args:
            archive_path (str): 压缩包文件路径
            charset (str): 字符集
            min_length (int): 最小长度
            max_length (int): 最大长度
            algorithm (str): 哈希算法（如果需要）
        
        Returns:
            dict or None: 成功返回包含密码、尝试次数和耗时的字典，失败返回None
        """
        import itertools
        start_time = time.time()
        attempts = 0
        
        try:
            # 遍历长度
            for length in range(min_length, max_length + 1):
                # 生成所有组合
                for password_tuple in itertools.product(charset, repeat=length):
                    password = ''.join(password_tuple)
                    attempts += 1
                    
                    # 测试密码
                    if self.test_archive_password(archive_path, password):
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
    
    def dictionary_attack_archive(self, archive_path, wordlist_path):
        """
        字典攻击压缩包密码
        
        Args:
            archive_path (str): 压缩包文件路径
            wordlist_path (str): 字典文件路径
        
        Returns:
            dict or None: 成功返回包含密码、尝试次数和耗时的字典，失败返回None
        """
        start_time = time.time()
        attempts = 0
        
        try:
            # 读取字典
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            # 遍历字典
            for password in wordlist:
                attempts += 1
                
                # 测试密码
                if self.test_archive_password(archive_path, password):
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
