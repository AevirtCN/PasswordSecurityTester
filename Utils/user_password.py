#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户密码测试模块
"""

import subprocess
import time
import itertools
import getpass

class UserPasswordTester:
    """用户密码测试类"""
    
    def __init__(self):
        """初始化用户密码测试器"""
        pass
    
    def get_windows_users(self):
        """
        获取Windows系统用户列表
        
        Returns:
            list: 用户列表
        """
        try:
            output = subprocess.check_output(['net', 'user'], universal_newlines=True)
            users = []
            lines = output.split('\n')
            
            # 解析输出获取用户列表
            for line in lines:
                line = line.strip()
                if line and not line.startswith('\n') and not line.startswith('用户') and not line.startswith('命令成功'):
                    users.extend(line.split())
            
            return users
        except Exception as e:
            print(f"获取用户列表出错: {e}")
            return []
    
    def test_user_password(self, username, password):
        """
        测试用户密码（使用net user命令模拟测试）
        
        Args:
            username (str): 用户名
            password (str): 测试密码
        
        Returns:
            bool: 密码是否符合强度要求
        """
        # 基于密码强度评估结果返回
        from utils.password_strength import PasswordStrength
        strength_evaluator = PasswordStrength()
        result = strength_evaluator.evaluate(password)
        
        # 密码强度为中等及以上视为符合要求
        is_secure = result['strength'] in ['中等', '强', '非常强']
        
        # 这里可以添加net user命令测试，但需要管理员权限
        # 实际环境中可以根据需要实现真实测试
        
        return is_secure
    
    def test_user_password_with_netuser(self, username, password):
        """
        使用net user命令测试用户密码
        
        Args:
            username (str): 用户名
            password (str): 测试密码
        
        Returns:
            dict: 测试结果
        """
        try:
            # 尝试使用net user命令检查用户信息
            # 注意：这不会实际验证密码，但可以获取用户信息
            output = subprocess.check_output(['net', 'user', username], universal_newlines=True)
            
            # 基于密码强度评估结果返回
            from utils.password_strength import PasswordStrength
            strength_evaluator = PasswordStrength()
            result = strength_evaluator.evaluate(password)
            
            is_secure = result['strength'] in ['中等', '强', '非常强']
            
            return {
                'success': True,
                'username': username,
                'is_secure': is_secure,
                'strength': result['strength'],
                'score': result['score'],
                'user_info': output
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def simulate_brute_force(self, username, charset, min_length, max_length):
        """
        模拟暴力破解用户密码
        
        Args:
            username (str): 用户名
            charset (str): 字符集
            min_length (int): 最小长度
            max_length (int): 最大长度
        
        Returns:
            dict: 模拟结果
        """
        start_time = time.time()
        total_attempts = 0
        
        try:
            # 计算总尝试次数
            for length in range(min_length, max_length + 1):
                total_attempts += len(charset) ** length
            
            # 计算预计时间（基于实际测试速度，假设每次尝试需要0.1ms）
            estimated_time = total_attempts * 0.0001
            
            end_time = time.time()
            actual_time = end_time - start_time
            
            return {
                'username': username,
                'charset_length': len(charset),
                'min_length': min_length,
                'max_length': max_length,
                'total_attempts': total_attempts,
                'estimated_time_seconds': estimated_time,
                'estimated_time_formatted': self._format_time(estimated_time),
                'actual_time_seconds': actual_time,
                'security_level': self._calculate_security_level(total_attempts, estimated_time)
            }
        except Exception as e:
            print(f"模拟暴力破解出错: {e}")
            return None
    
    def _format_time(self, seconds):
        """
        格式化时间
        
        Args:
            seconds (float): 秒数
        
        Returns:
            str: 格式化的时间字符串
        """
        if seconds < 60:
            return f"{seconds:.2f} 秒"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f} 分钟"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.2f} 小时"
        else:
            days = seconds / 86400
            return f"{days:.2f} 天"
    
    def _calculate_security_level(self, attempts, estimated_time):
        """
        计算安全级别
        
        Args:
            attempts (int): 总尝试次数
            estimated_time (float): 预计时间（秒）
        
        Returns:
            str: 安全级别
        """
        if estimated_time < 3600:
            return "非常弱"
        elif estimated_time < 86400:
            return "弱"
        elif estimated_time < 604800:
            return "中等"
        elif estimated_time < 2592000:
            return "强"
        else:
            return "非常强"
    
    def evaluate_user_password_security(self, username):
        """
        评估用户密码安全性
        
        Args:
            username (str): 用户名
        
        Returns:
            dict: 评估结果
        """
        # 模拟评估结果
        # 实际环境中可以根据需要实现更复杂的评估
        return {
            'username': username,
            'security_tips': [
                '使用至少12个字符的密码',
                '包含大小写字母、数字和特殊字符',
                '避免使用常见密码和个人信息',
                '定期更换密码',
                '使用密码管理器生成和存储复杂密码'
            ],
            'brute_force_simulation': {
                'simple_charset': 'abcdefghijklmnopqrstuvwxyz',
                'complex_charset': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()',
                'recommendation': '使用复杂字符集和较长密码长度'
            }
        }
    
    def get_current_user(self):
        """
        获取当前登录用户
        
        Returns:
            str: 当前用户名
        """
        return getpass.getuser()
