#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码强度评估模块
"""

import re

class PasswordStrength:
    """密码强度评估类"""
    
    def __init__(self):
        """初始化密码强度评估器"""
        pass
    
    def evaluate(self, password):
        """
        评估密码强度
        
        Args:
            password (str): 待评估的密码
        
        Returns:
            dict: 包含强度评分、等级和建议的字典
        """
        if not password:
            return {
                'score': 0,
                'strength': '非常弱',
                'suggestions': ['请输入密码']
            }
        
        # 计算各项评分
        length_score = self._evaluate_length(password)
        complexity_score = self._evaluate_complexity(password)
        variety_score = self._evaluate_variety(password)
        uniqueness_score = self._evaluate_uniqueness(password)
        
        # 计算总评分
        total_score = length_score + complexity_score + variety_score + uniqueness_score
        
        # 确定强度等级
        strength = self._get_strength_level(total_score)
        
        # 生成建议
        suggestions = self._generate_suggestions(password)
        
        return {
            'score': total_score,
            'strength': strength,
            'suggestions': suggestions
        }
    
    def _evaluate_length(self, password):
        """
        评估密码长度
        
        Args:
            password (str): 待评估的密码
        
        Returns:
            int: 长度评分
        """
        length = len(password)
        
        if length < 6:
            return 0
        elif length < 8:
            return 1
        elif length < 10:
            return 2
        elif length < 12:
            return 3
        else:
            return 4
    
    def _evaluate_complexity(self, password):
        """
        评估密码复杂度
        
        Args:
            password (str): 待评估的密码
        
        Returns:
            int: 复杂度评分
        """
        score = 0
        
        # 包含小写字母
        if re.search(r'[a-z]', password):
            score += 1
        
        # 包含大写字母
        if re.search(r'[A-Z]', password):
            score += 1
        
        # 包含数字
        if re.search(r'[0-9]', password):
            score += 1
        
        # 包含特殊字符
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 1
        
        return score
    
    def _evaluate_variety(self, password):
        """
        评估密码字符多样性
        
        Args:
            password (str): 待评估的密码
        
        Returns:
            int: 多样性评分
        """
        # 计算唯一字符比例
        unique_chars = len(set(password))
        total_chars = len(password)
        variety_ratio = unique_chars / total_chars if total_chars > 0 else 0
        
        if variety_ratio < 0.5:
            return 0
        elif variety_ratio < 0.7:
            return 1
        elif variety_ratio < 0.9:
            return 2
        else:
            return 3
    
    def _evaluate_uniqueness(self, password):
        """
        评估密码唯一性
        
        Args:
            password (str): 待评估的密码
        
        Returns:
            int: 唯一性评分
        """
        # 常见弱密码列表
        common_passwords = [
            'password', '123456', '12345678', '1234', 'qwerty',
            '12345', 'dragon', '123123', 'baseball', 'abc123',
            'football', 'monkey', 'letmein', '696969', 'shadow',
            'master', '666666', 'qwertyuiop', '123321', 'mustang',
            '123456789', 'michael', '654321', 'superman', '1qaz2wsx'
        ]
        
        # 检查是否为常见弱密码
        if password.lower() in common_passwords:
            return 0
        
        # 检查是否为简单模式
        if password.isdigit() or password.isalpha():
            return 1
        
        # 检查是否为键盘模式
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '1234567890', '0987654321']
        for pattern in keyboard_patterns:
            if pattern in password.lower() or pattern[::-1] in password.lower():
                return 1
        
        return 3
    
    def _get_strength_level(self, score):
        """
        根据评分获取强度等级
        
        Args:
            score (int): 总评分
        
        Returns:
            str: 强度等级
        """
        if score < 3:
            return '非常弱'
        elif score < 6:
            return '弱'
        elif score < 9:
            return '中等'
        elif score < 12:
            return '强'
        else:
            return '非常强'
    
    def _generate_suggestions(self, password):
        """
        根据密码生成改进建议
        
        Args:
            password (str): 待评估的密码
        
        Returns:
            list: 改进建议列表
        """
        suggestions = []
        
        # 长度建议
        if len(password) < 8:
            suggestions.append('增加密码长度至少为8个字符')
        elif len(password) < 12:
            suggestions.append('考虑使用更长的密码（至少12个字符）')
        
        # 复杂度建议
        if not re.search(r'[a-z]', password):
            suggestions.append('添加小写字母')
        if not re.search(r'[A-Z]', password):
            suggestions.append('添加大写字母')
        if not re.search(r'[0-9]', password):
            suggestions.append('添加数字')
        if not re.search(r'[^a-zA-Z0-9]', password):
            suggestions.append('添加特殊字符（如!@#$%^&*()）')
        
        # 多样性建议
        unique_chars = len(set(password))
        total_chars = len(password)
        if unique_chars / total_chars < 0.7 and total_chars > 5:
            suggestions.append('使用更多不同类型的字符')
        
        # 唯一性建议
        common_passwords = ['password', '123456', '12345678', '1234', 'qwerty']
        if password.lower() in common_passwords:
            suggestions.append('避免使用常见弱密码')
        if password.isdigit():
            suggestions.append('避免使用纯数字密码')
        if password.isalpha():
            suggestions.append('避免使用纯字母密码')
        
        # 特殊建议
        if len(password) > 12 and len(set(password)) > 8:
            suggestions.append('密码强度良好，继续保持！')
        
        return suggestions
