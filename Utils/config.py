#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模块
"""

import json
import os

class ConfigManager:
    """配置管理器"""
    def __init__(self):
        """初始化配置管理器"""
        self.config_file = "config.json"
        self.default_config = {
            "performance": {
                "process_count": 4,        # 多进程数量
                "thread_count": 8,         # 线程数量
                "memory_limit": 1024,       # 内存限制（MB）
                "cache_size": 10000,        # 缓存大小
                "batch_size": 1000,         # 批处理大小
                "segment_count": 10         # 分段数量
            },
            "ui": {
                "theme": "light",           # 主题（light/dark）
                "font_size": 10             # 字体大小
            },
            "security": {
                "auto_clear": True,         # 自动清除敏感信息
                "show_warning": True        # 显示安全警告
            }
        }
        self.config = self.load_config()
    
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return self.default_config
        except Exception as e:
            print(f"加载配置文件出错: {e}")
            return self.default_config
    
    def save_config(self):
        """保存配置文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存配置文件出错: {e}")
            return False
    
    def get(self, key, default=None):
        """获取配置值"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key, value):
        """设置配置值"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        return self.save_config()
    
    def reset(self):
        """重置为默认配置"""
        self.config = self.default_config
        return self.save_config()
