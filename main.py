#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全性测试工具主入口
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
from password_cracker import PasswordCracker
from encryption_tester import EncryptionTester
from utils.config import ConfigManager

# 版本信息
VERSION = "v0.1.1"
RELEASE_DATE = "2026-02-13"

class SecurityTesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"安全性测试工具 - {VERSION}")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 初始化配置管理器
        self.config_manager = ConfigManager()
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建选项卡
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 密码测试选项卡
        self.password_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.password_tab, text="密码测试")
        
        # 加密测试选项卡
        self.encryption_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encryption_tab, text="加密测试")
        
        # 结果选项卡
        self.result_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.result_tab, text="测试结果")
        
        # 设置选项卡
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="设置")
        
        # 初始化选项卡内容
        self.init_password_tab()
        self.init_encryption_tab()
        self.init_result_tab()
        self.init_settings_tab()
        
        # 禁用测试按钮
        self.start_password_test.config(state=tk.DISABLED)
        self.start_encryption_test.config(state=tk.DISABLED)
        
        # 绑定事件
        self.password_hash.trace_add("write", self.enable_password_test)
        self.encryption_hash.trace_add("write", self.enable_encryption_test)
    
    def init_password_tab(self):
        """初始化密码测试选项卡"""
        # 创建框架
        frame = ttk.LabelFrame(self.password_tab, text="密码爆破测试", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 密码哈希输入
        ttk.Label(frame, text="目标哈希值:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.password_hash = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_hash, width=60).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # 攻击方式选择
        ttk.Label(frame, text="攻击方式:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.attack_method = ttk.Combobox(frame, values=["字典攻击", "暴力破解", "掩码攻击"], width=20)
        self.attack_method.current(0)
        self.attack_method.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # 字典文件选择
        ttk.Label(frame, text="字典文件:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.wordlist_path = tk.StringVar(value="default")
        ttk.Entry(frame, textvariable=self.wordlist_path, width=40).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # 字符集设置
        ttk.Label(frame, text="字符集:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.charset = tk.StringVar(value="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")
        ttk.Entry(frame, textvariable=self.charset, width=60).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # 最小长度
        ttk.Label(frame, text="最小长度:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.min_length = tk.StringVar(value="4")
        ttk.Entry(frame, textvariable=self.min_length, width=10).grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # 最大长度
        ttk.Label(frame, text="最大长度:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.max_length = tk.StringVar(value="8")
        ttk.Entry(frame, textvariable=self.max_length, width=10).grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # 掩码设置
        ttk.Label(frame, text="掩码:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.mask = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.mask, width=40).grid(row=6, column=1, sticky=tk.W, pady=5)
        
        # 哈希算法选择
        ttk.Label(frame, text="哈希算法:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.hash_algorithm = ttk.Combobox(frame, values=["md5", "sha1", "sha256", "sha512"], width=20)
        self.hash_algorithm.current(0)
        self.hash_algorithm.grid(row=7, column=1, sticky=tk.W, pady=5)
        
        # 测试按钮
        self.start_password_test = ttk.Button(frame, text="开始测试", command=self.start_password_test_thread)
        self.start_password_test.grid(row=8, column=0, columnspan=2, pady=10)
    
    def init_encryption_tab(self):
        """初始化加密测试选项卡"""
        # 创建框架
        frame = ttk.LabelFrame(self.encryption_tab, text="加密方式测试", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 目标哈希输入
        ttk.Label(frame, text="目标哈希值:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.encryption_hash = tk.StringVar()
        ttk.Entry(frame, textvariable=self.encryption_hash, width=60).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # 加密方式选择
        ttk.Label(frame, text="加密方式:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.encryption_method = ttk.Combobox(frame, values=["单加密", "混合加密"], width=20)
        self.encryption_method.current(0)
        self.encryption_method.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # 单加密算法选择
        ttk.Label(frame, text="单加密算法:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.single_algorithm = ttk.Combobox(frame, values=["md5", "sha1", "sha256", "sha512"], width=20)
        self.single_algorithm.current(0)
        self.single_algorithm.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # 混合加密链设置
        ttk.Label(frame, text="混合加密链:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.encryption_chain = tk.StringVar(value="md5>sha256")
        ttk.Entry(frame, textvariable=self.encryption_chain, width=40).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # 字典文件选择
        ttk.Label(frame, text="字典文件:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.encryption_wordlist = tk.StringVar(value="default")
        ttk.Entry(frame, textvariable=self.encryption_wordlist, width=40).grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # 测试按钮
        self.start_encryption_test = ttk.Button(frame, text="开始测试", command=self.start_encryption_test_thread)
        self.start_encryption_test.grid(row=5, column=0, columnspan=2, pady=10)
    
    def init_result_tab(self):
        """初始化结果选项卡"""
        # 创建框架
        frame = ttk.LabelFrame(self.result_tab, text="测试结果", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建文本框
        self.result_text = tk.Text(frame, wrap=tk.WORD, height=20)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(self.result_text, command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.config(yscrollcommand=scrollbar.set)
        
        # 清空按钮
        ttk.Button(frame, text="清空结果", command=self.clear_result).pack(side=tk.RIGHT, pady=5)
    
    def enable_password_test(self, *args):
        """启用密码测试按钮"""
        if self.password_hash.get():
            self.start_password_test.config(state=tk.NORMAL)
        else:
            self.start_password_test.config(state=tk.DISABLED)
    
    def enable_encryption_test(self, *args):
        """启用加密测试按钮"""
        if self.encryption_hash.get():
            self.start_encryption_test.config(state=tk.NORMAL)
        else:
            self.start_encryption_test.config(state=tk.DISABLED)
    
    def start_password_test_thread(self):
        """启动密码测试线程"""
        # 禁用测试按钮
        self.start_password_test.config(state=tk.DISABLED)
        
        # 获取参数
        target_hash = self.password_hash.get()
        method = self.attack_method.get()
        wordlist = self.wordlist_path.get()
        charset = self.charset.get()
        min_len = int(self.min_length.get())
        max_len = int(self.max_length.get())
        mask = self.mask.get()
        algorithm = self.hash_algorithm.get()
        
        # 清空结果
        self.clear_result()
        
        # 添加测试信息
        self.add_result(f"开始密码爆破测试")
        self.add_result(f"目标哈希: {target_hash}")
        self.add_result(f"攻击方式: {method}")
        self.add_result(f"哈希算法: {algorithm}")
        
        # 创建线程
        thread = threading.Thread(target=self.run_password_test, args=(
            target_hash, method, wordlist, charset, min_len, max_len, mask, algorithm
        ))
        thread.daemon = True
        thread.start()
    
    def run_password_test(self, target_hash, method, wordlist, charset, min_len, max_len, mask, algorithm):
        """运行密码测试"""
        try:
            cracker = PasswordCracker()
            
            if method == "字典攻击":
                result = cracker.dictionary_attack(target_hash, wordlist, algorithm)
            elif method == "暴力破解":
                result = cracker.brute_force_attack(target_hash, charset, min_len, max_len, algorithm)
            else:  # 掩码攻击
                result = cracker.mask_attack(target_hash, mask, charset, algorithm)
            
            # 显示结果
            if result:
                self.add_result(f"\n破解成功!")
                self.add_result(f"密码: {result['password']}")
                self.add_result(f"尝试次数: {result['attempts']}")
                self.add_result(f"耗时: {result['time']:.2f} 秒")
            else:
                self.add_result(f"\n破解失败，未找到匹配的密码")
        except Exception as e:
            self.add_result(f"\n测试过程中出错: {str(e)}")
        finally:
            # 启用测试按钮
            self.start_password_test.config(state=tk.NORMAL)
    
    def start_encryption_test_thread(self):
        """启动加密测试线程"""
        # 禁用测试按钮
        self.start_encryption_test.config(state=tk.DISABLED)
        
        # 获取参数
        target_hash = self.encryption_hash.get()
        method = self.encryption_method.get()
        wordlist = self.encryption_wordlist.get()
        
        # 清空结果
        self.clear_result()
        
        # 添加测试信息
        self.add_result(f"开始加密方式测试")
        self.add_result(f"目标哈希: {target_hash}")
        self.add_result(f"加密方式: {method}")
        
        # 创建线程
        thread = threading.Thread(target=self.run_encryption_test, args=(
            target_hash, method, wordlist
        ))
        thread.daemon = True
        thread.start()
    
    def run_encryption_test(self, target_hash, method, wordlist):
        """运行加密测试"""
        try:
            tester = EncryptionTester()
            
            if method == "单加密":
                algorithm = self.single_algorithm.get()
                self.add_result(f"加密算法: {algorithm}")
                result = tester.single_encryption_attack(target_hash, algorithm, wordlist)
            else:  # 混合加密
                chain = self.encryption_chain.get().split(">")
                self.add_result(f"加密链: {' > '.join(chain)}")
                result = tester.hybrid_encryption_attack(target_hash, chain, wordlist)
            
            # 显示结果
            if result:
                self.add_result(f"\n破解成功!")
                self.add_result(f"原始密码: {result['password']}")
                self.add_result(f"尝试次数: {result['attempts']}")
                self.add_result(f"耗时: {result['time']:.2f} 秒")
            else:
                self.add_result(f"\n破解失败，未找到匹配的密码")
        except Exception as e:
            self.add_result(f"\n测试过程中出错: {str(e)}")
        finally:
            # 启用测试按钮
            self.start_encryption_test.config(state=tk.NORMAL)
    
    def add_result(self, text):
        """添加结果文本"""
        self.result_text.insert(tk.END, text + "\n")
        self.result_text.see(tk.END)
    
    def clear_result(self):
        """清空结果"""
        self.result_text.delete(1.0, tk.END)
    
    def init_settings_tab(self):
        """初始化设置选项卡"""
        # 创建框架
        frame = ttk.LabelFrame(self.settings_tab, text="设置", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 性能设置
        perf_frame = ttk.LabelFrame(frame, text="性能设置", padding="10")
        perf_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 多进程数量
        ttk.Label(perf_frame, text="多进程数量:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.process_count = tk.IntVar(value=self.config_manager.get('performance.process_count', 4))
        ttk.Entry(perf_frame, textvariable=self.process_count, width=10).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # 线程数量
        ttk.Label(perf_frame, text="线程数量:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.thread_count = tk.IntVar(value=self.config_manager.get('performance.thread_count', 8))
        ttk.Entry(perf_frame, textvariable=self.thread_count, width=10).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # 内存限制
        ttk.Label(perf_frame, text="内存限制 (MB):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.memory_limit = tk.IntVar(value=self.config_manager.get('performance.memory_limit', 1024))
        ttk.Entry(perf_frame, textvariable=self.memory_limit, width=10).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # 缓存大小
        ttk.Label(perf_frame, text="缓存大小:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.cache_size = tk.IntVar(value=self.config_manager.get('performance.cache_size', 10000))
        ttk.Entry(perf_frame, textvariable=self.cache_size, width=10).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # 批处理大小
        ttk.Label(perf_frame, text="批处理大小:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.batch_size = tk.IntVar(value=self.config_manager.get('performance.batch_size', 1000))
        ttk.Entry(perf_frame, textvariable=self.batch_size, width=10).grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # 分段数量
        ttk.Label(perf_frame, text="分段数量:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.segment_count = tk.IntVar(value=self.config_manager.get('performance.segment_count', 10))
        ttk.Entry(perf_frame, textvariable=self.segment_count, width=10).grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # UI设置
        ui_frame = ttk.LabelFrame(frame, text="UI设置", padding="10")
        ui_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 主题
        ttk.Label(ui_frame, text="主题:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.theme = tk.StringVar(value=self.config_manager.get('ui.theme', 'light'))
        ttk.Combobox(ui_frame, textvariable=self.theme, values=['light', 'dark'], width=15).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # 字体大小
        ttk.Label(ui_frame, text="字体大小:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.font_size = tk.IntVar(value=self.config_manager.get('ui.font_size', 10))
        ttk.Entry(ui_frame, textvariable=self.font_size, width=10).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # 安全设置
        sec_frame = ttk.LabelFrame(frame, text="安全设置", padding="10")
        sec_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 自动清除
        self.auto_clear = tk.BooleanVar(value=self.config_manager.get('security.auto_clear', True))
        ttk.Checkbutton(sec_frame, text="自动清除敏感信息", variable=self.auto_clear).grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # 显示警告
        self.show_warning = tk.BooleanVar(value=self.config_manager.get('security.show_warning', True))
        ttk.Checkbutton(sec_frame, text="显示安全警告", variable=self.show_warning).grid(row=1, column=0, sticky=tk.W, pady=5)
        
        # 保存按钮
        ttk.Button(frame, text="保存设置", command=self.save_settings).pack(pady=10)
    
    def save_settings(self):
        """保存设置"""
        try:
            # 保存性能设置
            self.config_manager.set('performance.process_count', self.process_count.get())
            self.config_manager.set('performance.thread_count', self.thread_count.get())
            self.config_manager.set('performance.memory_limit', self.memory_limit.get())
            self.config_manager.set('performance.cache_size', self.cache_size.get())
            self.config_manager.set('performance.batch_size', self.batch_size.get())
            self.config_manager.set('performance.segment_count', self.segment_count.get())
            
            # 保存UI设置
            self.config_manager.set('ui.theme', self.theme.get())
            self.config_manager.set('ui.font_size', self.font_size.get())
            
            # 保存安全设置
            self.config_manager.set('security.auto_clear', self.auto_clear.get())
            self.config_manager.set('security.show_warning', self.show_warning.get())
            
            messagebox.showinfo("成功", "设置已保存")
        except Exception as e:
            messagebox.showerror("错误", f"保存设置出错: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityTesterApp(root)
    root.mainloop()
