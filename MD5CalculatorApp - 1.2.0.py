import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, Menu
import hashlib
import os
import threading
import json
import csv
import time
from tkinterdnd2 import TkinterDnD, DND_FILES
from datetime import datetime

class UltimateMD5CalculatorApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("终极MD5计算工具")
        self.geometry("900x700")
        self.minsize(800, 600)
        
        # 配置
        self.config_file = "md5_tool_config.json"
        self.history_file = "md5_history.json"
        self.max_history = 50
        
        # 初始化设置
        self.settings = {
            "theme": "light",
            "uppercase": True,
            "auto_compare": False,
            "auto_check_duplicates": True,
            "recent_files": [],
            "window_size": "900x700"
        }
        
        # 历史记录
        self.history = []
        
        # 加载配置和历史
        self.load_config()
        self.load_history()
        
        # 样式配置
        self.setup_theme()
        
        # 创建UI
        self.create_widgets()
        self.setup_layout()
        self.setup_drag_and_drop()
        self.setup_menu()
        
        # 用于存储文件MD5结果的字典
        self.file_md5_dict = {}
        
        # 用于线程安全操作
        self.lock = threading.Lock()
        
        # 线程控制
        self.calculation_thread = None
        self.stop_flag = False
    
    def setup_theme(self):
        """设置主题样式"""
        self.style = ttk.Style()
        
        if self.settings["theme"] == "dark":
            self.configure(bg="#333333")
            self.style.theme_use("alt")
            
            # 深色主题颜色配置
            bg_color = "#333333"
            fg_color = "#ffffff"
            entry_bg = "#555555"
            text_bg = "#444444"
            
            self.style.configure(".", background=bg_color, foreground=fg_color)
            self.style.configure("TFrame", background=bg_color)
            self.style.configure("TLabel", background=bg_color, foreground=fg_color)
            self.style.configure("TButton", background="#555555", foreground=fg_color)
            self.style.configure("TEntry", fieldbackground=entry_bg, foreground=fg_color)
            self.style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg_color)
            self.style.configure("TScrollbar", background="#555555")
            self.style.configure("Treeview", 
                                background=text_bg, 
                                foreground=fg_color,
                                fieldbackground=text_bg)
            self.style.map('Treeview', background=[('selected', '#0078d7')])
            
            # 文本控件样式
            text_style = {
                "bg": text_bg, "fg": fg_color, 
                "insertbackground": fg_color,
                "selectbackground": "#0078d7",
                "selectforeground": fg_color
            }
            self.text_input.configure(**text_style)
            self.result_text.configure(**text_style)
            self.multi_file_listbox.configure(
                bg=text_bg, fg=fg_color, 
                selectbackground="#0078d7",
                selectforeground=fg_color
            )
        else:
            # 浅色主题为默认
            self.style.theme_use("clam")
    
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded_settings = json.load(f)
                    self.settings.update(loaded_settings)
        except Exception as e:
            print(f"加载配置失败: {str(e)}")
    
    def save_config(self):
        """保存配置文件"""
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            print(f"保存配置失败: {str(e)}")
    
    def load_history(self):
        """加载历史记录"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
        except Exception as e:
            print(f"加载历史记录失败: {str(e)}")
    
    def save_history(self):
        """保存历史记录"""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history[-self.max_history:], f, indent=4)
        except Exception as e:
            print(f"保存历史记录失败: {str(e)}")
    
    def add_to_history(self, item):
        """添加到历史记录"""
        self.history.append(item)
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
        self.save_history()
    
    def create_widgets(self):
        """创建所有UI组件"""
        # 输入方式选择
        self.input_method = tk.StringVar(value="text")
        self.input_frame = ttk.LabelFrame(self, text="输入方式")
        self.text_radio = ttk.Radiobutton(
            self.input_frame, text="文本输入", variable=self.input_method, value="text",
            command=self.toggle_input_method)
        self.file_radio = ttk.Radiobutton(
            self.input_frame, text="文件输入", variable=self.input_method, value="file",
            command=self.toggle_input_method)
        self.multi_file_radio = ttk.Radiobutton(
            self.input_frame, text="多文件输入", variable=self.input_method, value="multi_file",
            command=self.toggle_input_method)
        self.dir_radio = ttk.Radiobutton(
            self.input_frame, text="目录输入", variable=self.input_method, value="directory",
            command=self.toggle_input_method)
        
        # 哈希算法选择
        self.hash_algorithm = tk.StringVar(value="md5")
        self.hash_menu = ttk.Combobox(
            self.input_frame, textvariable=self.hash_algorithm,
            values=["md5", "sha1", "sha256", "sha512"], state="readonly")
        self.hash_menu.bind("<<ComboboxSelected>>", self.on_hash_algorithm_change)
        
        # 文本输入区域
        self.text_frame = ttk.LabelFrame(self, text="文本输入")
        self.text_input = scrolledtext.ScrolledText(self.text_frame, height=10, wrap=tk.WORD)
        
        # 文件输入区域
        self.file_frame = ttk.LabelFrame(self, text="文件输入")
        self.file_path = tk.StringVar()
        self.file_entry = ttk.Entry(
            self.file_frame, textvariable=self.file_path, state="readonly")
        self.browse_button = ttk.Button(
            self.file_frame, text="浏览...", command=self.browse_file)
        self.show_in_explorer_button = ttk.Button(
            self.file_frame, text="打开所在目录", command=self.show_in_explorer)
        
        # 多文件输入区域
        self.multi_file_frame = ttk.LabelFrame(self, text="多文件输入")
        self.multi_file_listbox = tk.Listbox(
            self.multi_file_frame, selectmode=tk.EXTENDED)
        self.multi_file_scroll = ttk.Scrollbar(
            self.multi_file_frame, orient=tk.VERTICAL, command=self.multi_file_listbox.yview)
        self.multi_file_listbox.configure(yscrollcommand=self.multi_file_scroll.set)
        
        self.multi_file_buttons_frame = ttk.Frame(self.multi_file_frame)
        self.add_files_button = ttk.Button(
            self.multi_file_buttons_frame, text="添加文件", command=self.add_files)
        self.add_dir_button = ttk.Button(
            self.multi_file_buttons_frame, text="添加目录", command=self.add_directory)
        self.remove_files_button = ttk.Button(
            self.multi_file_buttons_frame, text="移除选中", command=self.remove_selected_files)
        self.clear_files_button = ttk.Button(
            self.multi_file_buttons_frame, text="清空列表", command=self.clear_file_list)
        
        # 目录输入区域
        self.dir_frame = ttk.LabelFrame(self, text="目录输入")
        self.dir_path = tk.StringVar()
        self.dir_entry = ttk.Entry(
            self.dir_frame, textvariable=self.dir_path, state="readonly")
        self.browse_dir_button = ttk.Button(
            self.dir_frame, text="浏览...", command=self.browse_directory)
        self.show_dir_in_explorer_button = ttk.Button(
            self.dir_frame, text="打开目录", command=self.show_dir_in_explorer)
        
        # 文件过滤器
        self.filter_frame = ttk.LabelFrame(self.dir_frame, text="文件过滤")
        self.filter_ext = tk.StringVar()
        self.filter_ext_entry = ttk.Entry(
            self.filter_frame, textvariable=self.filter_ext)
        self.recursive_var = tk.BooleanVar(value=True)
        self.recursive_check = ttk.Checkbutton(
            self.filter_frame, text="包含子目录", variable=self.recursive_var)
        
        # 计算选项
        self.options_frame = ttk.LabelFrame(self, text="计算选项")
        self.uppercase_var = tk.BooleanVar(value=self.settings["uppercase"])
        self.uppercase_check = ttk.Checkbutton(
            self.options_frame, text="大写结果", variable=self.uppercase_var)
        
        self.compare_var = tk.BooleanVar(value=self.settings["auto_compare"])
        self.compare_check = ttk.Checkbutton(
            self.options_frame, text="比对模式", variable=self.compare_var,
            command=self.toggle_compare_mode)
        
        self.auto_check_duplicates_var = tk.BooleanVar(value=self.settings["auto_check_duplicates"])
        self.auto_check_duplicates_check = ttk.Checkbutton(
            self.options_frame, text="自动检测重复", variable=self.auto_check_duplicates_var)
        
        self.compare_target_frame = ttk.Frame(self.options_frame)
        self.compare_target_label = ttk.Label(self.compare_target_frame, text="比对目标:")
        self.compare_target = tk.StringVar()
        self.compare_entry = ttk.Entry(
            self.compare_target_frame, textvariable=self.compare_target)
        self.compare_history_button = ttk.Button(
            self.compare_target_frame, text="历史", command=self.show_history_menu)
        
        # 计算按钮
        self.calculate_button = ttk.Button(
            self, text="计算MD5", command=self.start_calculation_thread)
        self.stop_button = ttk.Button(
            self, text="停止计算", command=self.stop_calculation, state=tk.DISABLED)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self, variable=self.progress_var, maximum=100)
        
        # 结果显示
        self.result_frame = ttk.LabelFrame(self, text="MD5结果")
        self.result_text = scrolledtext.ScrolledText(
            self.result_frame, height=10, wrap=tk.WORD, state="disabled")
        
        # 比对结果
        self.compare_result_var = tk.StringVar()
        self.compare_result_label = ttk.Label(
            self.result_frame, textvariable=self.compare_result_var,
            font=('Arial', 10, 'bold'))
        
        # 多文件结果表格
        self.multi_result_frame = ttk.LabelFrame(self, text="文件MD5结果")
        self.multi_result_tree = ttk.Treeview(
            self.multi_result_frame, columns=("file", "path", "md5", "size", "modified"), show="headings")
        self.multi_result_tree.heading("file", text="文件名", command=lambda: self.sort_treeview("file", False))
        self.multi_result_tree.heading("path", text="路径")
        self.multi_result_tree.heading("md5", text="MD5值", command=lambda: self.sort_treeview("md5", False))
        self.multi_result_tree.heading("size", text="大小", command=lambda: self.sort_treeview("size", False))
        self.multi_result_tree.heading("modified", text="修改时间", command=lambda: self.sort_treeview("modified", False))
        
        self.multi_result_tree.column("file", width=200, anchor=tk.W)
        self.multi_result_tree.column("path", width=250, anchor=tk.W)
        self.multi_result_tree.column("md5", width=250, anchor=tk.W)
        self.multi_result_tree.column("size", width=100, anchor=tk.E)
        self.multi_result_tree.column("modified", width=150, anchor=tk.W)
        
        self.multi_result_scroll = ttk.Scrollbar(
            self.multi_result_frame, orient=tk.VERTICAL, command=self.multi_result_tree.yview)
        self.multi_result_tree.configure(yscrollcommand=self.multi_result_scroll.set)
        
        # 操作按钮
        self.button_frame = ttk.Frame(self)
        self.copy_button = ttk.Button(
            self.button_frame, text="复制结果", command=self.copy_result)
        self.save_button = ttk.Button(
            self.button_frame, text="保存结果", command=self.save_result)
        self.export_button = ttk.Button(
            self.button_frame, text="导出结果", command=self.export_result)
        self.clear_button = ttk.Button(
            self.button_frame, text="清空", command=self.clear_all)
        self.exit_button = ttk.Button(
            self.button_frame, text="退出", command=self.quit)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = ttk.Label(
            self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        
        # 右键菜单
        self.setup_context_menus()
    
    def setup_layout(self):
        """设置UI布局"""
        # 输入方式选择和哈希算法
        self.input_frame.pack(pady=5, padx=10, fill=tk.X)
        self.text_radio.pack(side=tk.LEFT, padx=5)
        self.file_radio.pack(side=tk.LEFT, padx=5)
        self.multi_file_radio.pack(side=tk.LEFT, padx=5)
        self.dir_radio.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.input_frame, text="算法:").pack(side=tk.LEFT, padx=5)
        self.hash_menu.pack(side=tk.LEFT, padx=5)
        
        # 文本输入区域
        self.text_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        # 文件输入区域 (初始隐藏)
        self.file_frame.pack(pady=5, padx=10, fill=tk.X)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_button.pack(side=tk.LEFT, padx=2)
        self.show_in_explorer_button.pack(side=tk.LEFT, padx=2)
        self.file_frame.pack_forget()
        
        # 多文件输入区域 (初始隐藏)
        self.multi_file_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.multi_file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.multi_file_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.multi_file_buttons_frame.pack(fill=tk.X, pady=5)
        self.add_files_button.pack(side=tk.LEFT, padx=2, expand=True)
        self.add_dir_button.pack(side=tk.LEFT, padx=2, expand=True)
        self.remove_files_button.pack(side=tk.LEFT, padx=2, expand=True)
        self.clear_files_button.pack(side=tk.LEFT, padx=2, expand=True)
        self.multi_file_frame.pack_forget()
        
        # 目录输入区域 (初始隐藏)
        self.dir_frame.pack(pady=5, padx=10, fill=tk.X)
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_dir_button.pack(side=tk.LEFT, padx=2)
        self.show_dir_in_explorer_button.pack(side=tk.LEFT, padx=2)
        
        self.filter_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Label(self.filter_frame, text="扩展名过滤:").pack(side=tk.LEFT, padx=5)
        self.filter_ext_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.recursive_check.pack(side=tk.LEFT, padx=5)
        self.dir_frame.pack_forget()
        
        # 计算选项
        self.options_frame.pack(pady=5, padx=10, fill=tk.X)
        self.uppercase_check.pack(side=tk.LEFT, padx=5)
        self.compare_check.pack(side=tk.LEFT, padx=5)
        self.auto_check_duplicates_check.pack(side=tk.LEFT, padx=5)
        self.compare_target_frame.pack(fill=tk.X, padx=5, pady=5)
        self.compare_target_label.pack(side=tk.LEFT)
        self.compare_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.compare_history_button.pack(side=tk.LEFT, padx=5)
        
        # 计算按钮和进度条
        button_progress_frame = ttk.Frame(self)
        button_progress_frame.pack(pady=5, fill=tk.X, padx=10)
        self.calculate_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # 结果显示
        self.result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.compare_result_label.pack(fill=tk.X)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # 多文件结果表格 (初始隐藏)
        self.multi_result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.multi_result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.multi_result_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.multi_result_frame.pack_forget()
        
        # 操作按钮
        self.button_frame.pack(pady=10, fill=tk.X)
        self.copy_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.save_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.export_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.clear_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.exit_button.pack(side=tk.LEFT, padx=5, expand=True)
        
        # 状态栏
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 初始显示文本输入
        self.toggle_input_method()
    
    def setup_menu(self):
        """设置菜单栏"""
        menubar = tk.Menu(self)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="新建", command=self.clear_all)
        file_menu.add_separator()
        file_menu.add_command(label="打开文件...", command=self.browse_file)
        file_menu.add_command(label="打开目录...", command=self.browse_directory)
        file_menu.add_separator()
        file_menu.add_command(label="保存结果", command=self.save_result)
        file_menu.add_command(label="导出结果", command=self.export_result)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.quit)
        menubar.add_cascade(label="文件", menu=file_menu)
        
        # 编辑菜单
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="复制结果", command=self.copy_result)
        edit_menu.add_command(label="清空", command=self.clear_all)
        menubar.add_cascade(label="编辑", menu=edit_menu)
        
        # 工具菜单
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_checkbutton(label="大写结果", variable=self.uppercase_var)
        tools_menu.add_checkbutton(label="比对模式", variable=self.compare_var)
        tools_menu.add_checkbutton(label="自动检测重复", variable=self.auto_check_duplicates_var)
        tools_menu.add_separator()
        tools_menu.add_command(label="历史记录", command=self.show_history_dialog)
        menubar.add_cascade(label="工具", menu=tools_menu)
        
        # 视图菜单
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="浅色主题", command=lambda: self.change_theme("light"))
        view_menu.add_command(label="深色主题", command=lambda: self.change_theme("dark"))
        menubar.add_cascade(label="视图", menu=view_menu)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        
        self.config(menu=menubar)
    
    def setup_context_menus(self):
        """设置右键菜单"""
        # 文本输入右键菜单
        self.text_context_menu = Menu(self.text_input, tearoff=0)
        self.text_context_menu.add_command(label="剪切", command=lambda: self.text_input.event_generate("<<Cut>>"))
        self.text_context_menu.add_command(label="复制", command=lambda: self.text_input.event_generate("<<Copy>>"))
        self.text_context_menu.add_command(label="粘贴", command=lambda: self.text_input.event_generate("<<Paste>>"))
        self.text_context_menu.add_separator()
        self.text_context_menu.add_command(label="清空", command=lambda: self.text_input.delete("1.0", tk.END))
        self.text_input.bind("<Button-3>", lambda e: self.text_context_menu.tk_popup(e.x_root, e.y_root))
        
        # 结果文本右键菜单
        self.result_context_menu = Menu(self.result_text, tearoff=0)
        self.result_context_menu.add_command(label="复制", command=self.copy_result)
        self.result_context_menu.add_separator()
        self.result_context_menu.add_command(label="清空", command=lambda: self.clear_result())
        self.result_text.bind("<Button-3>", lambda e: self.result_context_menu.tk_popup(e.x_root, e.y_root))
        
        # 多文件列表右键菜单
        self.listbox_context_menu = Menu(self.multi_file_listbox, tearoff=0)
        self.listbox_context_menu.add_command(label="打开文件", command=self.open_selected_file)
        self.listbox_context_menu.add_command(label="打开所在目录", command=self.show_selected_in_explorer)
        self.listbox_context_menu.add_separator()
        self.listbox_context_menu.add_command(label="移除选中", command=self.remove_selected_files)
        self.listbox_context_menu.add_command(label="清空列表", command=self.clear_file_list)
        self.multi_file_listbox.bind("<Button-3>", lambda e: self.listbox_context_menu.tk_popup(e.x_root, e.y_root))
        
        # 结果表格右键菜单
        self.treeview_context_menu = Menu(self.multi_result_tree, tearoff=0)
        self.treeview_context_menu.add_command(label="复制MD5", command=self.copy_selected_md5)
        self.treeview_context_menu.add_command(label="打开文件", command=self.open_selected_result_file)
        self.treeview_context_menu.add_command(label="打开所在目录", command=self.show_selected_result_in_explorer)
        self.treeview_context_menu.add_separator()
        self.treeview_context_menu.add_command(label="导出选中项", command=self.export_selected_results)
        self.multi_result_tree.bind("<Button-3>", lambda e: self.treeview_context_menu.tk_popup(e.x_root, e.y_root))
    
    def setup_drag_and_drop(self):
        """设置拖拽功能"""
        # 文本区域拖拽
        self.text_input.drop_target_register(DND_FILES)
        self.text_input.dnd_bind('<<Drop>>', self.handle_text_drop)
        
        # 文件输入拖拽
        self.file_entry.drop_target_register(DND_FILES)
        self.file_entry.dnd_bind('<<Drop>>', self.handle_file_drop)
        
        # 多文件列表拖拽
        self.multi_file_listbox.drop_target_register(DND_FILES)
        self.multi_file_listbox.dnd_bind('<<Drop>>', self.handle_multi_file_drop)
        
        # 目录输入拖拽
        self.dir_entry.drop_target_register(DND_FILES)
        self.dir_entry.dnd_bind('<<Drop>>', self.handle_dir_drop)
    
    def handle_text_drop(self, event):
        """处理文本区域拖拽"""
        file_path = self.process_dropped_path(event.data)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.text_input.delete('1.0', tk.END)
                self.text_input.insert('1.0', content)
                self.input_method.set("text")
                self.toggle_input_method()
                self.add_to_recent_files(file_path)
            except Exception as e:
                self.show_error(f"无法读取文件: {str(e)}")
    
    def handle_file_drop(self, event):
        """处理文件拖拽"""
        file_path = self.process_dropped_path(event.data)
        if os.path.isfile(file_path):
            self.file_path.set(file_path)
            self.input_method.set("file")
            self.toggle_input_method()
            self.add_to_recent_files(file_path)
    
    def handle_multi_file_drop(self, event):
        """处理多文件拖拽"""
        files = [self.process_dropped_path(f) for f in self.parse_dropped_files(event.data)]
        valid_files = [f for f in files if os.path.isfile(f)]
        
        if valid_files:
            for file_path in valid_files:
                if file_path not in self.multi_file_listbox.get(0, tk.END):
                    self.multi_file_listbox.insert(tk.END, file_path)
                    self.add_to_recent_files(file_path)
            self.input_method.set("multi_file")
            self.toggle_input_method()
    
    def handle_dir_drop(self, event):
        """处理目录拖拽"""
        path = self.process_dropped_path(event.data)
        if os.path.isdir(path):
            self.dir_path.set(path)
            self.input_method.set("directory")
            self.toggle_input_method()
            self.add_to_recent_files(path)
    
    def process_dropped_path(self, path):
        """处理拖拽路径"""
        return path.strip('{}').replace('\\', '/')
    
    def parse_dropped_files(self, data):
        """解析拖拽的文件列表"""
        if isinstance(data, str):
            return [f.strip('{}') for f in data.split()]
        return [data.strip('{}')]
    
    def add_to_recent_files(self, path):
        """添加到最近使用的文件"""
        if path in self.settings["recent_files"]:
            self.settings["recent_files"].remove(path)
        self.settings["recent_files"].insert(0, path)
        if len(self.settings["recent_files"]) > 10:
            self.settings["recent_files"] = self.settings["recent_files"][:10]
        self.save_config()
    
    def toggle_input_method(self):
        """切换输入方式"""
        # 隐藏所有输入区域
        self.text_frame.pack_forget()
        self.file_frame.pack_forget()
        self.multi_file_frame.pack_forget()
        self.dir_frame.pack_forget()
        self.multi_result_frame.pack_forget()
        
        # 显示选中的输入区域
        method = self.input_method.get()
        if method == "text":
            self.text_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
            self.result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        elif method == "file":
            self.file_frame.pack(pady=5, padx=10, fill=tk.X)
            self.result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        elif method == "multi_file":
            self.multi_file_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
            self.multi_result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        elif method == "directory":
            self.dir_frame.pack(pady=5, padx=10, fill=tk.X)
            self.multi_result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        # 更新标题
        algorithm = self.hash_algorithm.get().upper()
        self.result_frame.config(text=f"{algorithm}结果")
        self.multi_result_frame.config(text=f"文件{algorithm}结果")
    
    def toggle_compare_mode(self):
        """切换比对模式"""
        if self.compare_var.get():
            self.compare_target_frame.pack(fill=tk.X, padx=5, pady=5)
            self.settings["auto_compare"] = True
        else:
            self.compare_target_frame.pack_forget()
            self.compare_result_var.set("")
            self.settings["auto_compare"] = False
        self.save_config()
    
    def on_hash_algorithm_change(self, event=None):
        """哈希算法改变事件"""
        self.toggle_input_method()
    
    def browse_file(self):
        """浏览文件"""
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.add_to_recent_files(filename)
    
    def browse_directory(self):
        """浏览目录"""
        directory = filedialog.askdirectory()
        if directory:
            self.dir_path.set(directory)
            self.add_to_recent_files(directory)
    
    def add_files(self):
        """添加多个文件"""
        files = filedialog.askopenfilenames()
        if files:
            for file_path in files:
                if file_path not in self.multi_file_listbox.get(0, tk.END):
                    self.multi_file_listbox.insert(tk.END, file_path)
                    self.add_to_recent_files(file_path)
    
    def add_directory(self):
        """添加目录中的所有文件"""
        directory = filedialog.askdirectory()
        if directory:
            self.add_directory_files(directory)
            self.add_to_recent_files(directory)
    
    def add_directory_files(self, directory):
        """添加目录中的文件到列表"""
        recursive = self.recursive_var.get()
        ext_filter = self.filter_ext.get().strip()
        
        for root, _, files in os.walk(directory):
            for filename in files:
                if ext_filter and not filename.lower().endswith(ext_filter.lower()):
                    continue
                file_path = os.path.join(root, filename)
                if file_path not in self.multi_file_listbox.get(0, tk.END):
                    self.multi_file_listbox.insert(tk.END, file_path)
            
            if not recursive:
                break
    
    def remove_selected_files(self):
        """移除选中的文件"""
        selected = self.multi_file_listbox.curselection()
        for index in reversed(selected):
            self.multi_file_listbox.delete(index)
    
    def clear_file_list(self):
        """清空文件列表"""
        self.multi_file_listbox.delete(0, tk.END)
    
    def show_in_explorer(self):
        """在资源管理器中显示文件"""
        file_path = self.file_path.get()
        if file_path and os.path.exists(file_path):
            os.startfile(os.path.dirname(file_path))
    
    def show_dir_in_explorer(self):
        """在资源管理器中显示目录"""
        dir_path = self.dir_path.get()
        if dir_path and os.path.exists(dir_path):
            os.startfile(dir_path)
    
    def open_selected_file(self):
        """打开选中的文件"""
        selected = self.multi_file_listbox.curselection()
        if selected:
            file_path = self.multi_file_listbox.get(selected[0])
            if os.path.exists(file_path):
                os.startfile(file_path)
    
    def show_selected_in_explorer(self):
        """在资源管理器中显示选中的文件"""
        selected = self.multi_file_listbox.curselection()
        if selected:
            file_path = self.multi_file_listbox.get(selected[0])
            if os.path.exists(file_path):
                os.startfile(os.path.dirname(file_path))
    
    def open_selected_result_file(self):
        """打开结果表格中选中的文件"""
        selected = self.multi_result_tree.selection()
        if selected:
            item = self.multi_result_tree.item(selected[0])
            file_path = os.path.join(item['values'][1], item['values'][0])
            if os.path.exists(file_path):
                os.startfile(file_path)
    
    def show_selected_result_in_explorer(self):
        """在资源管理器中显示结果表格中选中的文件"""
        selected = self.multi_result_tree.selection()
        if selected:
            item = self.multi_result_tree.item(selected[0])
            file_path = os.path.join(item['values'][1], item['values'][0])
            if os.path.exists(file_path):
                os.startfile(os.path.dirname(file_path))
    
    def copy_selected_md5(self):
        """复制结果表格中选中的MD5值"""
        selected = self.multi_result_tree.selection()
        if selected:
            item = self.multi_result_tree.item(selected[0])
            md5 = item['values'][2]
            self.clipboard_clear()
            self.clipboard_append(md5)
            self.status_var.set("MD5值已复制到剪贴板")
    
    def start_calculation_thread(self):
        """启动计算线程"""
        # 禁用计算按钮，启用停止按钮
        self.calculate_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_flag = False
        
        # 重置进度条
        self.progress_var.set(0)
        self.status_var.set("正在计算...")
        
        # 在新线程中执行计算
        self.calculation_thread = threading.Thread(target=self.calculate_hash)
        self.calculation_thread.daemon = True
        self.calculation_thread.start()
        
        # 检查线程状态的定时器
        self.after(100, self.check_thread)
    
    def check_thread(self):
        """检查线程状态"""
        if self.calculation_thread.is_alive():
            self.after(100, self.check_thread)
        else:
            self.calculate_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set("计算完成")
    
    def stop_calculation(self):
        """停止计算"""
        self.stop_flag = True
        self.status_var.set("正在停止...")
    
    def calculate_hash(self):
        """计算哈希值"""
        try:
            algorithm = self.hash_algorithm.get()
            if self.input_method.get() == "text":
                self.calculate_text_hash(algorithm)
            elif self.input_method.get() == "file":
                self.calculate_single_file_hash(algorithm)
            elif self.input_method.get() == "multi_file":
                self.calculate_multiple_files_hash(algorithm)
            elif self.input_method.get() == "directory":
                self.calculate_directory_hash(algorithm)
        except Exception as e:
            self.show_error(f"计算过程中发生错误: {str(e)}")
    
    def calculate_text_hash(self, algorithm):
        """计算文本哈希"""
        content = self.text_input.get("1.0", tk.END).encode('utf-8')
        if not content.strip():
            self.show_warning("请输入要计算哈希的文本内容")
            return
        
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(content)
        hash_value = hash_obj.hexdigest()
        
        if self.uppercase_var.get():
            hash_value = hash_value.upper()
        
        self.display_result(hash_value)
        
        # 添加到历史记录
        self.add_to_history({
            "type": "text",
            "content": self.text_input.get("1.0", tk.END).strip(),
            "hash": hash_value,
            "algorithm": algorithm,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        # 比对模式处理
        if self.compare_var.get():
            self.handle_compare(hash_value)
    
    def calculate_single_file_hash(self, algorithm):
        """计算单个文件哈希"""
        filepath = self.file_path.get()
        if not filepath:
            self.show_warning("请选择要计算哈希的文件")
            return
        
        if not os.path.exists(filepath):
            self.show_error("文件不存在或路径无效")
            return
        
        # 计算大文件的哈希
        hash_obj = hashlib.new(algorithm)
        total_size = os.path.getsize(filepath)
        processed_size = 0
        
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    if self.stop_flag:
                        self.status_var.set("计算已停止")
                        return
                    
                    hash_obj.update(chunk)
                    processed_size += len(chunk)
                    progress = (processed_size / total_size) * 100
                    self.progress_var.set(progress)
            
            hash_value = hash_obj.hexdigest()
            if self.uppercase_var.get():
                hash_value = hash_value.upper()
            
            result_text = f"文件: {os.path.basename(filepath)}\n{algorithm.upper()}: {hash_value}"
            self.display_result(result_text)
            
            # 添加到历史记录
            self.add_to_history({
                "type": "file",
                "path": filepath,
                "hash": hash_value,
                "algorithm": algorithm,
                "size": total_size,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # 比对模式处理
            if self.compare_var.get():
                self.handle_compare(hash_value)
        
        except IOError as e:
            self.show_error(f"读取文件时出错: {str(e)}")
    
    def calculate_multiple_files_hash(self, algorithm):
        """计算多个文件哈希"""
        file_count = self.multi_file_listbox.size()
        if file_count == 0:
            self.show_warning("请添加要计算哈希的文件")
            return
        
        # 清空结果表格
        for item in self.multi_result_tree.get_children():
            self.multi_result_tree.delete(item)
        
        # 清空哈希字典
        self.file_md5_dict.clear()
        
        # 计算每个文件的哈希
        for i in range(file_count):
            if self.stop_flag:
                self.status_var.set("计算已停止")
                return
            
            filepath = self.multi_file_listbox.get(i)
            if not os.path.exists(filepath):
                continue
            
            # 更新进度
            progress = (i / file_count) * 100
            self.progress_var.set(progress)
            self.status_var.set(f"正在计算: {os.path.basename(filepath)} ({i+1}/{file_count})")
            
            # 计算哈希
            hash_obj = hashlib.new(algorithm)
            try:
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        if self.stop_flag:
                            return
                        hash_obj.update(chunk)
                
                hash_value = hash_obj.hexdigest()
                if self.uppercase_var.get():
                    hash_value = hash_value.upper()
                
                # 存储结果
                file_size = os.path.getsize(filepath)
                modified_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
                self.file_md5_dict[filepath] = hash_value
                
                # 添加到结果表格
                self.multi_result_tree.insert("", tk.END, values=(
                    os.path.basename(filepath),
                    os.path.dirname(filepath),
                    hash_value,
                    self.format_file_size(file_size),
                    modified_time
                ))
                
                # 比对模式处理
                if self.compare_var.get() and self.compare_target.get():
                    if hash_value == self.compare_target.get().strip():
                        self.multi_result_tree.item(self.multi_result_tree.get_children()[-1], tags=('match',))
                        self.multi_result_tree.tag_configure('match', background='lightgreen')
            
            except IOError as e:
                self.multi_result_tree.insert("", tk.END, values=(
                    os.path.basename(filepath),
                    os.path.dirname(filepath),
                    f"错误: {str(e)}",
                    "-",
                    "-"
                ))
        
        # 自动检测重复文件
        if self.auto_check_duplicates_var.get():
            self.find_duplicate_files()
        
        self.progress_var.set(100)
        
        # 添加到历史记录
        self.add_to_history({
            "type": "multi_file",
            "count": file_count,
            "algorithm": algorithm,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    def calculate_directory_hash(self, algorithm):
        """计算目录中所有文件的哈希"""
        dir_path = self.dir_path.get()
        if not dir_path:
            self.show_warning("请选择要计算哈希的目录")
            return
        
        if not os.path.exists(dir_path):
            self.show_error("目录不存在或路径无效")
            return
        
        # 获取目录中所有文件
        recursive = self.recursive_var.get()
        ext_filter = self.filter_ext.get().strip()
        file_paths = []
        
        for root, _, files in os.walk(dir_path):
            for filename in files:
                if ext_filter and not filename.lower().endswith(ext_filter.lower()):
                    continue
                file_paths.append(os.path.join(root, filename))
            
            if not recursive:
                break
        
        if not file_paths:
            self.show_warning("目录中没有符合条件的文件")
            return
        
        # 清空结果表格
        for item in self.multi_result_tree.get_children():
            self.multi_result_tree.delete(item)
        
        # 清空哈希字典
        self.file_md5_dict.clear()
        
        # 计算每个文件的哈希
        total_files = len(file_paths)
        for i, filepath in enumerate(file_paths):
            if self.stop_flag:
                self.status_var.set("计算已停止")
                return
            
            # 更新进度
            progress = (i / total_files) * 100
            self.progress_var.set(progress)
            self.status_var.set(f"正在计算: {os.path.basename(filepath)} ({i+1}/{total_files})")
            
            # 计算哈希
            hash_obj = hashlib.new(algorithm)
            try:
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        if self.stop_flag:
                            return
                        hash_obj.update(chunk)
                
                hash_value = hash_obj.hexdigest()
                if self.uppercase_var.get():
                    hash_value = hash_value.upper()
                
                # 存储结果
                file_size = os.path.getsize(filepath)
                modified_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
                self.file_md5_dict[filepath] = hash_value
                
                # 添加到结果表格
                self.multi_result_tree.insert("", tk.END, values=(
                    os.path.basename(filepath),
                    os.path.dirname(filepath),
                    hash_value,
                    self.format_file_size(file_size),
                    modified_time
                ))
                
                # 比对模式处理
                if self.compare_var.get() and self.compare_target.get():
                    if hash_value == self.compare_target.get().strip():
                        self.multi_result_tree.item(self.multi_result_tree.get_children()[-1], tags=('match',))
                        self.multi_result_tree.tag_configure('match', background='lightgreen')
            
            except IOError as e:
                self.multi_result_tree.insert("", tk.END, values=(
                    os.path.basename(filepath),
                    os.path.dirname(filepath),
                    f"错误: {str(e)}",
                    "-",
                    "-"
                ))
        
        # 自动检测重复文件
        if self.auto_check_duplicates_var.get():
            self.find_duplicate_files()
        
        self.progress_var.set(100)
        
        # 添加到历史记录
        self.add_to_history({
            "type": "directory",
            "path": dir_path,
            "count": total_files,
            "algorithm": algorithm,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    def find_duplicate_files(self):
        """找出哈希相同的文件"""
        # 找出哈希相同的文件
        hash_to_files = {}
        for filepath, hash_value in self.file_md5_dict.items():
            if hash_value not in hash_to_files:
                hash_to_files[hash_value] = []
            hash_to_files[hash_value].append(filepath)
        
        # 标记重复文件
        duplicate_count = 0
        for hash_value, files in hash_to_files.items():
            if len(files) > 1:
                duplicate_count += len(files)
                for filepath in files:
                    for item in self.multi_result_tree.get_children():
                        values = self.multi_result_tree.item(item, 'values')
                        if values[0] == os.path.basename(filepath) and values[1] == os.path.dirname(filepath):
                            self.multi_result_tree.item(item, tags=('duplicate',))
                            self.multi_result_tree.tag_configure('duplicate', background='lightyellow')
                            break
        
        if duplicate_count > 0:
            self.status_var.set(f"发现 {duplicate_count} 个重复文件")
    
    def handle_compare(self, hash_value):
        """处理比对逻辑"""
        compare_target = self.compare_target.get().strip()
        if not compare_target:
            return
        
        if hash_value == compare_target:
            self.compare_result_var.set("比对结果: 匹配")
            self.compare_result_label.config(foreground="green")
        else:
            self.compare_result_var.set("比对结果: 不匹配")
            self.compare_result_label.config(foreground="red")
    
    def display_result(self, result):
        """显示结果"""
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", result)
        self.result_text.config(state="disabled")
    
    def clear_result(self):
        """清空结果"""
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        self.compare_result_var.set("")
    
    def copy_result(self):
        """复制结果"""
        if self.input_method.get() in ["multi_file", "directory"]:
            # 复制多文件结果
            result = ""
            for item in self.multi_result_tree.get_children():
                values = self.multi_result_tree.item(item, 'values')
                result += f"{values[0]}\t{values[1]}\t{values[2]}\t{values[3]}\t{values[4]}\n"
        else:
            # 复制单结果
            result = self.result_text.get("1.0", tk.END).strip()
        
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)
            self.status_var.set("结果已复制到剪贴板")
        else:
            self.show_warning("没有可复制的哈希结果")
    
    def save_result(self):
        """保存结果为文本文件"""
        if self.input_method.get() in ["multi_file", "directory"]:
            # 保存多文件结果
            default_filename = f"{self.hash_algorithm.get()}_results.txt"
            result = ""
            for item in self.multi_result_tree.get_children():
                values = self.multi_result_tree.item(item, 'values')
                result += f"{values[0]}\t{values[1]}\t{values[2]}\t{values[3]}\t{values[4]}\n"
        else:
            # 保存单结果
            default_filename = f"{self.hash_algorithm.get()}_result.txt"
            result = self.result_text.get("1.0", tk.END).strip()
        
        if not result:
            self.show_warning("没有可保存的哈希结果")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=default_filename)
        
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(result)
                self.status_var.set(f"结果已保存到: {filepath}")
                self.add_to_recent_files(filepath)
            except IOError as e:
                self.show_error(f"保存文件时出错: {str(e)}")
    
    def export_result(self):
        """导出结果为CSV或JSON"""
        if self.input_method.get() in ["multi_file", "directory"]:
            # 导出多文件结果
            default_filename = f"{self.hash_algorithm.get()}_results"
            data = []
            for item in self.multi_result_tree.get_children():
                values = self.multi_result_tree.item(item, 'values')
                data.append({
                    "filename": values[0],
                    "path": values[1],
                    "hash": values[2],
                    "size": values[3],
                    "modified": values[4]
                })
        else:
            # 导出单结果
            default_filename = f"{self.hash_algorithm.get()}_result"
            content = self.result_text.get("1.0", tk.END).strip()
            if not content:
                self.show_warning("没有可导出的哈希结果")
                return
            
            if "\n" in content:
                # 文件结果
                parts = content.split("\n")
                data = {
                    "filename": parts[0].replace("文件: ", ""),
                    "hash": parts[1].split(": ")[1],
                    "algorithm": self.hash_algorithm.get()
                }
            else:
                # 文本结果
                data = {
                    "hash": content,
                    "algorithm": self.hash_algorithm.get()
                }
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=default_filename)
        
        if not filepath:
            return
        
        try:
            if filepath.lower().endswith('.csv'):
                if isinstance(data, list):
                    with open(filepath, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=data[0].keys())
                        writer.writeheader()
                        writer.writerows(data)
                else:
                    with open(filepath, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        for key, value in data.items():
                            writer.writerow([key, value])
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
            
            self.status_var.set(f"结果已导出到: {filepath}")
            self.add_to_recent_files(filepath)
        except IOError as e:
            self.show_error(f"导出文件时出错: {str(e)}")
    
    def export_selected_results(self):
        """导出选中的结果"""
        selected = self.multi_result_tree.selection()
        if not selected:
            self.show_warning("请先选择要导出的项目")
            return
        
        default_filename = f"{self.hash_algorithm.get()}_selected_results"
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=default_filename)
        
        if not filepath:
            return
        
        data = []
        for item in selected:
            values = self.multi_result_tree.item(item, 'values')
            data.append({
                "filename": values[0],
                "path": values[1],
                "hash": values[2],
                "size": values[3],
                "modified": values[4]
            })
        
        try:
            if filepath.lower().endswith('.csv'):
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
            
            self.status_var.set(f"选中结果已导出到: {filepath}")
            self.add_to_recent_files(filepath)
        except IOError as e:
            self.show_error(f"导出文件时出错: {str(e)}")
    
    def clear_all(self):
        """清空所有输入和结果"""
        self.text_input.delete("1.0", tk.END)
        self.file_path.set("")
        self.dir_path.set("")
        self.multi_file_listbox.delete(0, tk.END)
        self.compare_target.set("")
        self.compare_result_var.set("")
        
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        
        for item in self.multi_result_tree.get_children():
            self.multi_result_tree.delete(item)
        
        self.progress_var.set(0)
        self.status_var.set("就绪")
    
    def format_file_size(self, size):
        """格式化文件大小显示"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def sort_treeview(self, col, reverse):
        """表格排序"""
        data = [(self.multi_result_tree.set(child, col), child) 
                for child in self.multi_result_tree.get_children('')]
        
        # 尝试转换为数字排序
        try:
            data.sort(key=lambda x: float(x[0].split()[0]), reverse=reverse)
        except ValueError:
            data.sort(reverse=reverse)
        
        for index, (_, child) in enumerate(data):
            self.multi_result_tree.move(child, '', index)
        
        # 反转排序顺序
        self.multi_result_tree.heading(col, command=lambda: self.sort_treeview(col, not reverse))
    
    def show_history_menu(self):
        """显示历史记录菜单"""
        if not self.history:
            self.show_warning("没有历史记录")
            return
        
        menu = Menu(self, tearoff=0)
        
        # 只显示最近10条记录
        for item in self.history[-10:]:
            if item["type"] == "text":
                label = f"文本: {item['content'][:30]}... - {item['hash']}"
            elif item["type"] == "file":
                label = f"文件: {os.path.basename(item['path'])} - {item['hash']}"
            else:
                label = f"{item['type']} - {item['time']}"
            
            menu.add_command(
                label=label,
                command=lambda h=item['hash']: self.compare_target.set(h))
        
        menu.tk_popup(*self.winfo_pointerxy())
    
    def show_history_dialog(self):
        """显示历史记录对话框"""
        if not self.history:
            self.show_warning("没有历史记录")
            return
        
        history_win = tk.Toplevel(self)
        history_win.title("历史记录")
        history_win.geometry("800x600")
        
        # 创建表格
        tree = ttk.Treeview(history_win, columns=("type", "content", "hash", "time"), show="headings")
        tree.heading("type", text="类型")
        tree.heading("content", text="内容")
        tree.heading("hash", text="哈希值")
        tree.heading("time", text="时间")
        
        tree.column("type", width=100)
        tree.column("content", width=300)
        tree.column("hash", width=200)
        tree.column("time", width=150)
        
        # 添加数据
        for item in reversed(self.history):
            if item["type"] == "text":
                content = item["content"][:50] + "..." if len(item["content"]) > 50 else item["content"]
            elif item["type"] == "file":
                content = os.path.basename(item["path"])
            elif item["type"] == "multi_file":
                content = f"{item['count']} 个文件"
            elif item["type"] == "directory":
                content = os.path.basename(item["path"])
            else:
                content = ""
            
            tree.insert("", tk.END, values=(
                item["type"],
                content,
                item.get("hash", ""),
                item["time"]
            ))
        
        # 右键菜单
        history_menu = Menu(history_win, tearoff=0)
        history_menu.add_command(label="复制哈希值", 
                               command=lambda: self.copy_history_item(tree))
        history_menu.add_command(label="删除记录", 
                               command=lambda: self.delete_history_item(tree, history_win))
        
        tree.bind("<Button-3>", lambda e: history_menu.tk_popup(e.x_root, e.y_root))
        
        # 布局
        scroll = ttk.Scrollbar(history_win, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def copy_history_item(self, tree):
        """复制历史记录中的哈希值"""
        selected = tree.selection()
        if selected:
            item = tree.item(selected[0])
            hash_value = item['values'][2]
            if hash_value:
                self.clipboard_clear()
                self.clipboard_append(hash_value)
                self.status_var.set("哈希值已复制到剪贴板")
    
    def delete_history_item(self, tree, window):
        """删除历史记录项"""
        selected = tree.selection()
        if selected:
            item = tree.item(selected[0])
            index = len(self.history) - 1 - tree.index(selected[0])
            del self.history[index]
            self.save_history()
            tree.delete(selected[0])
            window.destroy()
            self.show_history_dialog()
    
    def change_theme(self, theme):
        """切换主题"""
        self.settings["theme"] = theme
        self.save_config()
        self.setup_theme()
    
    def show_about(self):
        """显示关于对话框"""
        about_win = tk.Toplevel(self)
        about_win.title("关于")
        about_win.geometry("400x300")
        about_win.resizable(False, False)
        
        about_text = f"""
终极MD5计算工具

版本: 1.0
作者: DeepSeek Chat

功能:
- 支持MD5、SHA1、SHA256、SHA512算法
- 支持文本、文件、多文件和目录计算
- 支持拖拽操作
- 支持哈希值比对
- 自动检测重复文件
- 历史记录功能
- 深色/浅色主题

© 2023 深度求索 版权所有
"""
        ttk.Label(about_win, text=about_text, justify=tk.LEFT).pack(padx=20, pady=20)
        ttk.Button(about_win, text="确定", command=about_win.destroy).pack(pady=10)
    
    def show_warning(self, message):
        """显示警告消息"""
        messagebox.showwarning("警告", message)
    
    def show_error(self, message):
        """显示错误消息"""
        messagebox.showerror("错误", message)
    
    def on_closing(self):
        """窗口关闭事件"""
        self.save_config()
        self.destroy()

if __name__ == "__main__":
    app = UltimateMD5CalculatorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()