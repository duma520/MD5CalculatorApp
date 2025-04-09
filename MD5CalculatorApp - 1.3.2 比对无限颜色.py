import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, Menu
import hashlib
import os
import threading
import json
import csv
from datetime import datetime
from tkinterdnd2 import TkinterDnD, DND_FILES

class UltimateHashCalculator(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("专业哈希计算工具")
        self.geometry("1000x700")
        self.minsize(800, 600)
        
        # 配置设置
        self.config_file = "hash_tool_config.json"
        self.history_file = "hash_history.json"
        self.max_history = 50
        self.current_theme = "light"
        
        # 初始化设置
        self.settings = {
            "theme": "light",
            "uppercase": True,
            "auto_compare": False,
            "auto_check_duplicates": True,
            "recent_files": [],
            "window_size": "1000x700",
            "layout": "horizontal"
        }
        
        # 历史记录
        self.history = []
        
        # 加载配置和历史
        self.load_config()
        self.load_history()
        
        # 创建UI
        self.setup_ui()
        
        # 窗口事件绑定
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.bind("<Configure>", self.on_window_resize)
        
        # 线程控制
        self.calculation_thread = None
        self.stop_flag = False
        self.file_md5_dict = {}
        self.lock = threading.Lock()

        # 动态颜色生成配置
        self.color_hue_step = 30  # 色相间隔（单位：度），值越小颜色越多，色相间隔（单位：度），值越小颜色越多，建议 15~45
        self.match_color = "#90EE90"  # 比对模式匹配文件的颜色

        # 颜色设置 - 用于标记重复文件
        # self.color_palette = ['lightgreen', 'lightblue', 'lightyellow', 'lightpink', 'lightcyan']

    #  HSL 转 RGB 
    def hsl_to_rgb(self, h, s, l):
        """将HSL颜色转换为RGB十六进制字符串"""
        h /= 360.0
        s /= 100.0
        l /= 100.0
        
        if s == 0:
            r = g = b = l
        else:
            def hue_to_rgb(p, q, t):
                t += 1 if t < 0 else 0
                t -= 1 if t > 1 else 0
                if t < 1/6: return p + (q - p) * 6 * t
                if t < 1/2: return q
                if t < 2/3: return p + (q - p) * (2/3 - t) * 6
                return p
            
            q = l * (1 + s) if l < 0.5 else l + s - l * s
            p = 2 * l - q
            r = hue_to_rgb(p, q, h + 1/3)
            g = hue_to_rgb(p, q, h)
            b = hue_to_rgb(p, q, h - 1/3)
        
        r, g, b = int(round(r*255)), int(round(g*255)), int(round(b*255))
        return f"#{r:02x}{g:02x}{b:02x}"


    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded_settings = json.load(f)
                    self.settings.update(loaded_settings)
                    self.current_theme = self.settings["theme"]
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

    def setup_ui(self):
        """设置主界面"""
        # 主容器
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 左侧面板 (输入区域)
        self.left_panel = ttk.Frame(self.main_container)
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 右侧面板 (结果区域)
        self.right_panel = ttk.Frame(self.main_container)
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 输入方式选择
        self.setup_input_methods()
        
        # 输入内容区域
        self.setup_input_content()
        
        # 计算选项
        self.setup_calculation_options()
        
        # 计算按钮
        self.setup_action_buttons()
        
        # 结果显示区域
        self.setup_result_display()
        
        # 状态栏
        self.setup_status_bar()
        
        # 菜单
        self.setup_menus()
        
        # 拖拽支持
        self.setup_drag_drop()
        
        # 应用主题
        self.apply_theme()
        
        # 初始布局
        self.adjust_layout()

    def setup_input_methods(self):
        """设置输入方式选择区域"""
        input_frame = ttk.LabelFrame(self.left_panel, text="输入方式", padding=5)
        input_frame.pack(fill=tk.X, pady=(0,5))
        
        # 输入方式单选按钮
        self.input_method = tk.StringVar(value="text")
        methods = [
            ("文本", "text"),
            ("文件", "file"),
            ("多文件", "multi_file"),
            ("目录", "directory")
        ]
        
        for text, value in methods:
            ttk.Radiobutton(
                input_frame, text=text, variable=self.input_method, 
                value=value, command=self.toggle_input_method
            ).pack(side=tk.LEFT, padx=5)
        
        # 哈希算法选择
        ttk.Label(input_frame, text="算法:").pack(side=tk.LEFT, padx=(10,2))
        self.hash_algorithm = tk.StringVar(value="md5")
        hash_menu = ttk.Combobox(
            input_frame, textvariable=self.hash_algorithm,
            values=["md5", "sha1", "sha256", "sha512"], 
            state="readonly", width=8)
        hash_menu.pack(side=tk.LEFT)
        hash_menu.bind("<<ComboboxSelected>>", self.on_hash_algorithm_change)

    def setup_input_content(self):
        """设置输入内容区域"""
        container = ttk.Frame(self.left_panel)
        container.pack(fill=tk.BOTH, expand=True)
        
        # 文本输入
        self.text_frame = ttk.LabelFrame(container, text="文本输入", padding=5)
        self.text_input = scrolledtext.ScrolledText(
            self.text_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        # 文件输入
        self.file_frame = ttk.LabelFrame(container, text="文件输入", padding=5)
        self.file_path = tk.StringVar()
        self.file_entry = ttk.Entry(
            self.file_frame, textvariable=self.file_path, state="readonly")
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        btn_frame = ttk.Frame(self.file_frame)
        btn_frame.pack(side=tk.RIGHT)
        
        ttk.Button(btn_frame, text="...", width=3, 
                  command=self.browse_file).pack(side=tk.LEFT, padx=1)
        ttk.Button(btn_frame, text="↗", width=3,
                  command=self.show_in_explorer).pack(side=tk.LEFT, padx=1)
        
        # 多文件输入
        self.multi_file_frame = ttk.LabelFrame(container, text="多文件输入", padding=5)
        
        # 多文件列表和按钮
        list_btn_frame = ttk.Frame(self.multi_file_frame)
        list_btn_frame.pack(fill=tk.BOTH, expand=True)
        
        # 文件列表
        self.multi_file_listbox = tk.Listbox(
            list_btn_frame, selectmode=tk.EXTENDED, 
            font=('Consolas', 9))
        scroll = ttk.Scrollbar(
            list_btn_frame, orient=tk.VERTICAL, command=self.multi_file_listbox.yview)
        self.multi_file_listbox.configure(yscrollcommand=scroll.set)
        
        self.multi_file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 操作按钮
        btn_frame = ttk.Frame(self.multi_file_frame)
        btn_frame.pack(fill=tk.X, pady=(5,0))
        
        ttk.Button(btn_frame, text="添加文件", 
                  command=self.add_files).pack(side=tk.LEFT, expand=True, padx=1)
        ttk.Button(btn_frame, text="添加目录", 
                  command=self.add_directory).pack(side=tk.LEFT, expand=True, padx=1)
        ttk.Button(btn_frame, text="移除", 
                  command=self.remove_selected_files).pack(side=tk.LEFT, expand=True, padx=1)
        ttk.Button(btn_frame, text="清空", 
                  command=self.clear_file_list).pack(side=tk.LEFT, expand=True, padx=1)
        
        # 目录输入
        self.dir_frame = ttk.LabelFrame(container, text="目录输入", padding=5)
        
        # 目录路径和按钮
        self.dir_path = tk.StringVar()
        self.dir_entry = ttk.Entry(self.dir_frame, textvariable=self.dir_path, 
                 state="readonly")
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)

        
        btn_frame = ttk.Frame(self.dir_frame)
        btn_frame.pack(side=tk.RIGHT)
        
        ttk.Button(btn_frame, text="...", width=3,
                  command=self.browse_directory).pack(side=tk.LEFT, padx=1)
        ttk.Button(btn_frame, text="↗", width=3,
                  command=self.show_dir_in_explorer).pack(side=tk.LEFT, padx=1)
        
        # 文件过滤器
        filter_frame = ttk.Frame(self.dir_frame)
        filter_frame.pack(fill=tk.X, pady=(5,0))
        
        ttk.Label(filter_frame, text="扩展名:").pack(side=tk.LEFT)
        self.filter_ext = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.filter_ext, 
                 width=8).pack(side=tk.LEFT, padx=2)
        
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="包含子目录", 
                       variable=self.recursive_var).pack(side=tk.LEFT, padx=5)
        
        # 初始显示文本输入
        self.text_frame.pack(fill=tk.BOTH, expand=True)

    def setup_calculation_options(self):
        """设置计算选项区域"""
        opt_frame = ttk.LabelFrame(self.left_panel, text="计算选项", padding=5)
        opt_frame.pack(fill=tk.X, pady=(5,0))
        
        # 选项复选框
        self.uppercase_var = tk.BooleanVar(value=self.settings["uppercase"])
        ttk.Checkbutton(opt_frame, text="大写结果", 
                       variable=self.uppercase_var).pack(side=tk.LEFT, padx=5)
        
        self.compare_var = tk.BooleanVar(value=self.settings["auto_compare"])
        ttk.Checkbutton(opt_frame, text="比对模式", 
                       variable=self.compare_var,
                       command=self.toggle_compare_mode).pack(side=tk.LEFT, padx=5)
        
        self.auto_check_duplicates_var = tk.BooleanVar(
            value=self.settings["auto_check_duplicates"])
        ttk.Checkbutton(opt_frame, text="检测重复", 
                       variable=self.auto_check_duplicates_var).pack(side=tk.LEFT, padx=5)
        
        # 比对目标
        self.compare_target_frame = ttk.Frame(opt_frame)
        ttk.Label(self.compare_target_frame, text="目标:").pack(side=tk.LEFT)
        self.compare_target = tk.StringVar()
        ttk.Entry(self.compare_target_frame, textvariable=self.compare_target, 
                 width=30).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.compare_target_frame, text="历史", width=5,
                  command=self.show_history_menu).pack(side=tk.LEFT)
        
        if self.settings["auto_compare"]:
            self.compare_target_frame.pack(side=tk.LEFT, padx=5)

    def setup_action_buttons(self):
        """设置操作按钮区域"""
        btn_frame = ttk.Frame(self.left_panel)
        btn_frame.pack(fill=tk.X, pady=(5,0))
        
        # 计算按钮
        self.calculate_button = ttk.Button(
            btn_frame, text="计算哈希", command=self.start_calculation_thread)
        self.calculate_button.pack(side=tk.LEFT, expand=True, padx=2)
        
        # 停止按钮
        self.stop_button = ttk.Button(
            btn_frame, text="停止", command=self.stop_calculation, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, expand=True, padx=2)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(
            btn_frame, variable=self.progress_var, maximum=100,
            mode='determinate').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)

    def setup_result_display(self):
        """设置结果显示区域"""
        # 结果标签
        self.result_label = ttk.Label(
            self.right_panel, text="MD5 结果", font=('Arial', 10, 'bold'))
        self.result_label.pack(fill=tk.X)
        
        # 比对结果
        self.compare_result_var = tk.StringVar()
        self.compare_result_label = ttk.Label(
            self.right_panel, textvariable=self.compare_result_var,
            font=('Arial', 10))
        self.compare_result_label.pack(fill=tk.X)
        
        # 主结果文本
        self.result_text = scrolledtext.ScrolledText(
            self.right_panel, wrap=tk.WORD, state="disabled", 
            font=('Consolas', 10), height=10)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # 多文件结果表格
        self.multi_result_frame = ttk.Frame(self.right_panel)
        
        # 创建Treeview和滚动条
        self.multi_result_tree = ttk.Treeview(
            self.multi_result_frame, 
            columns=("file", "path", "md5", "size", "modified"), 
            show="headings", selectmode="extended")
        
        # 设置列
        columns = [
            ("file", "文件名", 200),
            ("path", "路径", 250),
            ("md5", "哈希值", 250),
            ("size", "大小", 80),
            ("modified", "修改时间", 120)
        ]
        
        for col_id, col_text, col_width in columns:
            self.multi_result_tree.heading(col_id, text=col_text)
            self.multi_result_tree.column(col_id, width=col_width, anchor=tk.W)
        
        # 修改时间和大小列右对齐
        self.multi_result_tree.column("size", anchor=tk.E)
        
        # 添加滚动条
        scroll = ttk.Scrollbar(
            self.multi_result_frame, orient=tk.VERTICAL, 
            command=self.multi_result_tree.yview)
        self.multi_result_tree.configure(yscrollcommand=scroll.set)
        
        # 布局
        self.multi_result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 结果操作按钮
        result_btn_frame = ttk.Frame(self.right_panel)
        result_btn_frame.pack(fill=tk.X, pady=(5,0))
        
        ttk.Button(result_btn_frame, text="复制", 
                  command=self.copy_result).pack(side=tk.LEFT, expand=True)
        ttk.Button(result_btn_frame, text="保存", 
                  command=self.save_result).pack(side=tk.LEFT, expand=True)
        ttk.Button(result_btn_frame, text="导出", 
                  command=self.export_result).pack(side=tk.LEFT, expand=True)
        ttk.Button(result_btn_frame, text="清空", 
                  command=self.clear_result).pack(side=tk.LEFT, expand=True)

    def setup_status_bar(self):
        """设置状态栏"""
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        
        self.status_bar = ttk.Frame(self)
        self.status_bar.pack(fill=tk.X, padx=5, pady=(0,5))
        
        ttk.Label(self.status_bar, textvariable=self.status_var, 
                 relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X)
        
        # 添加布局切换按钮
        ttk.Button(self.status_bar, text="切换布局", width=10,
                  command=self.toggle_layout).pack(side=tk.RIGHT)

    def setup_menus(self):
        """设置菜单栏"""
        menubar = tk.Menu(self)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="新建", command=self.clear_all)
        file_menu.add_separator()
        file_menu.add_command(label="打开文件...", command=self.browse_file)
        file_menu.add_command(label="打开目录...", command=self.browse_directory)
        file_menu.add_separator()
        
        # 最近文件子菜单
        recent_menu = tk.Menu(file_menu, tearoff=0)
        self.update_recent_files_menu(recent_menu)
        file_menu.add_cascade(label="最近文件", menu=recent_menu)
        
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
        
        # 视图菜单
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="浅色主题", command=lambda: self.change_theme("light"))
        view_menu.add_command(label="深色主题", command=lambda: self.change_theme("dark"))
        view_menu.add_separator()
        view_menu.add_command(label="水平布局", command=lambda: self.set_layout("horizontal"))
        view_menu.add_command(label="垂直布局", command=lambda: self.set_layout("vertical"))
        menubar.add_cascade(label="视图", menu=view_menu)
        
        # 工具菜单
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_checkbutton(label="大写结果", variable=self.uppercase_var)
        tools_menu.add_checkbutton(label="比对模式", variable=self.compare_var)
        tools_menu.add_checkbutton(label="自动检测重复", variable=self.auto_check_duplicates_var)
        tools_menu.add_separator()
        tools_menu.add_command(label="历史记录", command=self.show_history_dialog)
        menubar.add_cascade(label="工具", menu=tools_menu)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="帮助", command=self.show_help)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        
        self.config(menu=menubar)

    def update_recent_files_menu(self, menu):
        """更新最近文件菜单"""
        menu.delete(0, tk.END)
        for filepath in self.settings["recent_files"]:
            menu.add_command(
                label=os.path.basename(filepath),
                command=lambda f=filepath: self.open_recent_file(f))
        
        if not self.settings["recent_files"]:
            menu.add_command(label="无最近文件", state=tk.DISABLED)
        
        menu.add_separator()
        menu.add_command(label="清除历史", command=self.clear_recent_files)

    def open_recent_file(self, filepath):
        """打开最近文件"""
        if os.path.isfile(filepath):
            self.file_path.set(filepath)
            self.input_method.set("file")
            self.toggle_input_method()
        elif os.path.isdir(filepath):
            self.dir_path.set(filepath)
            self.input_method.set("directory")
            self.toggle_input_method()

    def clear_recent_files(self):
        """清除最近文件记录"""
        self.settings["recent_files"] = []
        self.save_config()

    def setup_drag_drop(self):
        """设置拖拽支持"""
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

    def apply_theme(self):
        """应用主题样式"""
        style = ttk.Style()
        
        if self.current_theme == "dark":
            self.configure(bg="#333333")
            style.theme_use("alt")
            
            # 配置深色主题颜色
            bg_color = "#333333"
            fg_color = "#ffffff"
            entry_bg = "#555555"
            text_bg = "#444444"
            
            style.configure(".", background=bg_color, foreground=fg_color)
            style.configure("TFrame", background=bg_color)
            style.configure("TLabel", background=bg_color, foreground=fg_color)
            style.configure("TButton", background="#555555", foreground=fg_color)
            style.configure("TEntry", fieldbackground=entry_bg, foreground=fg_color)
            style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg_color)
            style.configure("TScrollbar", background="#555555")
            style.configure("Treeview", 
                          background=text_bg, 
                          foreground=fg_color,
                          fieldbackground=text_bg)
            style.map('Treeview', background=[('selected', '#0078d7')])
            
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
            style.theme_use("clam")
            style.configure(".", background="white", foreground="black")
            style.configure("TFrame", background="white")
            style.configure("TLabel", background="white", foreground="black")
            style.configure("TButton", background="#f0f0f0", foreground="black")
            style.configure("TEntry", fieldbackground="white", foreground="black")
            style.configure("TCombobox", fieldbackground="white", foreground="black")
            
            # 文本控件样式
            self.text_input.configure(
                bg="white", fg="black", 
                insertbackground="black",
                selectbackground="#0078d7",
                selectforeground="white"
            )
            self.result_text.configure(
                bg="white", fg="black", 
                insertbackground="black",
                selectbackground="#0078d7",
                selectforeground="white"
            )
            self.multi_file_listbox.configure(
                bg="white", fg="black", 
                selectbackground="#0078d7",
                selectforeground="white"
            )

    def adjust_layout(self):
        """根据窗口大小调整布局"""
        width = self.winfo_width()
        
        if width < 900 or self.settings["layout"] == "vertical":
            # 垂直布局 (小窗口或手动选择)
            self.left_panel.pack_forget()
            self.right_panel.pack_forget()
            
            self.left_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.right_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            # 水平布局 (大窗口)
            self.left_panel.pack_forget()
            self.right_panel.pack_forget()
            
            self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    def toggle_layout(self):
        """切换布局方向"""
        if self.settings["layout"] == "vertical":
            self.set_layout("horizontal")
        else:
            self.set_layout("vertical")

    def set_layout(self, layout):
        """设置布局方向"""
        self.settings["layout"] = layout
        self.save_config()
        self.adjust_layout()

    def on_window_resize(self, event):
        """窗口大小变化事件"""
        if event.widget == self:
            self.adjust_layout()

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
            self.text_frame.pack(fill=tk.BOTH, expand=True)
            self.result_text.pack(fill=tk.BOTH, expand=True)
            self.multi_result_frame.pack_forget()
        elif method == "file":
            self.file_frame.pack(fill=tk.X)
            self.result_text.pack(fill=tk.BOTH, expand=True)
            self.multi_result_frame.pack_forget()
        elif method == "multi_file":
            self.multi_file_frame.pack(fill=tk.BOTH, expand=True)
            self.result_text.pack_forget()
            self.multi_result_frame.pack(fill=tk.BOTH, expand=True)
        elif method == "directory":
            self.dir_frame.pack(fill=tk.X)
            self.result_text.pack_forget()
            self.multi_result_frame.pack(fill=tk.BOTH, expand=True)
        
        # 更新标题
        algorithm = self.hash_algorithm.get().upper()
        self.result_label.config(text=f"{algorithm} 结果")
        self.multi_result_tree.heading("md5", text=f"{algorithm}值")

    def on_hash_algorithm_change(self, event=None):
        """哈希算法改变事件"""
        self.toggle_input_method()

    def toggle_compare_mode(self):
        """切换比对模式"""
        if self.compare_var.get():
            self.compare_target_frame.pack(side=tk.LEFT, padx=5)
            self.settings["auto_compare"] = True
        else:
            self.compare_target_frame.pack_forget()
            self.compare_result_var.set("")
            self.settings["auto_compare"] = False
        self.save_config()

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
            print(f"Error calculating hash: {str(e)}")

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
                        self.multi_result_tree.tag_configure('match', background=self.match_color)  # 使用统一的亮绿色


            
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
                        self.multi_result_tree.tag_configure('match', background=self.match_color)  # 使用统一的亮绿色


            
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
        """动态生成无限颜色标记重复文件"""
        hash_to_files = {}
        for filepath, hash_value in self.file_md5_dict.items():
            if hash_value not in hash_to_files:
                hash_to_files[hash_value] = []
            hash_to_files[hash_value].append(filepath)
        
        duplicate_count = 0
        for group_id, (hash_value, files) in enumerate(hash_to_files.items()):
            if len(files) > 1:
                duplicate_count += len(files)
                # 生成HSL颜色并转换为RGB
                hue = (group_id * self.color_hue_step) % 360
                color = self.hsl_to_rgb(hue, 80, 85)  # 使用转换方法
                
                for filepath in files:
                    for item in self.multi_result_tree.get_children():
                        values = self.multi_result_tree.item(item, 'values')
                        if values[0] == os.path.basename(filepath) and values[1] == os.path.dirname(filepath):
                            self.multi_result_tree.item(item, tags=(f'dup_group_{group_id}',))
                            self.multi_result_tree.tag_configure(f'dup_group_{group_id}', background=color)
                            break
        
        if duplicate_count > 0:
            self.status_var.set(f"发现 {duplicate_count} 个重复文件（共 {len(hash_to_files)} 组）")



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
        self.current_theme = theme
        self.settings["theme"] = theme
        self.save_config()
        self.apply_theme()

    def show_help(self):
        """显示帮助信息"""
        help_text = """
哈希计算工具使用说明:

1. 选择输入方式:
   - 文本: 直接输入要计算哈希的文本内容
   - 文件: 计算单个文件的哈希值
   - 多文件: 批量计算多个文件的哈希值
   - 目录: 计算目录下所有文件的哈希值

2. 选择哈希算法:
   - 支持MD5、SHA1、SHA256、SHA512算法

3. 计算选项:
   - 大写结果: 将哈希值转换为大写
   - 比对模式: 输入目标哈希值进行比对
   - 检测重复: 自动标记相同哈希值的文件

4. 操作:
   - 拖拽文件/目录到对应区域可直接计算
   - 右键菜单提供快捷操作
   - 结果可以复制、保存或导出

5. 其他功能:
   - 历史记录查看
   - 深色/浅色主题切换
   - 布局方向调整
"""
        messagebox.showinfo("帮助", help_text)

    def show_about(self):
        """显示关于对话框"""
        about_text = f"""
专业哈希计算工具

版本: 2.0
作者: DeepSeek Chat

功能:
- 支持MD5、SHA1、SHA256、SHA512算法
- 支持文本、文件、多文件和目录计算
- 拖拽操作支持
- 哈希值比对功能
- 自动检测重复文件
- 历史记录功能
- 深色/浅色主题切换
- 自适应布局

© 2023 深度求索 版权所有
"""
        messagebox.showinfo("关于", about_text)

    def on_closing(self):
        """窗口关闭事件"""
        self.save_config()
        self.destroy()

    def show_warning(self, message):
        """显示警告消息"""
        messagebox.showwarning("警告", message)

    def show_error(self, message):
        """显示错误消息"""
        messagebox.showerror("错误", message)

if __name__ == "__main__":
    app = UltimateHashCalculator()
    app.mainloop()