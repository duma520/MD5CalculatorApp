import os
import sys
import hashlib
import json
import csv
import threading
import sqlite3
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit,
                            QPushButton, QRadioButton, QButtonGroup, QComboBox, QCheckBox, QProgressBar, QListWidget,
                            QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox, QMenu, QAction, QTabWidget,
                            QGroupBox, QScrollArea, QStatusBar, QSizePolicy, QSplitter)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal, QSettings, QPoint
from PyQt5.QtGui import QIcon, QFont, QTextCursor, QColor
import blake3
import pyhashxx
import cityhash
import farmhash
import mmh3


class ProjectInfo:
    """项目信息元数据"""
    VERSION = "2.5.0"
    BUILD_DATE = "2025-05-15"
    AUTHOR = "杜玛"
    LICENSE = "MIT"
    COPYRIGHT = "© 永久 杜玛"
    URL = "https://github.com/duma520"
    MAINTAINER_EMAIL = "不提供"
    NAME = "专业哈希计算工具"
    DESCRIPTION = "专业哈希计算工具，支持多种哈希算法和文件处理功能。"
    HELP_TEXT = """
哈希计算工具使用说明:
1. 选择输入方式:
   - 文本: 直接输入要计算哈希的文本内容
   - 文件: 计算单个文件的哈希值
   - 多文件: 批量计算多个文件的哈希值
   - 目录: 计算目录下所有文件的哈希值
2. 选择哈希算法:
   - 支持MD5、SHA1、SHA256、SHA512等算法
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


class DatabaseManager:
    """数据库管理类"""
    def __init__(self):
        self.db_file = "hash_tool.db"
        self.init_db()
        # 添加默认主题设置
        if not self.get_setting("theme"):
            self.set_setting("theme", "default")  # 添加默认主题
    
    def init_db(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # 创建设置表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        ''')
        
        # 创建历史记录表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            content TEXT,
            path TEXT,
            hash TEXT,
            algorithm TEXT,
            size INTEGER,
            count INTEGER,
            time TEXT
        )
        ''')
        
        # 创建最近文件表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS recent_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE,
            last_used TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_setting(self, key, default=None):
        """获取设置"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else default
    
    def set_setting(self, key, value):
        """保存设置"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value) 
        VALUES (?, ?)
        ''', (key, value))
        conn.commit()
        conn.close()
    
    def add_history(self, item):
        """添加历史记录"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO history (
            type, content, path, hash, algorithm, size, count, time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item.get('type'),
            item.get('content'),
            item.get('path'),
            item.get('hash'),
            item.get('algorithm'),
            item.get('size'),
            item.get('count'),
            item.get('time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        ))
        
        # 限制历史记录数量
        cursor.execute('DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT 50)')
        
        conn.commit()
        conn.close()
    
    def get_history(self, limit=50):
        """获取历史记录"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM history ORDER BY id DESC LIMIT ?', (limit,))
        results = cursor.fetchall()
        conn.close()
        
        history = []
        for row in results:
            history.append({
                'id': row[0],
                'type': row[1],
                'content': row[2],
                'path': row[3],
                'hash': row[4],
                'algorithm': row[5],
                'size': row[6],
                'count': row[7],
                'time': row[8]
            })
        return history
    
    def delete_history(self, history_id):
        """删除历史记录"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM history WHERE id = ?', (history_id,))
        conn.commit()
        conn.close()
    
    def add_recent_file(self, path):
        """添加最近文件"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # 检查是否已存在
        cursor.execute('SELECT id FROM recent_files WHERE path = ?', (path,))
        exists = cursor.fetchone()
        
        if exists:
            # 更新最后使用时间
            cursor.execute('''
            UPDATE recent_files 
            SET last_used = ?
            WHERE path = ?
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), path))
        else:
            # 插入新记录
            cursor.execute('''
            INSERT INTO recent_files (path, last_used)
            VALUES (?, ?)
            ''', (path, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        
        # 限制最近文件数量
        cursor.execute('DELETE FROM recent_files WHERE id NOT IN (SELECT id FROM recent_files ORDER BY last_used DESC LIMIT 10)')
        
        conn.commit()
        conn.close()
    
    def get_recent_files(self, limit=10):
        """获取最近文件"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT path FROM recent_files ORDER BY last_used DESC LIMIT ?', (limit,))
        results = cursor.fetchall()
        conn.close()
        return [row[0] for row in results]
    
    def clear_recent_files(self):
        """清空最近文件"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM recent_files')
        conn.commit()
        conn.close()


class HashCalculator(QThread):
    """哈希计算线程"""
    progress_updated = pyqtSignal(int)
    result_ready = pyqtSignal(str)
    file_result_ready = pyqtSignal(dict)
    status_updated = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.input_method = "text"
        self.algorithm = "md5"
        self.blake_length = 512
        self.uppercase = False
        self.compare_mode = False
        self.compare_target = ""
        self.auto_check_duplicates = True
        self.text_content = ""
        self.file_path = ""
        self.dir_path = ""
        self.file_paths = []
        self.recursive = True
        self.filter_ext = ""
        self.stop_flag = False
    
    def run(self):
        """线程运行方法"""
        try:
            if self.input_method == "text":
                self.calculate_text_hash()
            elif self.input_method == "file":
                self.calculate_single_file_hash()
            elif self.input_method == "multi_file":
                self.calculate_multiple_files_hash()
            elif self.input_method == "directory":
                self.calculate_directory_hash()
        except Exception as e:
            self.status_updated.emit(f"计算错误: {str(e)}")
        finally:
            self.finished_signal.emit()
    
    def calculate_text_hash(self):
        """计算文本哈希"""
        content = self.text_content.encode('utf-8')
        if not content.strip():
            self.status_updated.emit("请输入要计算哈希的文本内容")
            return

        # 计算哈希值
        if self.algorithm == "blake3":
            hash_value = blake3.blake3(content).hexdigest()
        elif self.algorithm == "siphash":
            hash_value = hex(pyhashxx.hash64(content))[2:]
        elif self.algorithm == "cityhash":
            hash_value = hex(cityhash.CityHash64(content))[2:]
        elif self.algorithm == "farmhash":
            hash_value = hex(farmhash.hash64(content))[2:]
        elif self.algorithm == "murmurhash":
            hash_value = hex(mmh3.hash64(content)[0])[2:]
        elif self.algorithm in ["blake2b", "blake2s"]:
            hash_obj = hashlib.new(self.algorithm, digest_size=self.blake_length//8)
            hash_obj.update(content)
            hash_value = hash_obj.hexdigest()
        else:
            hash_obj = hashlib.new(self.algorithm)
            hash_obj.update(content)
            hash_value = hash_obj.hexdigest()
        
        if self.uppercase:
            hash_value = hash_value.upper()
        
        self.result_ready.emit(hash_value)
        
        # 比对模式处理
        if self.compare_mode:
            self.handle_compare(hash_value)
    
    def calculate_single_file_hash(self):
        """计算单个文件哈希"""
        if not os.path.exists(self.file_path):
            self.status_updated.emit("文件不存在或路径无效")
            return
        
        # 初始化哈希对象
        if self.algorithm == "blake3":
            hash_obj = blake3.blake3()
        elif self.algorithm == "siphash":
            hash_obj = pyhashxx.Hasher()
        elif self.algorithm == "cityhash":
            content = open(self.file_path, 'rb').read()
            hash_value = hex(cityhash.CityHash64(content))[2:]
        elif self.algorithm == "farmhash":
            content = open(self.file_path, 'rb').read()
            hash_value = hex(farmhash.hash64(content))[2:]
        elif self.algorithm == "murmurhash":
            content = open(self.file_path, 'rb').read()
            hash_value = hex(mmh3.hash64(content)[0])[2:]
        elif self.algorithm in ["blake2b", "blake2s"]:
            hash_obj = hashlib.new(self.algorithm, digest_size=self.blake_length//8)
        else:
            hash_obj = hashlib.new(self.algorithm)

        total_size = os.path.getsize(self.file_path)
        processed_size = 0
        
        try:
            if self.algorithm in ["cityhash", "farmhash", "murmurhash"]:
                # 这些算法需要一次性计算
                pass
            else:
                with open(self.file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        if self.stop_flag:
                            self.status_updated.emit("计算已停止")
                            return
                        
                        hash_obj.update(chunk)
                        processed_size += len(chunk)
                        progress = (processed_size / total_size) * 100
                        self.progress_updated.emit(int(progress))
            
            if self.algorithm in ["cityhash", "farmhash", "murmurhash"]:
                # 一次性计算整个文件
                content = open(self.file_path, 'rb').read()
                if self.algorithm == "cityhash":
                    hash_value = hex(cityhash.CityHash64(content))[2:]
                elif self.algorithm == "farmhash":
                    hash_value = hex(farmhash.hash64(content))[2:]
                elif self.algorithm == "murmurhash":
                    hash_value = hex(mmh3.hash64(content)[0])[2:]
            else:
                hash_value = hash_obj.hexdigest()
            
            if self.uppercase:
                hash_value = hash_value.upper()
            
            result_text = f"文件: {os.path.basename(self.file_path)}\n{self.algorithm.upper()}: {hash_value}"
            self.result_ready.emit(result_text)
            
            # 比对模式处理
            if self.compare_mode:
                self.handle_compare(hash_value)
        
        except IOError as e:
            self.status_updated.emit(f"读取文件时出错: {str(e)}")
    
    def calculate_multiple_files_hash(self):
        """计算多个文件哈希"""
        file_count = len(self.file_paths)
        if file_count == 0:
            self.status_updated.emit("请添加要计算哈希的文件")
            return
        
        # 计算每个文件的哈希
        for i, filepath in enumerate(self.file_paths):
            if self.stop_flag:
                self.status_updated.emit("计算已停止")
                return
            
            if not os.path.exists(filepath):
                continue
            
            # 更新进度
            progress = (i / file_count) * 100
            self.progress_updated.emit(int(progress))
            self.status_updated.emit(f"正在计算: {os.path.basename(filepath)} ({i+1}/{file_count})")
            
            # 计算哈希
            try:
                if self.algorithm == "blake3":
                    hash_obj = blake3.blake3()
                elif self.algorithm == "siphash":
                    hash_obj = pyhashxx.Hasher()
                elif self.algorithm == "cityhash":
                    content = open(filepath, 'rb').read()
                    hash_value = hex(cityhash.CityHash64(content))[2:]
                elif self.algorithm == "farmhash":
                    content = open(filepath, 'rb').read()
                    hash_value = hex(farmhash.hash64(content))[2:]
                elif self.algorithm == "murmurhash":
                    content = open(filepath, 'rb').read()
                    hash_value = hex(mmh3.hash64(content)[0])[2:]
                elif self.algorithm in ["blake2b", "blake2s"]:
                    hash_obj = hashlib.new(self.algorithm, digest_size=self.blake_length//8)
                else:
                    hash_obj = hashlib.new(self.algorithm)

                if self.algorithm in ["cityhash", "farmhash", "murmurhash"]:
                    # 这些算法已经在上面的条件中计算完成
                    pass
                else:
                    with open(filepath, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            if self.stop_flag:
                                return
                            hash_obj.update(chunk)
                    
                    hash_value = hash_obj.hexdigest()
                
                if self.uppercase:
                    hash_value = hash_value.upper()
                
                # 准备结果数据
                file_size = os.path.getsize(filepath)
                modified_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
                
                result = {
                    "filename": os.path.basename(filepath),
                    "path": os.path.dirname(filepath),
                    "hash": hash_value,
                    "size": self.format_file_size(file_size),
                    "modified": modified_time,
                    "match": self.compare_mode and hash_value == self.compare_target.strip()
                }
                
                self.file_result_ready.emit(result)
            
            except IOError as e:
                result = {
                    "filename": os.path.basename(filepath),
                    "path": os.path.dirname(filepath),
                    "hash": f"错误: {str(e)}",
                    "size": "-",
                    "modified": "-",
                    "match": False
                }
                self.file_result_ready.emit(result)
        
        self.progress_updated.emit(100)
    
    def calculate_directory_hash(self):
        """计算目录中所有文件的哈希"""
        if not os.path.exists(self.dir_path):
            self.status_updated.emit("目录不存在或路径无效")
            return
        
        # 获取目录中所有文件
        file_paths = []
        for root, _, files in os.walk(self.dir_path):
            for filename in files:
                if self.filter_ext and not filename.lower().endswith(self.filter_ext.lower()):
                    continue
                file_paths.append(os.path.join(root, filename))
            
            if not self.recursive:
                break
        
        if not file_paths:
            self.status_updated.emit("目录中没有符合条件的文件")
            return
        
        # 计算每个文件的哈希
        total_files = len(file_paths)
        for i, filepath in enumerate(file_paths):
            if self.stop_flag:
                self.status_updated.emit("计算已停止")
                return
            
            # 更新进度
            progress = (i / total_files) * 100
            self.progress_updated.emit(int(progress))
            self.status_updated.emit(f"正在计算: {os.path.basename(filepath)} ({i+1}/{total_files})")
            
            # 计算哈希
            try:
                if self.algorithm == "blake3":
                    hash_obj = blake3.blake3()
                elif self.algorithm == "siphash":
                    hash_obj = pyhashxx.Hasher()
                elif self.algorithm == "cityhash":
                    with open(filepath, "rb") as f:
                        content = f.read()
                    hash_value = hex(cityhash.CityHash64(content))[2:]
                elif self.algorithm == "farmhash":
                    with open(filepath, "rb") as f:
                        content = f.read()
                    hash_value = hex(farmhash.hash64(content))[2:]
                elif self.algorithm == "murmurhash":
                    with open(filepath, "rb") as f:
                        content = f.read()
                    hash_value = hex(mmh3.hash64(content)[0])[2:]
                elif self.algorithm in ["blake2b", "blake2s"]:
                    hash_obj = hashlib.new(self.algorithm, digest_size=self.blake_length//8)
                else:
                    hash_obj = hashlib.new(self.algorithm)

                if self.algorithm in ["cityhash", "farmhash", "murmurhash"]:
                    # 这些算法已经在上面的条件中计算完成
                    pass
                else:
                    with open(filepath, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hash_obj.update(chunk)
                    
                    hash_value = hash_obj.hexdigest()
                
                if self.uppercase:
                    hash_value = hash_value.upper()
                
                # 准备结果数据
                file_size = os.path.getsize(filepath)
                modified_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
                
                result = {
                    "filename": os.path.basename(filepath),
                    "path": os.path.dirname(filepath),
                    "hash": hash_value,
                    "size": self.format_file_size(file_size),
                    "modified": modified_time,
                    "match": self.compare_mode and hash_value == self.compare_target.strip()
                }
                
                self.file_result_ready.emit(result)
            
            except IOError as e:
                result = {
                    "filename": os.path.basename(filepath),
                    "path": os.path.dirname(filepath),
                    "hash": f"错误: {str(e)}",
                    "size": "-",
                    "modified": "-",
                    "match": False
                }
                self.file_result_ready.emit(result)
        
        self.progress_updated.emit(100)
    
    def handle_compare(self, hash_value):
        """处理比对逻辑"""
        if self.compare_mode and self.compare_target.strip():
            if hash_value == self.compare_target.strip():
                self.status_updated.emit("比对结果: 匹配")
            else:
                self.status_updated.emit("比对结果: 不匹配")
    
    def format_file_size(self, size):
        """格式化文件大小显示"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"


class HashToolWindow(QMainWindow):
    """主窗口类"""
    def __init__(self):
        super().__init__()
        
        # 初始化数据库
        self.db = DatabaseManager()
        
        # 初始化设置
        self.settings = {
            "theme": self.db.get_setting("theme", "default"),  # 修改默认值为default
            "uppercase": self.db.get_setting("uppercase", "true") == "true",
            "auto_compare": self.db.get_setting("auto_compare", "false") == "true",
            "auto_check_duplicates": self.db.get_setting("auto_check_duplicates", "true") == "true",
            "layout": self.db.get_setting("layout", "horizontal"),
            "window_size": self.db.get_setting("window_size", "1000x700")
        }
        
        # 初始化UI
        self.init_ui()
        
        # 初始化哈希计算线程
        self.hash_calculator = HashCalculator()
        self.hash_calculator.progress_updated.connect(self.update_progress)
        self.hash_calculator.result_ready.connect(self.display_result)
        self.hash_calculator.file_result_ready.connect(self.add_file_result)
        self.hash_calculator.status_updated.connect(self.update_status)
        self.hash_calculator.finished_signal.connect(self.on_calculation_finished)
        
        # 应用初始设置
        self.apply_settings()
    
    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle(f"{ProjectInfo.NAME} {ProjectInfo.VERSION}")
        self.setWindowIcon(QIcon("icon.ico"))
        
        # 设置初始窗口大小
        width, height = map(int, self.settings["window_size"].split('x'))
        self.resize(width, height)
        
        # 创建主部件
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        # 主布局
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(5, 5, 5, 5)
        self.main_layout.setSpacing(5)
        
        # 创建输入区域和结果区域的拆分器
        self.splitter = QSplitter(Qt.Vertical if self.settings["layout"] == "vertical" else Qt.Horizontal)
        self.main_layout.addWidget(self.splitter)
        
        # 创建输入区域
        self.create_input_area()
        
        # 创建结果区域
        self.create_result_area()
        
        # 创建状态栏
        self.create_status_bar()
        
        # 创建菜单
        self.create_menus()
    
        
    def create_input_method_selector(self):
        """创建输入方式选择器"""
        input_frame = QGroupBox("输入方式")
        input_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QHBoxLayout(input_frame)
        
        # 输入方式单选按钮
        self.input_method_group = QButtonGroup()
        methods = [
            ("文本", "text"),
            ("文件", "file"),
            ("多文件", "multi_file"),
            ("目录", "directory")
        ]
        
        for text, value in methods:
            radio = QRadioButton(text)
            radio.setProperty("value", value)
            self.input_method_group.addButton(radio)
            layout.addWidget(radio)
        
        # 默认选择文本输入
        self.input_method_group.buttons()[0].setChecked(True)
        self.input_method_group.buttonClicked.connect(self.toggle_input_method)
        
        # 哈希算法选择
        layout.addWidget(QLabel("算法:"))
        self.hash_algorithm = QComboBox()
        self.hash_algorithm.addItems([
            "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
            "sha3_224", "sha3_256", "sha3_384", "sha3_512",
            "blake2b", "blake2s", "blake3", "siphash", "cityhash",
            "farmhash", "murmurhash"
        ])
        self.hash_algorithm.setCurrentText("md5")
        self.hash_algorithm.currentTextChanged.connect(self.on_hash_algorithm_change)
        layout.addWidget(self.hash_algorithm)
        
        self.input_layout.addWidget(input_frame)
    
    def create_input_content(self):
        """创建输入内容区域"""
        # 使用堆叠窗口来切换不同输入方式
        self.input_stack = QTabWidget()
        self.input_stack.setTabPosition(QTabWidget.North)
        self.input_stack.setDocumentMode(True)
        
        # 文本输入
        self.text_input = QTextEdit()
        self.text_input.setFont(QFont("Consolas", 10))
        self.input_stack.addTab(self.text_input, "文本输入")
        
        # 文件输入
        self.file_input_widget = QWidget()
        file_layout = QVBoxLayout(self.file_input_widget)
        file_layout.setContentsMargins(0, 0, 0, 0)
        
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        file_btn_layout = QHBoxLayout()
        
        browse_file_btn = QPushButton("...")
        browse_file_btn.setMaximumWidth(30)
        browse_file_btn.clicked.connect(self.browse_file)
        
        show_file_btn = QPushButton("↗")
        show_file_btn.setMaximumWidth(30)
        show_file_btn.clicked.connect(self.show_in_explorer)
        
        file_btn_layout.addWidget(self.file_path_edit)
        file_btn_layout.addWidget(browse_file_btn)
        file_btn_layout.addWidget(show_file_btn)
        
        file_layout.addLayout(file_btn_layout)
        self.input_stack.addTab(self.file_input_widget, "文件输入")
        
        # 多文件输入
        self.multi_file_widget = QWidget()
        multi_file_layout = QVBoxLayout(self.multi_file_widget)
        multi_file_layout.setContentsMargins(0, 0, 0, 0)
        
        self.multi_file_list = QListWidget()
        self.multi_file_list.setSelectionMode(QListWidget.ExtendedSelection)
        multi_file_layout.addWidget(self.multi_file_list)
        
        multi_file_btn_layout = QHBoxLayout()
        
        add_files_btn = QPushButton("添加文件")
        add_files_btn.clicked.connect(self.add_files)
        
        add_dir_btn = QPushButton("添加目录")
        add_dir_btn.clicked.connect(self.add_directory)
        
        remove_btn = QPushButton("移除")
        remove_btn.clicked.connect(self.remove_selected_files)
        
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear_file_list)
        
        multi_file_btn_layout.addWidget(add_files_btn)
        multi_file_btn_layout.addWidget(add_dir_btn)
        multi_file_btn_layout.addWidget(remove_btn)
        multi_file_btn_layout.addWidget(clear_btn)
        
        multi_file_layout.addLayout(multi_file_btn_layout)
        self.input_stack.addTab(self.multi_file_widget, "多文件输入")
        
        # 目录输入
        self.dir_input_widget = QWidget()
        dir_layout = QVBoxLayout(self.dir_input_widget)
        dir_layout.setContentsMargins(0, 0, 0, 0)
        
        self.dir_path_edit = QLineEdit()
        self.dir_path_edit.setReadOnly(True)
        dir_btn_layout = QHBoxLayout()
        
        browse_dir_btn = QPushButton("...")
        browse_dir_btn.setMaximumWidth(30)
        browse_dir_btn.clicked.connect(self.browse_directory)
        
        show_dir_btn = QPushButton("↗")
        show_dir_btn.setMaximumWidth(30)
        show_dir_btn.clicked.connect(self.show_dir_in_explorer)
        
        dir_btn_layout.addWidget(self.dir_path_edit)
        dir_btn_layout.addWidget(browse_dir_btn)
        dir_btn_layout.addWidget(show_dir_btn)
        
        dir_layout.addLayout(dir_btn_layout)
        
        # 文件过滤器
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("扩展名:"))
        
        self.filter_ext_edit = QLineEdit()
        self.filter_ext_edit.setMaximumWidth(100)
        filter_layout.addWidget(self.filter_ext_edit)
        
        self.recursive_check = QCheckBox("包含子目录")
        self.recursive_check.setChecked(True)
        filter_layout.addWidget(self.recursive_check)
        
        filter_layout.addStretch()
        dir_layout.addLayout(filter_layout)
        
        self.input_stack.addTab(self.dir_input_widget, "目录输入")
        
        # 默认显示第一个标签页
        self.input_stack.setCurrentIndex(0)
        
        self.input_layout.addWidget(self.input_stack)
    
    def create_calculation_options(self):
        """创建计算选项区域"""
        opt_frame = QGroupBox("计算选项")
        opt_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QHBoxLayout(opt_frame)
        
        # 选项复选框
        self.uppercase_check = QCheckBox("大写结果")
        self.uppercase_check.setChecked(self.settings["uppercase"])
        layout.addWidget(self.uppercase_check)
        
        self.compare_check = QCheckBox("比对模式")
        self.compare_check.setChecked(self.settings["auto_compare"])
        self.compare_check.stateChanged.connect(self.toggle_compare_mode)
        layout.addWidget(self.compare_check)
        
        self.auto_check_duplicates_check = QCheckBox("检测重复")
        self.auto_check_duplicates_check.setChecked(self.settings["auto_check_duplicates"])
        layout.addWidget(self.auto_check_duplicates_check)
        
        # BLAKE2输出长度选项
        self.blake_length_frame = QWidget()
        blake_layout = QHBoxLayout(self.blake_length_frame)
        blake_layout.setContentsMargins(0, 0, 0, 0)
        
        blake_layout.addWidget(QLabel("BLAKE2长度:"))
        self.blake_length_combo = QComboBox()
        self.blake_length_combo.addItems(["64", "128", "256", "384", "512"])
        self.blake_length_combo.setCurrentText("512")
        self.blake_length_combo.setMaximumWidth(60)
        blake_layout.addWidget(self.blake_length_combo)
        
        layout.addWidget(self.blake_length_frame)
        
        # 比对目标
        self.compare_target_frame = QWidget()
        compare_layout = QHBoxLayout(self.compare_target_frame)
        compare_layout.setContentsMargins(0, 0, 0, 0)
        
        compare_layout.addWidget(QLabel("目标:"))
        self.compare_target_edit = QLineEdit()
        compare_layout.addWidget(self.compare_target_edit)
        
        history_btn = QPushButton("历史")
        history_btn.setMaximumWidth(50)
        history_btn.clicked.connect(self.show_history_menu)
        compare_layout.addWidget(history_btn)
        
        layout.addWidget(self.compare_target_frame)
        
        self.input_layout.addWidget(opt_frame)
    
    def create_action_buttons(self):
        """创建操作按钮区域"""
        btn_frame = QWidget()
        btn_layout = QHBoxLayout(btn_frame)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        
        # 计算按钮 (左)
        self.calculate_btn = QPushButton("计算哈希")
        self.calculate_btn.clicked.connect(self.start_calculation)
        btn_layout.addWidget(self.calculate_btn)
        
        # 添加伸缩空间 (左中之间)
        btn_layout.addStretch(1)
        
        # 停止按钮 (中)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_calculation)
        btn_layout.addWidget(self.stop_btn)
        
        # 添加伸缩空间 (中右之间)
        btn_layout.addStretch(1)
        
        # 进度条 (右)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumWidth(200)  # 设置最小宽度
        btn_layout.addWidget(self.progress_bar)
        
        self.input_layout.addWidget(btn_frame)

    
    def create_input_area(self):
        """创建输入区域"""
        # 输入区域容器改为可滚动
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        self.input_container = QWidget()
        self.input_layout = QVBoxLayout(self.input_container)
        self.input_layout.setContentsMargins(5, 5, 5, 5)
        self.input_layout.setSpacing(5)
        
        # 输入方式选择
        self.create_input_method_selector()
        
        # 输入内容区域
        self.create_input_content()
        
        # 计算选项
        self.create_calculation_options()
        
        # 操作按钮区域
        self.create_action_buttons()
        
        scroll.setWidget(self.input_container)
        self.splitter.addWidget(scroll)



    def create_result_area(self):
        """创建结果区域"""
        # 结果区域容器改为可滚动
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        self.result_container = QWidget()
        self.result_layout = QVBoxLayout(self.result_container)
        self.result_layout.setContentsMargins(5, 5, 5, 5)  # 增加一些边距
        self.result_layout.setSpacing(5)
        
        # 结果标签
        self.result_label = QLabel(f"{self.hash_algorithm.currentText().upper()} 结果")
        self.result_label.setFont(QFont("Arial", 10, QFont.Bold))
        self.result_layout.addWidget(self.result_label)
        
        # 比对结果
        self.compare_result_label = QLabel()
        self.compare_result_label.setFont(QFont("Arial", 10))
        self.result_layout.addWidget(self.compare_result_label)
        
        # 使用堆叠窗口来切换不同结果显示方式
        self.result_stack = QTabWidget()
        self.result_stack.setTabPosition(QTabWidget.North)
        self.result_stack.setDocumentMode(True)
        
        # 单结果文本
        self.result_text = QTextEdit()
        self.result_text.setFont(QFont("Consolas", 10))
        self.result_text.setReadOnly(True)
        self.result_stack.addTab(self.result_text, "结果")
        
        # 多文件结果表格
        self.multi_result_widget = QWidget()
        multi_result_layout = QVBoxLayout(self.multi_result_widget)
        multi_result_layout.setContentsMargins(0, 0, 0, 0)
        
        self.multi_result_tree = QTreeWidget()
        self.multi_result_tree.setColumnCount(5)
        self.multi_result_tree.setHeaderLabels(["文件名", "路径", "哈希值", "大小", "修改时间"])
        self.multi_result_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.multi_result_tree.setSortingEnabled(True)
        
        # 设置列宽
        self.multi_result_tree.setColumnWidth(0, 200)
        self.multi_result_tree.setColumnWidth(1, 250)
        self.multi_result_tree.setColumnWidth(2, 250)
        self.multi_result_tree.setColumnWidth(3, 80)
        self.multi_result_tree.setColumnWidth(4, 120)
        
        # 添加右键菜单
        self.multi_result_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.multi_result_tree.customContextMenuRequested.connect(self.show_result_context_menu)
        
        multi_result_layout.addWidget(self.multi_result_tree)
        
        # 结果操作按钮
        result_btn_layout = QHBoxLayout()
        
        copy_btn = QPushButton("复制")
        copy_btn.clicked.connect(self.copy_result)
        
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self.save_result)
        
        export_btn = QPushButton("导出")
        export_btn.clicked.connect(self.export_result)
        
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear_result)
        
        result_btn_layout.addWidget(copy_btn)
        result_btn_layout.addWidget(save_btn)
        result_btn_layout.addWidget(export_btn)
        result_btn_layout.addWidget(clear_btn)
        
        multi_result_layout.addLayout(result_btn_layout)
        self.result_stack.addTab(self.multi_result_widget, "多文件结果")
        
        self.result_layout.addWidget(self.result_stack)
        
        scroll.setWidget(self.result_container)
        self.splitter.addWidget(scroll)
    
    def create_status_bar(self):
        """创建状态栏"""
        self.status_bar = QStatusBar()
        self.status_label = QLabel("就绪")
        self.status_bar.addWidget(self.status_label, 1)
        
        # 添加布局切换按钮
        self.layout_btn = QPushButton("切换布局")
        self.layout_btn.setMaximumWidth(80)
        self.layout_btn.clicked.connect(self.toggle_layout)
        self.status_bar.addPermanentWidget(self.layout_btn)
        
        self.setStatusBar(self.status_bar)
    
    def create_menus(self):
        """创建菜单栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu("文件")
        
        new_action = QAction("新建", self)
        new_action.triggered.connect(self.clear_all)
        file_menu.addAction(new_action)
        
        file_menu.addSeparator()
        
        open_file_action = QAction("打开文件...", self)
        open_file_action.triggered.connect(self.browse_file)
        file_menu.addAction(open_file_action)
        
        open_dir_action = QAction("打开目录...", self)
        open_dir_action.triggered.connect(self.browse_directory)
        file_menu.addAction(open_dir_action)
        
        file_menu.addSeparator()
        
        # 最近文件子菜单
        self.recent_files_menu = file_menu.addMenu("最近文件")
        self.update_recent_files_menu()
        
        file_menu.addSeparator()
        
        save_result_action = QAction("保存结果", self)
        save_result_action.triggered.connect(self.save_result)
        file_menu.addAction(save_result_action)
        
        export_result_action = QAction("导出结果", self)
        export_result_action.triggered.connect(self.export_result)
        file_menu.addAction(export_result_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("退出", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 编辑菜单
        edit_menu = menubar.addMenu("编辑")
        
        paste_action = QAction("粘贴", self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.paste_from_clipboard)
        edit_menu.addAction(paste_action)
        
        copy_result_action = QAction("复制结果", self)
        copy_result_action.triggered.connect(self.copy_result)
        edit_menu.addAction(copy_result_action)
        
        clear_action = QAction("清空", self)
        clear_action.triggered.connect(self.clear_all)
        edit_menu.addAction(clear_action)
        
        # 视图菜单
        view_menu = menubar.addMenu("视图")

        # 添加默认主题选项
        default_theme_action = QAction("默认风格", self)
        default_theme_action.triggered.connect(lambda: self.change_theme("default"))
        view_menu.addAction(default_theme_action)
                
        light_theme_action = QAction("浅色主题", self)
        light_theme_action.triggered.connect(lambda: self.change_theme("light"))
        view_menu.addAction(light_theme_action)
        
        dark_theme_action = QAction("深色主题", self)
        dark_theme_action.triggered.connect(lambda: self.change_theme("dark"))
        view_menu.addAction(dark_theme_action)
        
        view_menu.addSeparator()
        
        horizontal_layout_action = QAction("水平布局", self)
        horizontal_layout_action.triggered.connect(lambda: self.set_layout("horizontal"))
        view_menu.addAction(horizontal_layout_action)
        
        vertical_layout_action = QAction("垂直布局", self)
        vertical_layout_action.triggered.connect(lambda: self.set_layout("vertical"))
        view_menu.addAction(vertical_layout_action)
        
        # 工具菜单
        tools_menu = menubar.addMenu("工具")
        
        uppercase_action = QAction("大写结果", self, checkable=True)
        uppercase_action.setChecked(self.settings["uppercase"])
        uppercase_action.triggered.connect(lambda: self.set_uppercase(uppercase_action.isChecked()))
        tools_menu.addAction(uppercase_action)
        
        compare_action = QAction("比对模式", self, checkable=True)
        compare_action.setChecked(self.settings["auto_compare"])
        compare_action.triggered.connect(lambda: self.set_compare_mode(compare_action.isChecked()))
        tools_menu.addAction(compare_action)
        
        auto_check_action = QAction("自动检测重复", self, checkable=True)
        auto_check_action.setChecked(self.settings["auto_check_duplicates"])
        auto_check_action.triggered.connect(lambda: self.set_auto_check_duplicates(auto_check_action.isChecked()))
        tools_menu.addAction(auto_check_action)
        
        tools_menu.addSeparator()
        
        history_action = QAction("历史记录", self)
        history_action.triggered.connect(self.show_history_dialog)
        tools_menu.addAction(history_action)
        
        # 帮助菜单
        help_menu = menubar.addMenu("帮助")
        
        help_action = QAction("帮助", self)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def apply_settings(self):
        """应用设置"""
        # 应用主题
        self.apply_theme()
        
        # 应用布局
        self.set_layout(self.settings["layout"])
        
        # 应用其他设置
        self.uppercase_check.setChecked(self.settings["uppercase"])
        self.compare_check.setChecked(self.settings["auto_compare"])
        self.auto_check_duplicates_check.setChecked(self.settings["auto_check_duplicates"])
        
        # 更新UI状态
        self.toggle_compare_mode()
        self.on_hash_algorithm_change()
    
    def apply_theme(self):
        """应用主题样式"""
        if self.settings["theme"] == "dark":
            # 深色主题
            self.setStyleSheet("""
                QWidget {
                    background-color: #333333;
                    color: #ffffff;
                }
                QTextEdit, QLineEdit, QListWidget, QTreeWidget {
                    background-color: #444444;
                    color: #ffffff;
                    selection-background-color: #0078d7;
                }
                QGroupBox {
                    border: 1px solid #555555;
                    border-radius: 3px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 3px;
                }
                QPushButton {
                    background-color: #555555;
                    border: 1px solid #666666;
                    padding: 5px;
                    min-width: 70px;
                }
                QPushButton:hover {
                    background-color: #666666;
                }
                QPushButton:pressed {
                    background-color: #777777;
                }
                QComboBox {
                    background-color: #555555;
                    border: 1px solid #666666;
                    padding: 2px;
                }
                QProgressBar {
                    border: 1px solid #666666;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #0078d7;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                }
                QTabBar::tab {
                    background: #555555;
                    border: 1px solid #555555;
                    padding: 5px;
                }
                QTabBar::tab:selected {
                    background: #444444;
                    border-bottom-color: #444444;
                }
                QHeaderView::section {
                    background-color: #555555;
                    padding: 5px;
                    border: 1px solid #666666;
                }
                QMenuBar {
                    background-color: #444444;
                }
                QMenuBar::item {
                    background-color: transparent;
                    padding: 5px;
                }
                QMenuBar::item:selected {
                    background-color: #555555;
                }
                QMenu {
                    background-color: #444444;
                    border: 1px solid #666666;
                }
                QMenu::item:selected {
                    background-color: #555555;
                }
            """)
        elif self.settings["theme"] == "light":
            # 浅色主题
            self.setStyleSheet("""
                QWidget {
                    background-color: #ffffff;
                    color: #000000;
                }
                QTextEdit, QLineEdit, QListWidget, QTreeWidget {
                    background-color: #ffffff;
                    color: #000000;
                    selection-background-color: #0078d7;
                    selection-color: #ffffff;
                }
                QGroupBox {
                    border: 1px solid #cccccc;
                    border-radius: 3px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 3px;
                }
                QPushButton {
                    background-color: #f0f0f0;
                    border: 1px solid #cccccc;
                    padding: 5px;
                    min-width: 70px;
                }
                QPushButton:hover {
                    background-color: #e0e0e0;
                }
                QPushButton:pressed {
                    background-color: #d0d0d0;
                }
                QComboBox {
                    background-color: #ffffff;
                    border: 1px solid #cccccc;
                    padding: 2px;
                }
                QProgressBar {
                    border: 1px solid #cccccc;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #0078d7;
                }
                QTabWidget::pane {
                    border: 1px solid #cccccc;
                }
                QTabBar::tab {
                    background: #f0f0f0;
                    border: 1px solid #cccccc;
                    padding: 5px;
                }
                QTabBar::tab:selected {
                    background: #ffffff;
                    border-bottom-color: #ffffff;
                }
                QHeaderView::section {
                    background-color: #f0f0f0;
                    padding: 5px;
                    border: 1px solid #cccccc;
                }
            """)
        else:
            # 默认风格 - 使用系统原生样式
            self.setStyleSheet("")
    
    def toggle_input_method(self):
        """切换输入方式"""
        method = self.get_selected_input_method()
        
        # 显示对应的输入标签页
        if method == "text":
            self.input_stack.setCurrentIndex(0)
            self.result_stack.setCurrentIndex(0)
        elif method == "file":
            self.input_stack.setCurrentIndex(1)
            self.result_stack.setCurrentIndex(0)
        elif method == "multi_file":
            self.input_stack.setCurrentIndex(2)
            self.result_stack.setCurrentIndex(1)
        elif method == "directory":
            self.input_stack.setCurrentIndex(3)
            self.result_stack.setCurrentIndex(1)
        
        # 更新标题
        algorithm = self.hash_algorithm.currentText().upper()
        self.result_label.setText(f"{algorithm} 结果")
        self.multi_result_tree.headerItem().setText(2, f"{algorithm}值")
    
    def get_selected_input_method(self):
        """获取当前选中的输入方式"""
        for btn in self.input_method_group.buttons():
            if btn.isChecked():
                return btn.property("value")
        return "text"
    
    def on_hash_algorithm_change(self):
        """哈希算法改变事件"""
        algorithm = self.hash_algorithm.currentText()
        # 显示/隐藏BLAKE2长度选项
        if algorithm in ["blake2b", "blake2s"]:
            self.blake_length_frame.show()
        else:
            self.blake_length_frame.hide()
        
        self.toggle_input_method()
    
    def toggle_compare_mode(self):
        """切换比对模式"""
        if self.compare_check.isChecked():
            self.compare_target_frame.show()
            self.settings["auto_compare"] = True
        else:
            self.compare_target_frame.hide()
            self.compare_result_label.clear()
            self.settings["auto_compare"] = False
        
        self.db.set_setting("auto_compare", str(self.settings["auto_compare"]).lower())
    
    def toggle_layout(self):
        """切换布局方向"""
        if self.settings["layout"] == "vertical":
            self.set_layout("horizontal")
        else:
            self.set_layout("vertical")
    
    def set_layout(self, layout):
        """设置布局方向"""
        self.settings["layout"] = layout
        self.db.set_setting("layout", layout)
        
        # 重新设置拆分器方向
        self.splitter.setOrientation(Qt.Vertical if layout == "vertical" else Qt.Horizontal)
        
        # 更新按钮文本
        if layout == "vertical":
            self.layout_btn.setText("水平布局")
        else:
            self.layout_btn.setText("垂直布局")


    
    def set_uppercase(self, enabled):
        """设置大写结果选项"""
        self.settings["uppercase"] = enabled
        self.db.set_setting("uppercase", str(enabled).lower())
    
    def set_compare_mode(self, enabled):
        """设置比对模式选项"""
        self.settings["auto_compare"] = enabled
        self.compare_check.setChecked(enabled)
        self.db.set_setting("auto_compare", str(enabled).lower())
    
    def set_auto_check_duplicates(self, enabled):
        """设置自动检测重复选项"""
        self.settings["auto_check_duplicates"] = enabled
        self.db.set_setting("auto_check_duplicates", str(enabled).lower())
    
    def browse_file(self):
        """浏览文件"""
        filepath, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if filepath:
            self.file_path_edit.setText(filepath)
            self.db.add_recent_file(filepath)
            self.update_recent_files_menu()
    
    def browse_directory(self):
        """浏览目录"""
        dirpath = QFileDialog.getExistingDirectory(self, "选择目录")
        if dirpath:
            self.dir_path_edit.setText(dirpath)
            self.db.add_recent_file(dirpath)
            self.update_recent_files_menu()
    
    def add_files(self):
        """添加多个文件"""
        filepaths, _ = QFileDialog.getOpenFileNames(self, "选择文件")
        if filepaths:
            for filepath in filepaths:
                if self.multi_file_list.findItems(filepath, Qt.MatchExactly):
                    continue
                self.multi_file_list.addItem(filepath)
                self.db.add_recent_file(filepath)
            self.update_recent_files_menu()
    
    def add_directory(self):
        """添加目录中的所有文件"""
        dirpath = QFileDialog.getExistingDirectory(self, "选择目录")
        if dirpath:
            self.add_directory_files(dirpath)
            self.db.add_recent_file(dirpath)
            self.update_recent_files_menu()
    
    def add_directory_files(self, directory):
        """添加目录中的文件到列表"""
        recursive = self.recursive_check.isChecked()
        ext_filter = self.filter_ext_edit.text().strip()
        
        for root, _, files in os.walk(directory):
            for filename in files:
                if ext_filter and not filename.lower().endswith(ext_filter.lower()):
                    continue
                filepath = os.path.join(root, filename)
                if not self.multi_file_list.findItems(filepath, Qt.MatchExactly):
                    self.multi_file_list.addItem(filepath)
            
            if not recursive:
                break
    
    def remove_selected_files(self):
        """移除选中的文件"""
        for item in self.multi_file_list.selectedItems():
            self.multi_file_list.takeItem(self.multi_file_list.row(item))
    
    def clear_file_list(self):
        """清空文件列表"""
        self.multi_file_list.clear()
    
    def show_in_explorer(self):
        """在资源管理器中显示文件"""
        filepath = self.file_path_edit.text()
        if filepath and os.path.exists(filepath):
            os.startfile(os.path.dirname(filepath))
    
    def show_dir_in_explorer(self):
        """在资源管理器中显示目录"""
        dirpath = self.dir_path_edit.text()
        if dirpath and os.path.exists(dirpath):
            os.startfile(dirpath)
    
    def update_recent_files_menu(self):
        """更新最近文件菜单"""
        self.recent_files_menu.clear()
        
        recent_files = self.db.get_recent_files()
        if not recent_files:
            no_files_action = QAction("无最近文件", self)
            no_files_action.setEnabled(False)
            self.recent_files_menu.addAction(no_files_action)
        else:
            for filepath in recent_files:
                action = QAction(os.path.basename(filepath), self)
                action.setData(filepath)
                action.triggered.connect(lambda checked, f=filepath: self.open_recent_file(f))
                self.recent_files_menu.addAction(action)
        
        self.recent_files_menu.addSeparator()
        
        clear_action = QAction("清除历史", self)
        clear_action.triggered.connect(self.clear_recent_files)
        self.recent_files_menu.addAction(clear_action)
    
    def open_recent_file(self, filepath):
        """打开最近文件"""
        if os.path.isfile(filepath):
            self.file_path_edit.setText(filepath)
            for btn in self.input_method_group.buttons():
                if btn.property("value") == "file":
                    btn.setChecked(True)
                    break
            self.toggle_input_method()
        elif os.path.isdir(filepath):
            self.dir_path_edit.setText(filepath)
            for btn in self.input_method_group.buttons():
                if btn.property("value") == "directory":
                    btn.setChecked(True)
                    break
            self.toggle_input_method()
    
    def clear_recent_files(self):
        """清除最近文件记录"""
        self.db.clear_recent_files()
        self.update_recent_files_menu()
    
    def start_calculation(self):
        """开始计算哈希"""
        # 准备计算参数
        self.hash_calculator.input_method = self.get_selected_input_method()
        self.hash_calculator.algorithm = self.hash_algorithm.currentText()
        self.hash_calculator.blake_length = int(self.blake_length_combo.currentText())
        self.hash_calculator.uppercase = self.uppercase_check.isChecked()
        self.hash_calculator.compare_mode = self.compare_check.isChecked()
        self.hash_calculator.compare_target = self.compare_target_edit.text()
        self.hash_calculator.auto_check_duplicates = self.auto_check_duplicates_check.isChecked()
        
        # 根据输入方式设置相应参数
        if self.hash_calculator.input_method == "text":
            self.hash_calculator.text_content = self.text_input.toPlainText()
        elif self.hash_calculator.input_method == "file":
            self.hash_calculator.file_path = self.file_path_edit.text()
        elif self.hash_calculator.input_method == "multi_file":
            self.hash_calculator.file_paths = [self.multi_file_list.item(i).text() 
                                             for i in range(self.multi_file_list.count())]
        elif self.hash_calculator.input_method == "directory":
            self.hash_calculator.dir_path = self.dir_path_edit.text()
            self.hash_calculator.recursive = self.recursive_check.isChecked()
            self.hash_calculator.filter_ext = self.filter_ext_edit.text()
        
        # 清空之前的结果
        if self.hash_calculator.input_method in ["multi_file", "directory"]:
            self.multi_result_tree.clear()
        
        # 禁用计算按钮，启用停止按钮
        self.calculate_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.hash_calculator.stop_flag = False
        
        # 重置进度条
        self.progress_bar.setValue(0)
        self.status_label.setText("正在计算...")
        
        # 开始计算
        self.hash_calculator.start()
    
    def stop_calculation(self):
        """停止计算"""
        self.hash_calculator.stop_flag = True
        self.status_label.setText("正在停止...")
    
    def on_calculation_finished(self):
        """计算完成"""
        self.calculate_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("计算完成")
    
    def update_progress(self, value, speed=None):
        """更新进度条"""
        self.progress_bar.setValue(value)
        if speed:
            self.status_label.setText(f"计算中... {speed} MB/s")
    
    def display_result(self, result):
        """显示结果"""
        self.result_text.setPlainText(result)
        
        # 添加到历史记录
        input_method = self.get_selected_input_method()
        if input_method == "text":
            self.db.add_history({
                "type": "text",
                "content": self.text_input.toPlainText(),
                "hash": result,
                "algorithm": self.hash_algorithm.currentText()
            })
        elif input_method == "file":
            self.db.add_history({
                "type": "file",
                "path": self.file_path_edit.text(),
                "hash": result.split("\n")[1].split(": ")[1],
                "algorithm": self.hash_algorithm.currentText(),
                "size": os.path.getsize(self.file_path_edit.text())
            })
    
    def add_file_result(self, result):
        """添加文件结果到表格"""
        item = QTreeWidgetItem(self.multi_result_tree)
        item.setText(0, result["filename"])
        item.setText(1, result["path"])
        item.setText(2, result["hash"])
        item.setText(3, result["size"])
        item.setText(4, result["modified"])
        
        if result.get("match", False):
            item.setBackground(2, QColor("#90EE90"))
        
        # 自动检测重复文件
        if self.auto_check_duplicates_check.isChecked():
            self.find_duplicate_files()
    
    def find_duplicate_files(self):
        """标记重复文件"""
        hash_dict = {}
        
        # 收集所有哈希值
        for i in range(self.multi_result_tree.topLevelItemCount()):
            item = self.multi_result_tree.topLevelItem(i)
            hash_value = item.text(2)
            if hash_value not in hash_dict:
                hash_dict[hash_value] = []
            hash_dict[hash_value].append(item)
        
        # 为重复文件分配颜色
        color_hue = 0
        color_step = 30
        
        for hash_value, items in hash_dict.items():
            if len(items) > 1:
                # 生成HSL颜色并转换为RGB
                color = QColor.fromHsl(color_hue, 180, 200)
                color_hue = (color_hue + color_step) % 360
                
                for item in items:
                    for col in range(self.multi_result_tree.columnCount()):
                        item.setBackground(col, color)
    
    def update_status(self, message):
        """更新状态栏"""
        self.status_label.setText(message)
    
    def copy_result(self):
        """复制结果"""
        if self.get_selected_input_method() in ["multi_file", "directory"]:
            # 复制多文件结果
            result = ""
            for i in range(self.multi_result_tree.topLevelItemCount()):
                item = self.multi_result_tree.topLevelItem(i)
                result += f"{item.text(0)}\t{item.text(1)}\t{item.text(2)}\t{item.text(3)}\t{item.text(4)}\n"
        else:
            # 复制单结果
            result = self.result_text.toPlainText()
        
        if result.strip():
            clipboard = QApplication.clipboard()
            clipboard.setText(result)
            self.status_label.setText("结果已复制到剪贴板")
        else:
            QMessageBox.warning(self, "警告", "没有可复制的哈希结果")
    
    def save_result(self):
        """保存结果为文本文件"""
        if self.get_selected_input_method() in ["multi_file", "directory"]:
            # 保存多文件结果
            default_filename = f"{self.hash_algorithm.currentText()}_results.txt"
            result = ""
            for i in range(self.multi_result_tree.topLevelItemCount()):
                item = self.multi_result_tree.topLevelItem(i)
                result += f"{item.text(0)}\t{item.text(1)}\t{item.text(2)}\t{item.text(3)}\t{item.text(4)}\n"
        else:
            # 保存单结果
            default_filename = f"{self.hash_algorithm.currentText()}_result.txt"
            result = self.result_text.toPlainText()
        
        if not result.strip():
            QMessageBox.warning(self, "警告", "没有可保存的哈希结果")
            return
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "保存结果", default_filename, "文本文件 (*.txt);;所有文件 (*)")
        
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(result)
                self.status_label.setText(f"结果已保存到: {filepath}")
                self.db.add_recent_file(filepath)
                self.update_recent_files_menu()
            except IOError as e:
                QMessageBox.critical(self, "错误", f"保存文件时出错: {str(e)}")
    
    def export_result(self):
        """导出结果为CSV或JSON"""
        if self.get_selected_input_method() in ["multi_file", "directory"]:
            # 导出多文件结果
            default_filename = f"{self.hash_algorithm.currentText()}_results"
            data = []
            for i in range(self.multi_result_tree.topLevelItemCount()):
                item = self.multi_result_tree.topLevelItem(i)
                data.append({
                    "filename": item.text(0),
                    "path": item.text(1),
                    "hash": item.text(2),
                    "size": item.text(3),
                    "modified": item.text(4)
                })
        else:
            # 导出单结果
            default_filename = f"{self.hash_algorithm.currentText()}_result"
            content = self.result_text.toPlainText().strip()
            if not content:
                QMessageBox.warning(self, "警告", "没有可导出的哈希结果")
                return
            
            if "\n" in content:
                # 文件结果
                parts = content.split("\n")
                data = {
                    "filename": parts[0].replace("文件: ", ""),
                    "hash": parts[1].split(": ")[1],
                    "algorithm": self.hash_algorithm.currentText()
                }
            else:
                # 文本结果
                data = {
                    "hash": content,
                    "algorithm": self.hash_algorithm.currentText()
                }
        
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self, "导出结果", default_filename, 
            "JSON文件 (*.json);;CSV文件 (*.csv);;所有文件 (*)")
        
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
            
            self.status_label.setText(f"结果已导出到: {filepath}")
            self.db.add_recent_file(filepath)
            self.update_recent_files_menu()
        except IOError as e:
            QMessageBox.critical(self, "错误", f"导出文件时出错: {str(e)}")
    
    def export_selected_results(self):
        """导出选中的结果"""
        selected_items = self.multi_result_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择要导出的项目")
            return
        
        default_filename = f"{self.hash_algorithm.currentText()}_selected_results"
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self, "导出选中结果", default_filename, 
            "JSON文件 (*.json);;CSV文件 (*.csv);;所有文件 (*)")
        
        if not filepath:
            return
        
        data = []
        for item in selected_items:
            data.append({
                "filename": item.text(0),
                "path": item.text(1),
                "hash": item.text(2),
                "size": item.text(3),
                "modified": item.text(4)
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
            
            self.status_label.setText(f"选中结果已导出到: {filepath}")
            self.db.add_recent_file(filepath)
            self.update_recent_files_menu()
        except IOError as e:
            QMessageBox.critical(self, "错误", f"导出文件时出错: {str(e)}")
    
    def clear_result(self):
        """清空结果"""
        self.result_text.clear()
        self.compare_result_label.clear()
    
    def clear_all(self):
        """清空所有输入和结果"""
        self.text_input.clear()
        self.file_path_edit.clear()
        self.dir_path_edit.clear()
        self.multi_file_list.clear()
        self.compare_target_edit.clear()
        self.compare_result_label.clear()
        self.result_text.clear()
        self.multi_result_tree.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("就绪")
    
    def show_result_context_menu(self, pos):
        """显示结果表格的右键菜单"""
        menu = QMenu()
        
        copy_action = QAction("复制", self)
        copy_action.triggered.connect(self.copy_selected_results)
        menu.addAction(copy_action)
        
        export_action = QAction("导出选中", self)
        export_action.triggered.connect(self.export_selected_results)
        menu.addAction(export_action)
        
        show_in_explorer_action = QAction("在资源管理器中显示", self)
        show_in_explorer_action.triggered.connect(self.show_selected_in_explorer)
        menu.addAction(show_in_explorer_action)
        
        menu.exec_(self.multi_result_tree.viewport().mapToGlobal(pos))
    
    def copy_selected_results(self):
        """复制选中的结果"""
        selected_items = self.multi_result_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择要复制的项目")
            return
        
        result = ""
        for item in selected_items:
            result += f"{item.text(0)}\t{item.text(1)}\t{item.text(2)}\t{item.text(3)}\t{item.text(4)}\n"
        
        clipboard = QApplication.clipboard()
        clipboard.setText(result)
        self.status_label.setText("选中结果已复制到剪贴板")
    
    def show_selected_in_explorer(self):
        """在资源管理器中显示选中的文件"""
        selected_items = self.multi_result_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择文件")
            return
        
        for item in selected_items:
            filepath = os.path.join(item.text(1), item.text(0))
            if os.path.exists(filepath):
                os.startfile(os.path.dirname(filepath))
    
    def show_history_menu(self):
        """显示历史记录菜单"""
        history = self.db.get_history(10)
        if not history:
            QMessageBox.information(self, "信息", "没有历史记录")
            return
        
        menu = QMenu(self)
        
        for item in history:
            if item["type"] == "text":
                label = f"文本: {item['content'][:30]}... - {item['hash']}"
            elif item["type"] == "file":
                label = f"文件: {os.path.basename(item['path'])} - {item['hash']}"
            else:
                label = f"{item['type']} - {item['time']}"
            
            action = QAction(label, self)
            action.setData(item['hash'])
            action.triggered.connect(lambda checked, h=item['hash']: self.compare_target_edit.setText(h))
            menu.addAction(action)
        
        menu.exec_(self.mapToGlobal(self.compare_target_edit.pos() + QPoint(0, self.compare_target_edit.height())))
    
    def show_history_dialog(self):
        """显示历史记录对话框"""
        history = self.db.get_history()
        if not history:
            QMessageBox.information(self, "信息", "没有历史记录")
            return
        
        history_win = QDialog(self)
        history_win.setWindowTitle("历史记录")
        history_win.resize(800, 600)
        
        layout = QVBoxLayout(history_win)
        
        # 创建表格
        tree = QTreeWidget()
        tree.setColumnCount(4)
        tree.setHeaderLabels(["类型", "内容", "哈希值", "时间"])
        tree.setSortingEnabled(True)
        tree.sortByColumn(3, Qt.DescendingOrder)
        
        # 添加数据
        for item in history:
            tree_item = QTreeWidgetItem(tree)
            tree_item.setText(0, item["type"])
            
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
            
            tree_item.setText(1, content)
            tree_item.setText(2, item.get("hash", ""))
            tree_item.setText(3, item["time"])
            tree_item.setData(0, Qt.UserRole, item["id"])  # 保存ID以便删除
        
        # 右键菜单
        tree.setContextMenuPolicy(Qt.CustomContextMenu)
        tree.customContextMenuRequested.connect(lambda pos: self.show_history_item_menu(tree, pos))
        
        # 布局
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(tree)
        
        layout.addWidget(scroll)
        
        # 关闭按钮
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(history_win.close)
        layout.addWidget(close_btn)
        
        history_win.exec_()
    
    def show_history_item_menu(self, tree, pos):
        """显示历史记录项的右键菜单"""
        item = tree.itemAt(pos)
        if not item:
            return
        
        menu = QMenu()
        
        copy_action = QAction("复制哈希值", self)
        copy_action.triggered.connect(lambda: self.copy_history_hash(item))
        menu.addAction(copy_action)
        
        delete_action = QAction("删除记录", self)
        delete_action.triggered.connect(lambda: self.delete_history_item(item))
        menu.addAction(delete_action)
        
        menu.exec_(tree.viewport().mapToGlobal(pos))
    
    def copy_history_hash(self, item):
        """复制历史记录中的哈希值"""
        hash_value = item.text(2)
        if hash_value:
            clipboard = QApplication.clipboard()
            clipboard.setText(hash_value)
            self.status_label.setText("哈希值已复制到剪贴板")
    
    def delete_history_item(self, item):
        """删除历史记录项"""
        history_id = item.data(0, Qt.UserRole)
        self.db.delete_history(history_id)
        item.parent().removeChild(item)
    
    def paste_from_clipboard(self):
        """从剪贴板粘贴内容"""
        try:
            clipboard = QApplication.clipboard()
            clipboard_content = clipboard.text().strip()
            
            if not clipboard_content:
                QMessageBox.warning(self, "警告", "剪贴板中没有内容")
                return
            
            # 处理URI编码路径 (如 file:///C:/path/to/file)
            if clipboard_content.startswith('file://'):
                clipboard_content = clipboard_content[7:]  # 移除file://前缀
                # 处理URL编码的特殊字符
                try:
                    from urllib.parse import unquote
                    clipboard_content = unquote(clipboard_content)
                except ImportError:
                    pass
            
            # 规范化路径（处理开头的斜杠、引号、空格等）
            clipboard_content = clipboard_content.strip('"\' \t\r\n')
            
            # 处理Windows路径开头的斜杠问题（如 /G:/path/to/file）
            if clipboard_content.startswith('/') and len(clipboard_content) > 2 and clipboard_content[2] == ':':
                clipboard_content = clipboard_content[1:]
            
            # 处理Windows网络路径 (如 \\server\share)
            is_network_path = clipboard_content.startswith('\\\\')
            
            # 根据当前输入模式处理粘贴内容
            current_method = self.get_selected_input_method()
            
            if current_method == "text":
                self.text_input.setPlainText(clipboard_content)
                self.status_label.setText("已从剪贴板粘贴文本内容")
                
            elif current_method == "file":
                # 特殊处理拖放的文件路径 (可能包含换行)
                if '\n' in clipboard_content:
                    first_line = clipboard_content.split('\n')[0].strip()
                    if os.path.exists(first_line):
                        clipboard_content = first_line
                
                # 规范化路径
                normalized_path = os.path.normpath(clipboard_content) if not is_network_path else clipboard_content
                
                if os.path.exists(normalized_path):
                    self.file_path_edit.setText(normalized_path)
                    self.status_label.setText(f"已从剪贴板设置文件路径: {normalized_path}")
                    self.db.add_recent_file(normalized_path)
                    self.update_recent_files_menu()
                else:
                    print(f"[DEBUG] 剪贴板内容不是有效的文件路径:\n{clipboard_content}")   
                    QMessageBox.warning(self, "警告", 
                        f"剪贴板内容不是有效的文件路径:\n{clipboard_content}")
                    
            elif current_method == "multi_file":
                # 处理多文件路径（用换行或空格分隔）
                paths = []
                if '\n' in clipboard_content:
                    paths = clipboard_content.split('\n')
                elif ' ' in clipboard_content:
                    paths = clipboard_content.split(' ')
                else:
                    paths = [clipboard_content]
                    
                valid_paths = []
                for p in paths:
                    p = p.strip('"\' \t\r\n')
                    # 跳过空行
                    if not p:
                        continue
                    
                    # 处理URI编码路径
                    if p.startswith('file://'):
                        p = p[7:]
                        try:
                            from urllib.parse import unquote
                            p = unquote(p)
                        except ImportError:
                            pass
                    
                    # 处理Windows路径开头的斜杠问题
                    if p.startswith('/') and len(p) > 2 and p[2] == ':':
                        p = p[1:]
                    
                    # 尝试规范化路径（网络路径除外）
                    try:
                        norm_p = os.path.normpath(p) if not p.startswith('\\\\') else p
                        if os.path.exists(norm_p):
                            valid_paths.append(norm_p)
                    except (TypeError, ValueError) as e:
                        print(f"[DEBUG] 路径处理错误: {p} - {str(e)}")
                        continue
                
                if valid_paths:
                    added_count = 0
                    for path in valid_paths:
                        if not self.multi_file_list.findItems(path, Qt.MatchExactly):
                            self.multi_file_list.addItem(path)
                            added_count += 1
                            self.db.add_recent_file(path)
                    self.status_label.setText(f"已从剪贴板添加 {added_count} 个文件")
                    self.update_recent_files_menu()
                else:
                    print(f"[DEBUG] 剪贴板内容不是有效的文件路径:\n{clipboard_content}")
                    QMessageBox.warning(self, "警告", 
                        "剪贴板中没有有效的文件路径:\n" + "\n".join(paths[:5]) + 
                        ("\n..." if len(paths) > 5 else ""))
                        
            elif current_method == "directory":
                # 特殊处理拖放的目录路径 (可能包含换行)
                if '\n' in clipboard_content:
                    first_line = clipboard_content.split('\n')[0].strip()
                    if os.path.isdir(first_line):
                        clipboard_content = first_line
                
                # 规范化路径
                normalized_path = os.path.normpath(clipboard_content) if not is_network_path else clipboard_content
                
                if os.path.isdir(normalized_path):
                    self.dir_path_edit.setText(normalized_path)
                    self.status_label.setText(f"已从剪贴板设置目录路径: {normalized_path}")
                    self.db.add_recent_file(normalized_path)
                    self.update_recent_files_menu()
                else:
                    QMessageBox.warning(self, "警告", 
                        f"剪贴板内容不是有效的目录路径:\n{clipboard_content}")
                        
        except Exception as e:
            QMessageBox.critical(self, "错误", f"粘贴时发生错误: {str(e)}")
            import traceback
            print(f"[ERROR] Paste error: {traceback.format_exc()}")



    
    def change_theme(self, theme):
        """切换主题"""
        self.settings["theme"] = theme
        self.db.set_setting("theme", theme)
        self.apply_theme()
    
    def show_help(self):
        """显示帮助信息"""
        QMessageBox.information(self, "帮助", ProjectInfo.HELP_TEXT)
    
    def show_about(self):
        """显示关于对话框"""
        about_text = f"""
{ProjectInfo.NAME} {ProjectInfo.VERSION}

作者: {ProjectInfo.AUTHOR}
许可证: {ProjectInfo.LICENSE}
版权所有: {ProjectInfo.COPYRIGHT}
项目主页: {ProjectInfo.URL}

{ProjectInfo.DESCRIPTION}
"""
        QMessageBox.about(self, "关于", about_text)
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        # 保存窗口大小
        size = self.size()
        self.db.set_setting("window_size", f"{size.width()}x{size.height()}")
        
        # 停止计算线程
        if self.hash_calculator.isRunning():
            self.hash_calculator.stop_flag = True
            self.hash_calculator.wait()
        
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # app.setStyle('Fusion')  # 使用Fusion风格以获得更好的跨平台外观
    
    # 设置应用程序信息
    app.setApplicationName(ProjectInfo.NAME)
    app.setApplicationVersion(ProjectInfo.VERSION)
    app.setOrganizationName(ProjectInfo.AUTHOR)
    
    window = HashToolWindow()
    window.show()
    sys.exit(app.exec_())