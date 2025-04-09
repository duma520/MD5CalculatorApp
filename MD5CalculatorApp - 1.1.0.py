import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import hashlib
import os
import threading
from tkinterdnd2 import TkinterDnD, DND_FILES

class EnhancedMD5CalculatorApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("超级MD5计算工具")
        self.geometry("800x600")
        self.minsize(700, 500)
        
        # 样式配置
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TRadiobutton', padding=5)
        
        self.create_widgets()
        self.setup_layout()
        self.setup_drag_and_drop()
        
        # 用于存储文件MD5结果的字典
        self.file_md5_dict = {}
        
        # 用于线程安全操作
        self.lock = threading.Lock()
    
    def create_widgets(self):
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
        self.remove_files_button = ttk.Button(
            self.multi_file_buttons_frame, text="移除选中", command=self.remove_selected_files)
        self.clear_files_button = ttk.Button(
            self.multi_file_buttons_frame, text="清空列表", command=self.clear_file_list)
        
        # 计算选项
        self.options_frame = ttk.LabelFrame(self, text="计算选项")
        self.uppercase_var = tk.BooleanVar(value=True)
        self.uppercase_check = ttk.Checkbutton(
            self.options_frame, text="大写结果", variable=self.uppercase_var)
        
        self.compare_var = tk.BooleanVar(value=False)
        self.compare_check = ttk.Checkbutton(
            self.options_frame, text="比对模式", variable=self.compare_var,
            command=self.toggle_compare_mode)
        
        self.compare_target_frame = ttk.Frame(self.options_frame)
        self.compare_target_label = ttk.Label(self.compare_target_frame, text="比对目标:")
        self.compare_target = tk.StringVar()
        self.compare_entry = ttk.Entry(
            self.compare_target_frame, textvariable=self.compare_target)
        self.compare_target_frame.pack_forget()
        
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
            foreground="red", font=('Arial', 10, 'bold'))
        
        # 多文件结果表格
        self.multi_result_frame = ttk.LabelFrame(self, text="多文件MD5结果")
        self.multi_result_tree = ttk.Treeview(
            self.multi_result_frame, columns=("file", "md5", "size"), show="headings")
        self.multi_result_tree.heading("file", text="文件名")
        self.multi_result_tree.heading("md5", text="MD5值")
        self.multi_result_tree.heading("size", text="文件大小")
        self.multi_result_tree.column("file", width=300, anchor=tk.W)
        self.multi_result_tree.column("md5", width=250, anchor=tk.W)
        self.multi_result_tree.column("size", width=100, anchor=tk.E)
        
        self.multi_result_scroll = ttk.Scrollbar(
            self.multi_result_frame, orient=tk.VERTICAL, command=self.multi_result_tree.yview)
        self.multi_result_tree.configure(yscrollcommand=self.multi_result_scroll.set)
        
        # 操作按钮
        self.button_frame = ttk.Frame(self)
        self.copy_button = ttk.Button(
            self.button_frame, text="复制结果", command=self.copy_result)
        self.save_button = ttk.Button(
            self.button_frame, text="保存结果", command=self.save_result)
        self.clear_button = ttk.Button(
            self.button_frame, text="清空", command=self.clear_all)
        self.exit_button = ttk.Button(
            self.button_frame, text="退出", command=self.quit)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = ttk.Label(
            self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        
        # 线程控制
        self.calculation_thread = None
        self.stop_flag = False
    
    def setup_layout(self):
        # 输入方式选择
        self.input_frame.pack(pady=5, padx=10, fill=tk.X)
        self.text_radio.pack(side=tk.LEFT, padx=5)
        self.file_radio.pack(side=tk.LEFT, padx=5)
        self.multi_file_radio.pack(side=tk.LEFT, padx=5)
        
        # 文本输入区域
        self.text_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        # 文件输入区域 (初始隐藏)
        self.file_frame.pack(pady=5, padx=10, fill=tk.X)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_button.pack(side=tk.RIGHT, padx=5)
        self.file_frame.pack_forget()
        
        # 多文件输入区域 (初始隐藏)
        self.multi_file_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.multi_file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.multi_file_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.multi_file_buttons_frame.pack(fill=tk.X, pady=5)
        self.add_files_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.remove_files_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.clear_files_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.multi_file_frame.pack_forget()
        
        # 计算选项
        self.options_frame.pack(pady=5, padx=10, fill=tk.X)
        self.uppercase_check.pack(side=tk.LEFT, padx=5)
        self.compare_check.pack(side=tk.LEFT, padx=5)
        self.compare_target_frame.pack(fill=tk.X, padx=5, pady=5)
        self.compare_target_label.pack(side=tk.LEFT)
        self.compare_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
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
        self.copy_button.pack(side=tk.LEFT, padx=10, expand=True)
        self.save_button.pack(side=tk.LEFT, padx=10, expand=True)
        self.clear_button.pack(side=tk.LEFT, padx=10, expand=True)
        self.exit_button.pack(side=tk.LEFT, padx=10, expand=True)
        
        # 状态栏
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_drag_and_drop(self):
        # 设置拖拽功能
        self.text_input.drop_target_register(DND_FILES)
        self.text_input.dnd_bind('<<Drop>>', self.handle_text_drop)
        
        self.file_entry.drop_target_register(DND_FILES)
        self.file_entry.dnd_bind('<<Drop>>', self.handle_file_drop)
        
        self.multi_file_listbox.drop_target_register(DND_FILES)
        self.multi_file_listbox.dnd_bind('<<Drop>>', self.handle_multi_file_drop)
    
    def handle_text_drop(self, event):
        # 文本区域拖拽处理 - 直接读取文件内容
        file_path = event.data.strip('{}')
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.text_input.delete('1.0', tk.END)
                self.text_input.insert('1.0', content)
                self.input_method.set("text")
                self.toggle_input_method()
            except Exception as e:
                messagebox.showerror("错误", f"无法读取文件: {str(e)}")
    
    def handle_file_drop(self, event):
        # 文件输入拖拽处理
        file_path = event.data.strip('{}')
        if os.path.isfile(file_path):
            self.file_path.set(file_path)
            self.input_method.set("file")
            self.toggle_input_method()
    
    def handle_multi_file_drop(self, event):
        # 多文件拖拽处理
        files = [f.strip('{}') for f in event.data.split()] if isinstance(event.data, str) else [event.data.strip('{}')]
        valid_files = [f for f in files if os.path.isfile(f)]
        
        if valid_files:
            for file_path in valid_files:
                if file_path not in self.multi_file_listbox.get(0, tk.END):
                    self.multi_file_listbox.insert(tk.END, file_path)
            self.input_method.set("multi_file")
            self.toggle_input_method()
    
    def toggle_input_method(self):
        # 隐藏所有输入区域
        self.text_frame.pack_forget()
        self.file_frame.pack_forget()
        self.multi_file_frame.pack_forget()
        self.multi_result_frame.pack_forget()
        
        # 显示选中的输入区域
        method = self.input_method.get()
        if method == "text":
            self.text_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        elif method == "file":
            self.file_frame.pack(pady=5, padx=10, fill=tk.X)
        elif method == "multi_file":
            self.multi_file_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
            self.multi_result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
    
    def toggle_compare_mode(self):
        if self.compare_var.get():
            self.compare_target_frame.pack(fill=tk.X, padx=5, pady=5)
        else:
            self.compare_target_frame.pack_forget()
            self.compare_result_var.set("")
    
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
    
    def add_files(self):
        files = filedialog.askopenfilenames()
        if files:
            for file_path in files:
                if file_path not in self.multi_file_listbox.get(0, tk.END):
                    self.multi_file_listbox.insert(tk.END, file_path)
    
    def remove_selected_files(self):
        selected = self.multi_file_listbox.curselection()
        for index in reversed(selected):
            self.multi_file_listbox.delete(index)
    
    def clear_file_list(self):
        self.multi_file_listbox.delete(0, tk.END)
    
    def start_calculation_thread(self):
        # 禁用计算按钮，启用停止按钮
        self.calculate_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_flag = False
        
        # 重置进度条
        self.progress_var.set(0)
        self.status_var.set("正在计算...")
        
        # 在新线程中执行计算
        self.calculation_thread = threading.Thread(target=self.calculate_md5)
        self.calculation_thread.daemon = True
        self.calculation_thread.start()
        
        # 检查线程状态的定时器
        self.after(100, self.check_thread)
    
    def check_thread(self):
        if self.calculation_thread.is_alive():
            self.after(100, self.check_thread)
        else:
            self.calculate_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set("计算完成")
    
    def stop_calculation(self):
        self.stop_flag = True
        self.status_var.set("正在停止...")
    
    def calculate_md5(self):
        try:
            if self.input_method.get() == "text":
                self.calculate_text_md5()
            elif self.input_method.get() == "file":
                self.calculate_single_file_md5()
            elif self.input_method.get() == "multi_file":
                self.calculate_multiple_files_md5()
        except Exception as e:
            self.show_error(f"计算过程中发生错误: {str(e)}")
    
    def calculate_text_md5(self):
        content = self.text_input.get("1.0", tk.END).encode('utf-8')
        if not content.strip():
            self.show_warning("请输入要计算MD5的文本内容")
            return
        
        md5_hash = hashlib.md5(content).hexdigest()
        if self.uppercase_var.get():
            md5_hash = md5_hash.upper()
        
        self.display_result(md5_hash)
        
        # 比对模式处理
        if self.compare_var.get():
            self.handle_compare(md5_hash)
    
    def calculate_single_file_md5(self):
        filepath = self.file_path.get()
        if not filepath:
            self.show_warning("请选择要计算MD5的文件")
            return
        
        if not os.path.exists(filepath):
            self.show_error("文件不存在或路径无效")
            return
        
        # 计算大文件的MD5
        hash_md5 = hashlib.md5()
        total_size = os.path.getsize(filepath)
        processed_size = 0
        
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    if self.stop_flag:
                        self.status_var.set("计算已停止")
                        return
                    
                    hash_md5.update(chunk)
                    processed_size += len(chunk)
                    progress = (processed_size / total_size) * 100
                    self.progress_var.set(progress)
            
            md5_hash = hash_md5.hexdigest()
            if self.uppercase_var.get():
                md5_hash = md5_hash.upper()
            
            result_text = f"文件: {os.path.basename(filepath)}\nMD5: {md5_hash}"
            self.display_result(result_text)
            
            # 比对模式处理
            if self.compare_var.get():
                self.handle_compare(md5_hash)
        
        except IOError as e:
            self.show_error(f"读取文件时出错: {str(e)}")
    
    def calculate_multiple_files_md5(self):
        file_count = self.multi_file_listbox.size()
        if file_count == 0:
            self.show_warning("请添加要计算MD5的文件")
            return
        
        # 清空结果表格
        for item in self.multi_result_tree.get_children():
            self.multi_result_tree.delete(item)
        
        # 清空MD5字典
        self.file_md5_dict.clear()
        
        # 计算每个文件的MD5
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
            
            # 计算MD5
            hash_md5 = hashlib.md5()
            try:
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        if self.stop_flag:
                            return
                        hash_md5.update(chunk)
                
                md5_hash = hash_md5.hexdigest()
                if self.uppercase_var.get():
                    md5_hash = md5_hash.upper()
                
                # 存储结果
                file_size = os.path.getsize(filepath)
                self.file_md5_dict[filepath] = md5_hash
                
                # 添加到结果表格
                self.multi_result_tree.insert("", tk.END, values=(
                    os.path.basename(filepath),
                    md5_hash,
                    self.format_file_size(file_size)
                ))
                
                # 比对模式处理
                if self.compare_var.get() and self.compare_target.get():
                    if md5_hash == self.compare_target.get().strip():
                        self.multi_result_tree.item(self.multi_result_tree.get_children()[-1], tags=('match',))
                        self.multi_result_tree.tag_configure('match', background='lightgreen')
            
            except IOError as e:
                self.multi_result_tree.insert("", tk.END, values=(
                    os.path.basename(filepath),
                    f"错误: {str(e)}",
                    "-"
                ))
        
        # 比对模式处理 - 查找重复文件
        if not self.compare_var.get():
            self.find_duplicate_files()
        
        self.progress_var.set(100)
    
    def find_duplicate_files(self):
        # 找出MD5相同的文件
        md5_to_files = {}
        for filepath, md5 in self.file_md5_dict.items():
            if md5 not in md5_to_files:
                md5_to_files[md5] = []
            md5_to_files[md5].append(filepath)
        
        # 标记重复文件
        duplicate_count = 0
        for md5, files in md5_to_files.items():
            if len(files) > 1:
                duplicate_count += len(files)
                for filepath in files:
                    for item in self.multi_result_tree.get_children():
                        if self.multi_result_tree.item(item, 'values')[0] == os.path.basename(filepath):
                            self.multi_result_tree.item(item, tags=('duplicate',))
                            self.multi_result_tree.tag_configure('duplicate', background='lightyellow')
                            break
        
        if duplicate_count > 0:
            self.status_var.set(f"发现 {duplicate_count} 个重复文件")
    
    def handle_compare(self, md5_hash):
        compare_target = self.compare_target.get().strip()
        if not compare_target:
            return
        
        if md5_hash == compare_target:
            self.compare_result_var.set("比对结果: 匹配")
            self.compare_result_label.config(foreground="green")
        else:
            self.compare_result_var.set("比对结果: 不匹配")
            self.compare_result_label.config(foreground="red")
    
    def display_result(self, result):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", result)
        self.result_text.config(state="disabled")
    
    def copy_result(self):
        if self.input_method.get() == "multi_file":
            # 复制多文件结果
            result = ""
            for item in self.multi_result_tree.get_children():
                values = self.multi_result_tree.item(item, 'values')
                result += f"{values[0]}\t{values[1]}\t{values[2]}\n"
        else:
            # 复制单结果
            result = self.result_text.get("1.0", tk.END).strip()
        
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)
            self.status_var.set("结果已复制到剪贴板")
        else:
            self.show_warning("没有可复制的MD5结果")
    
    def save_result(self):
        if self.input_method.get() == "multi_file":
            # 保存多文件结果
            default_filename = "md5_results.txt"
            result = ""
            for item in self.multi_result_tree.get_children():
                values = self.multi_result_tree.item(item, 'values')
                result += f"{values[0]}\t{values[1]}\t{values[2]}\n"
        else:
            # 保存单结果
            default_filename = "md5_result.txt"
            result = self.result_text.get("1.0", tk.END).strip()
        
        if not result:
            self.show_warning("没有可保存的MD5结果")
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
            except IOError as e:
                self.show_error(f"保存文件时出错: {str(e)}")
    
    def clear_all(self):
        # 清空所有输入和结果
        self.text_input.delete("1.0", tk.END)
        self.file_path.set("")
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
        # 格式化文件大小显示
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def show_warning(self, message):
        messagebox.showwarning("警告", message)
    
    def show_error(self, message):
        messagebox.showerror("错误", message)

if __name__ == "__main__":
    app = EnhancedMD5CalculatorApp()
    app.mainloop()