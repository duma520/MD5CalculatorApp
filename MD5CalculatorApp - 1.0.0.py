import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os

class MD5CalculatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MD5计算工具")
        self.root.geometry("600x400")
        
        self.create_widgets()
        self.setup_layout()
    
    def create_widgets(self):
        # 输入方式选择
        self.input_method = tk.StringVar(value="text")
        self.text_radio = ttk.Radiobutton(
            self.root, text="文本输入", variable=self.input_method, value="text",
            command=self.toggle_input_method)
        self.file_radio = ttk.Radiobutton(
            self.root, text="文件输入", variable=self.input_method, value="file",
            command=self.toggle_input_method)
        
        # 文本输入区域
        self.text_frame = ttk.LabelFrame(self.root, text="文本输入")
        self.text_input = tk.Text(self.text_frame, height=10, wrap=tk.WORD)
        self.text_scroll = ttk.Scrollbar(
            self.text_frame, orient=tk.VERTICAL, command=self.text_input.yview)
        self.text_input.configure(yscrollcommand=self.text_scroll.set)
        
        # 文件输入区域
        self.file_frame = ttk.LabelFrame(self.root, text="文件输入")
        self.file_path = tk.StringVar()
        self.file_entry = ttk.Entry(
            self.file_frame, textvariable=self.file_path, state="readonly")
        self.browse_button = ttk.Button(
            self.file_frame, text="浏览...", command=self.browse_file)
        
        # 计算选项
        self.options_frame = ttk.LabelFrame(self.root, text="计算选项")
        self.uppercase_var = tk.BooleanVar(value=True)
        self.uppercase_check = ttk.Checkbutton(
            self.options_frame, text="大写结果", variable=self.uppercase_var)
        
        # 计算按钮
        self.calculate_button = ttk.Button(
            self.root, text="计算MD5", command=self.calculate_md5)
        
        # 结果显示
        self.result_frame = ttk.LabelFrame(self.root, text="MD5结果")
        self.result_text = tk.Text(
            self.result_frame, height=5, wrap=tk.WORD, state="disabled")
        self.result_scroll = ttk.Scrollbar(
            self.result_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=self.result_scroll.set)
        
        # 操作按钮
        self.button_frame = ttk.Frame(self.root)
        self.copy_button = ttk.Button(
            self.button_frame, text="复制结果", command=self.copy_result)
        self.clear_button = ttk.Button(
            self.button_frame, text="清空", command=self.clear_all)
        self.exit_button = ttk.Button(
            self.button_frame, text="退出", command=self.root.quit)
    
    def setup_layout(self):
        # 输入方式选择
        input_method_frame = ttk.Frame(self.root)
        input_method_frame.pack(pady=5, fill=tk.X)
        ttk.Label(input_method_frame, text="输入方式:").pack(side=tk.LEFT, padx=5)
        self.text_radio.pack(side=tk.LEFT, padx=5)
        self.file_radio.pack(side=tk.LEFT, padx=5)
        
        # 文本输入区域
        self.text_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.text_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 文件输入区域 (初始隐藏)
        self.file_frame.pack(pady=5, padx=10, fill=tk.X)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_button.pack(side=tk.RIGHT, padx=5)
        self.file_frame.pack_forget()
        
        # 计算选项
        self.options_frame.pack(pady=5, padx=10, fill=tk.X)
        self.uppercase_check.pack(side=tk.LEFT, padx=5)
        
        # 计算按钮
        self.calculate_button.pack(pady=10)
        
        # 结果显示
        self.result_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.result_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 操作按钮
        self.button_frame.pack(pady=10, fill=tk.X)
        self.copy_button.pack(side=tk.LEFT, padx=10, expand=True)
        self.clear_button.pack(side=tk.LEFT, padx=10, expand=True)
        self.exit_button.pack(side=tk.LEFT, padx=10, expand=True)
    
    def toggle_input_method(self):
        if self.input_method.get() == "text":
            self.file_frame.pack_forget()
            self.text_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        else:
            self.text_frame.pack_forget()
            self.file_frame.pack(pady=5, padx=10, fill=tk.X)
    
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
    
    def calculate_md5(self):
        try:
            if self.input_method.get() == "text":
                content = self.text_input.get("1.0", tk.END).encode('utf-8')
                if not content.strip():
                    messagebox.showwarning("警告", "请输入要计算MD5的文本内容")
                    return
                md5_hash = hashlib.md5(content).hexdigest()
            else:
                filepath = self.file_path.get()
                if not filepath:
                    messagebox.showwarning("警告", "请选择要计算MD5的文件")
                    return
                
                if not os.path.exists(filepath):
                    messagebox.showerror("错误", "文件不存在或路径无效")
                    return
                
                # 计算大文件的MD5
                hash_md5 = hashlib.md5()
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                md5_hash = hash_md5.hexdigest()
            
            if self.uppercase_var.get():
                md5_hash = md5_hash.upper()
            
            self.display_result(md5_hash)
        except Exception as e:
            messagebox.showerror("错误", f"计算MD5时发生错误:\n{str(e)}")
    
    def display_result(self, result):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", result)
        self.result_text.config(state="disabled")
    
    def copy_result(self):
        result = self.result_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("成功", "MD5结果已复制到剪贴板")
        else:
            messagebox.showwarning("警告", "没有可复制的MD5结果")
    
    def clear_all(self):
        self.text_input.delete("1.0", tk.END)
        self.file_path.set("")
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = MD5CalculatorApp(root)
    root.mainloop()