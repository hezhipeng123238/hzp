import hashlib

def calculate_md5(file_path):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.md5()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()

# 替换为测试文件的路径
file_path = 'D:"C:\\Users\\10742\\Desktop\\新建文件夹"'
md5_hash = calculate_md5(file_path)
print("MD5 Hash of test file:", md5_hash)

import os
import shutil
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# 模拟的恶意软件签名（可以是文件哈希值或特征）
MALICIOUS_SIGNATURES = [
    'e99a18c428cb38d5f260853678922e03',  # 示例哈希值，实际应是恶意文件的哈希
    'aab5f25c042a0f703f207c27b5b87033'
]

# 隔离区目录
ISOLATION_FOLDER = './quarantine'


# 检查文件是否包含恶意签名
def check_file_for_malware(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        file_hash = hash_md5.hexdigest()
        return file_hash in MALICIOUS_SIGNATURES
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False


# 扫描目录中的所有文件
def scan_directory(directory, progress_bar, text_output):
    malicious_files = []
    total_files = 0
    scanned_files = 0

    # 计算总文件数
    for root, dirs, files in os.walk(directory):
        total_files += len(files)

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            progress_bar['value'] = (scanned_files / total_files) * 100
            progress_bar.update()

            # 显示当前正在扫描的文件
            text_output.insert(tk.END, f"扫描: {file_path}\n")
            text_output.yview(tk.END)  # 自动滚动到最新内容
            scanned_files += 1

            if check_file_for_malware(file_path):
                malicious_files.append(file_path)

    return malicious_files


# 隔离恶意文件
def isolate_files(files):
    if not os.path.exists(ISOLATION_FOLDER):
        os.makedirs(ISOLATION_FOLDER)

    for file in files:
        try:
            file_name = os.path.basename(file)
            isolation_path = os.path.join(ISOLATION_FOLDER, file_name)
            shutil.move(file, isolation_path)  # 将恶意文件移动到隔离区
        except Exception as e:
            print(f"The file cannot be isolated. {file}: {e}")


# 打印报告
def print_report(malicious_files, text_output):
    if malicious_files:
        text_output.insert(tk.END, "\nThe scan is complete, and malicious files have been detected:\n")
        for file in malicious_files:
            text_output.insert(tk.END, f"- {file}\n")
    else:
        text_output.insert(tk.END, "\nThe scan is complete, and malicious files have been detected.\n")


# 主函数
def start_scan(directory, progress_bar, text_output):
    if not directory:
        messagebox.showwarning("Warning", "Please select the directory to scan first!")
        return

    malicious_files = scan_directory(directory, progress_bar, text_output)
    print_report(malicious_files, text_output)

    if malicious_files:
        isolate_files(malicious_files)
        messagebox.showinfo("Scan complete", f"{len(malicious_files)} malicious files found and quarantined!")
    else:
        messagebox.showinfo("Scan complete", "No malicious files found。")


# 打开文件夹选择对话框
def select_directory():
    directory = filedialog.askdirectory()
    return directory


# 创建GUI界面
def create_gui():
    # 初始化主窗口
    root = tk.Tk()
    root.title("Anti-malware scanner")
    root.geometry("600x400")

    # 选择扫描目录按钮
    select_button = tk.Button(root, text="Select directory", command=lambda: select_directory())
    select_button.pack(pady=10)

    # 显示选定目录
    directory_label = tk.Label(root, text="Select a directory to scan")
    directory_label.pack(pady=5)

    # 创建进度条
    progress_bar = ttk.Progressbar(root, length=400, mode='determinate')
    progress_bar.pack(pady=20)

    # 创建文本框，用于显示扫描输出
    text_output = tk.Text(root, height=10, width=70)
    text_output.pack(pady=10)

    # 扫描按钮
    scan_button = tk.Button(root, text="Start scanning",
                            command=lambda: start_scan(select_directory(), progress_bar, text_output))
    scan_button.pack(pady=10)

    # 运行GUI主循环
    root.mainloop()


# 运行程序
if __name__ == "__main__":
    create_gui()