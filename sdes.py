import tkinter as tk
from tkinter import messagebox

# 置换表和S盒
P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
P8 = [5, 2, 6, 3, 7, 4, 9, 8]
IP = [1, 5, 2, 0, 3, 7, 4, 6]
invIP = [3, 0, 2, 4, 6, 1, 7, 5]
EP = [3, 0, 1, 2, 1, 2, 3, 0]
P4 = [1, 3, 2, 0]
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2]
]
S1 = [
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3]
]


# 置换函数
def permute(input_bits, table):
    return ''.join(input_bits[i] for i in table)


# 左移函数
def left_shift(bits, n):
    return bits[n:] + bits[:n]


# 密钥生成
def keygen(key):
    p10key = permute(key, P10)
    shift1 = left_shift(p10key[:5], 1) + left_shift(p10key[5:], 1)
    k1 = permute(shift1, P8)
    shift2 = left_shift(shift1[:5], 2) + left_shift(shift1[5:], 2)
    k2 = permute(shift2, P8)
    return k1, k2


# 异或操作
def xor(bits1, bits2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))


# S盒替换
def sbox(input_bits, sbox):
    row = int(input_bits[0] + input_bits[3], 2)
    col = int(input_bits[1] + input_bits[2], 2)
    return f'{sbox[row][col]:02b}'


# f 函数实现
def f(right, subkey):
    expanded = permute(right, EP)
    xored = xor(expanded, subkey)
    left = sbox(xored[:4], S0)
    right_part = sbox(xored[4:], S1)
    return permute(left + right_part, P4)


# 单轮加密函数
def fk(bits, subkey):
    left, right = bits[:4], bits[4:]
    return xor(left, f(right, subkey)) + right


# 加密解密函数
def encrypt_decrypt(bits, key, encrypt=True):
    keys = keygen(key)
    initial_permuted = permute(bits, IP)
    round1 = fk(initial_permuted, keys[0 if encrypt else 1])
    switched = round1[4:] + round1[:4]
    round2 = fk(switched, keys[1 if encrypt else 0])
    return permute(round2, invIP)


# 验证输入格式
def verify_input(data, key):
    return len(data) == 8 and len(key) == 10 and all(bit in '01' for bit in data + key)


# ASCII 转二进制
def ascii_to_bin_list(text):
    return [bin(ord(c))[2:].zfill(8) for c in text]


# 二进制转 ASCII
def bin_list_to_ascii(bin_list):
    return ''.join(chr(int(b, 2)) for b in bin_list)


# 加密功能
def encrypt_bit():
    data = data_entry.get()
    key = key_entry.get()
    if not verify_input(data, key):
        messagebox.showerror("输入错误", "请输入8位二进制数据和10位二进制密钥。")
        return
    result = encrypt_decrypt(data, key, True)
    output_label.config(text=f"加密数据：{result}")


# 解密功能
def decrypt_bit():
    data = data_entry.get()
    key = key_entry.get()
    if not verify_input(data, key):
        messagebox.showerror("输入错误", "请输入8位二进制数据和10位二进制密钥。")
        return
    result = encrypt_decrypt(data, key, False)
    output_label.config(text=f"解密数据：{result}")


# ASCII 加密功能
def encrypt_ascii():
    text = ascii_data_entry.get()
    key = key_entry_ascii.get()
    if len(key) != 10 or not all(bit in '01' for bit in key):
        messagebox.showerror("输入错误", "请输入10位二进制密钥。")
        return
    bin_list = ascii_to_bin_list(text)
    encrypted_bin_list = [encrypt_decrypt(bits, key, True) for bits in bin_list]
    encrypted_text = bin_list_to_ascii(encrypted_bin_list)
    output_label_ascii.config(text=f"加密的ASCII数据：{encrypted_text}")


# ASCII 解密功能
def decrypt_ascii():
    text = ascii_data_entry.get()
    key = key_entry_ascii.get()
    if len(key) != 10 or not all(bit in '01' for bit in key):
        messagebox.showerror("输入错误", "请输入10位二进制密钥。")
        return
    bin_list = ascii_to_bin_list(text)
    decrypted_bin_list = [encrypt_decrypt(bits, key, False) for bits in bin_list]
    decrypted_text = bin_list_to_ascii(decrypted_bin_list)
    output_label_ascii.config(text=f"解密的ASCII数据：{decrypted_text}")


# 暴力破解功能
def brute_force():
    cipher_text = brute_force_cipher_entry.get()
    known_plaintext = brute_force_plain_entry.get()

    if not (len(cipher_text) == 8 and len(known_plaintext) == 8 and
            all(bit in '01' for bit in cipher_text + known_plaintext)):
        messagebox.showerror("输入错误", "请输入8位二进制密文和8位二进制明文。")
        return

    found_keys = []  # 用于存储可能的密钥
    progress = 0

    for i in range(1024):  # 生成所有可能的10位密钥
        key = f'{i:010b}'  # 将i转换为10位二进制格式
        decrypted_text = encrypt_decrypt(cipher_text, key, encrypt=False)

        # 显示当前正在尝试的密钥
        brute_force_output.config(text=f"尝试密钥: {key}")
        root.update()

        if decrypted_text == known_plaintext:  # 如果解密结果与已知明文一致
            found_keys.append(key)

        progress += 1
        progress_label.config(text=f"进度: {progress}/1024")

    # 显示结果
    if found_keys:
        brute_force_output.config(text=f"可能的密钥：{', '.join(found_keys)}")
    else:
        brute_force_output.config(text="没有找到合适的密钥。")

# 创建GUI界面
root = tk.Tk()
root.title("S-DES工具")

# 位加密/解密部分
tk.Label(root, text="请输入8位数据").grid(row=0, column=0)
data_entry = tk.Entry(root)
data_entry.grid(row=0, column=1)

tk.Label(root, text="请输入10位密钥").grid(row=1, column=0)
key_entry = tk.Entry(root)
key_entry.grid(row=1, column=1)

encrypt_button = tk.Button(root, text="加密", command=encrypt_bit)
encrypt_button.grid(row=2, column=0)

decrypt_button = tk.Button(root, text="解密", command=decrypt_bit)
decrypt_button.grid(row=2, column=1)

output_label = tk.Label(root, text="")
output_label.grid(row=3, column=0, columnspan=2)

# ASCII加密/解密部分
tk.Label(root, text="请输入ASCII数据").grid(row=4, column=0)
ascii_data_entry = tk.Entry(root)
ascii_data_entry.grid(row=4, column=1)

tk.Label(root, text="请输入10位密钥").grid(row=5, column=0)
key_entry_ascii = tk.Entry(root)
key_entry_ascii.grid(row=5, column=1)

encrypt_button_ascii = tk.Button(root, text="加密ASCII", command=encrypt_ascii)
encrypt_button_ascii.grid(row=6, column=0)

decrypt_button_ascii = tk.Button(root, text="解密ASCII", command=decrypt_ascii)
decrypt_button_ascii.grid(row=6, column=1)

output_label_ascii = tk.Label(root, text="")
output_label_ascii.grid(row=7, column=0, columnspan=2)

# 创建暴力破解部分的标签和输入框
tk.Label(root, text="密文(二进制)").grid(row=8, column=0)
brute_force_cipher_entry = tk.Entry(root)
brute_force_cipher_entry.grid(row=8, column=1)

tk.Label(root, text="已知明文(二进制)").grid(row=9, column=0)
brute_force_plain_entry = tk.Entry(root)
brute_force_plain_entry.grid(row=9, column=1)

# 暴力破解按钮
brute_force_button = tk.Button(root, text="暴力破解", command=brute_force)
brute_force_button.grid(row=10, column=0, columnspan=2)

# 暴力破解输出结果显示标签
brute_force_output = tk.Label(root, text="")
brute_force_output.grid(row=11, column=0, columnspan=2)

# 进度条显示
progress_label = tk.Label(root, text="进度: 0/1024")
progress_label.grid(row=12, column=0, columnspan=2)

root.mainloop()
