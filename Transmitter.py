# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
# conda install -c anaconda pycryptodome
# 引入所需的模組，包含base64、hashlib、Crypto.Cipher、Crypto、Random。
import base64
import hashlib
import secrets
import string
from Crypto.Cipher import AES
from Crypto import Random
print("Transfer function starts...", end='\n\n')
# 設定AES加密的區塊大小為16位元組，因為在AES中輸入的字串應該是16的倍數。
BLOCK_SIZE = 16

# 填充明文，確保它的長度是BLOCK_SIZE的倍數，填充的字節數量取決於所需的填充量。
def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

# 移除填充，還原原始明文。
def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]

# 接收明文和密鑰後執行以下操作：
#   使用提供的密鑰生成私鑰，並將明文填充。
#   生成一個初始向量(iv)。
#   使用CBC的AES加密模式和iv來加密填充的明文。
#   回傳包含iv和密文的base64編碼。
def encrypt(plain_text, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    plain_text = pad(plain_text)
    #print("After padding:", plain_text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plain_text.encode("utf-8"))), iv

# 接收密文和密鑰後執行以下操作：
#   將base64解碼後的密文還原為iv和加密的明文。
#   使用CBC的AES解密模式和iv來解密密文。
#   使用unpad來移除填充並回傳明文。
def decrypt(cipher_text, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[16:])).decode("utf-8")

# 從 key.txt 檔案中讀取資料製作key
with open('key.txt', 'r') as key_file:
    key = key_file.readline().strip()

# 從 V_i.txt 檔案中讀取V_i ID
with open('V_i.txt', 'r') as V_i_file:
    V_i = V_i_file.readline().strip()
print("ID of V_i:", V_i)

# 從 response_V_i.txt 檔案中讀取資料製作MSK_s
with open('response_V_i.txt', 'r') as response_V_i_file:
    response_V_i = response_V_i_file.readline().strip()
print("Response of V_i:", response_V_i)

# 從 MSK_V_i.txt 檔案中讀取資料製作MSK_s
with open('MSK_V_i.txt', 'r') as MSK_V_i_file:
    MSK_V_i = MSK_V_i_file.readline().strip()
print("MSK_V_i:", MSK_V_i)

#將response和V_i所擁有的key進行XOR
def xor_strings(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))
MSK_s = xor_strings(MSK_V_i, response_V_i)


#產生隨機亂數a
a = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
print("random number a:", a)

#產生隨機亂數b
b = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
print("random number b:", b)

# 將 c 值寫入到 txt 檔案中
c = 'MYqNVVzcno0w' 
with open('c.txt', 'w') as file:
    file.write(c)

#把ID和a串接

encrypted_par = V_i + c
print("encrypted_par:", encrypted_par)

#用MSK加密ID和亂數a
encrypted_par, iv = encrypt(encrypted_par, MSK_s)
print("P_V_i:", encrypted_par)

# 輸入要進行SHA-256雜湊的資料
sk = hashlib.sha256(encrypted_par).hexdigest()
# 顯示雜湊後的資料
print("Session Key:", sk)

# 將 iv 轉換為二進制字串
iv_binary_str = ''.join(format(byte, '08b') for byte in iv)
# 將 iv 值寫入到 txt 檔案中
with open('iv.txt', 'w') as file:
    file.write(iv_binary_str)

print("iv:", iv)
print("iv_binary:", iv_binary_str)

#將response和V_i所擁有的key進行XOR
def xor_strings(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))
MSK_s = xor_strings(response_V_i , c )

def hash_string_sha256(text: str) -> str:
    """將字串進行 SHA-256 雜湊並回傳十六進位字串"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def hash_to_binary_string(text: str) -> str:
    """將輸入字串經過 SHA-256 雜湊，並轉為 01 字串"""
    sha256_hash = hashlib.sha256(text.encode('utf-8')).digest()  # 32 bytes
    binary_string = ''.join(f'{byte:08b}' for byte in sha256_hash)  # 每個 byte 轉成 8 位元
    return binary_string

h_MSK = hash_to_binary_string(MSK_s)
print("Encrypted Data P_(V_i):", h_MSK)

# 將文字逐一寫入檔案
with open('Encrypted Data.txt', 'w') as file:
    file.write(h_MSK)


#==============================================================================

# 將 0 和 1 的字串還原回二進制資料
#binary_data_restored = bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))
# 輸出還原後的二進制資料
#print("Restored Binary Data:", binary_data_restored)
# 將還原回的二進制資料編碼成可利用的密文形式
#encrypted_par_restored = base64.b64encode(binary_data_restored)
#print("Restored Encrypted message:", encrypted_par_restored)

# 將二進制資料轉換為矩陣形式
#def convert_to_matrix(binary_str):
#    matrix = []
#    for i in range(0, len(binary_str), 4):  # 每4位元一個元素
#       matrix.append([binary_str[i:i+4]])  # 將每4位元作為一個元素加入矩陣
#    return matrix

#matrix = convert_to_matrix(binary_str)
#for row in matrix:
#    print("binary_str in Matrix:", row) 

# 取得前四組矩陣
#first_four_rows = matrix[:4]

# 輸出前四組矩陣
#for row in first_four_rows:
#    print("binary_str's first four rows:",row)    
    
#first_four_rows = 'first_four_rows.txt'

# 將前四組矩陣的內容寫入文字檔
#with open(first_four_rows, 'w') as file:
#    for row in matrix[:64]:  # 只寫入前四組矩陣
#        file.write(' '.join(row) + '\n')      

#decrypted_par_restored = decrypt(encrypted_par_restored, MSK_s)
#print("Decrypted Restored Message:", decrypted_par_restored)

#將用於生成session key的a及b串接
#sk_elem = a + b 

# 取出前256個位元
#first_256_bits = h_MSK_01[:256]
#print("First 256 bits:", first_256_bits)
#with open('first_256_bits.txt', 'w') as file:
#    file.write(first_256_bits)



# 解密訊息並顯示解密後的結果。
#decrypted_par = decrypt(encrypted_par, MSK_s)
#print("Decrypted P_V_i:", decrypted_par)






