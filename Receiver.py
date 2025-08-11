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
#from Crypto import Random
print("Receive function starts...", end='\n\n')
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
#   讀入初始向量(iv)。
#   使用CBC的AES加密模式和iv來加密填充的明文。
#   回傳包含iv和密文的base64編碼。
def encrypt(plain_text, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    plain_text = pad(plain_text)
    print("After padding:", plain_text)
#    iv = iv_restored
#    cipher = AES.new(private_key, AES.MODE_CBC, iv)
#   return base64.b64encode(iv + cipher.encrypt(plain_text.encode("utf-8")))

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

# 從 Received Encrypted Data.txt 檔案中讀取密文進行比對
with open('Received Encrypted Data.txt', 'r') as Rec_P_V_i:
    ReceivedCiphertext = Rec_P_V_i.readline().strip()
print("Received Encrypted Data Binary:", ReceivedCiphertext)    
    
# 將二進制字串轉換為二進制資料
comparison_mat = bytes(int(ReceivedCiphertext[i:i+8], 2) for i in range(0, len(ReceivedCiphertext), 8))
print("Received Encrypted Data Binary:", comparison_mat)

comparison = base64.b64encode(comparison_mat)
print("Restored Encrypted message:", comparison)

# 從 response_V_i.txt 檔案中讀取資料製作key
with open('response_V_i.txt', 'r') as key_file1:
    key1 = key_file1.readline().strip()

# 從 c.txt 檔案中讀取資料製作key
with open('c.txt', 'r') as key_file2:
    key2 = key_file2.readline().strip()

#將 key1 key2進行XOR
def xor_strings(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))
MSK_s_che = xor_strings( key1 , key2 )

def hash_to_binary_string(text: str) -> str:
    """將輸入字串經過 SHA-256 雜湊，並轉為 01 字串"""
    sha256_hash = hashlib.sha256(text.encode('utf-8')).digest()  # 32 bytes
    binary_string = ''.join(f'{byte:08b}' for byte in sha256_hash)  # 每個 byte 轉成 8 位元
    return binary_string

h_MSK_che = hash_to_binary_string(MSK_s_che)
print("SHA-256 hash:", h_MSK_che)


if h_MSK_che == ReceivedCiphertext:
    print("System Success.")
    print("Message has been transmitted securely.")
else:
    print("A technical problem occurred.")


# 從 message.txt 檔案中讀取要加密的訊息
#with open('message.txt', 'r') as message_file:
#   message = message_file.readline().strip()

# 從 first_16_bits.txt 檔案中讀取要比對的訊息
#with open('first_256_bits.txt', 'r') as comparison_file:
#    comparison = comparison_file.readline().strip()




# 輸入要進行SHA-256雜湊的資料
#data = input("Enter data to hashing: ")   
#data_sha = hashlib.sha256(data.encode('utf-8')).hexdigest()

# 顯示雜湊後的資料
#print("Hashes:", data_sha)



