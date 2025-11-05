from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def ensure_length(label: str, data: bytes, required: int) -> bytes:
    if len(data) < required:
        missing = required - len(data)
        random_bytes = get_random_bytes(missing)
        random_text = ''.join(chr(b % 95 + 32) for b in random_bytes)
        combined = data.decode('utf-8', errors='ignore') + random_text
        print(f"Se utilizará {label} (texto plano): {combined}")
        return data + random_bytes
    
    elif len(data) > required:
        truncated = data[:required].decode('utf-8', errors='ignore')
        print(f"Se utilizará {label} (texto plano, truncado): {truncated}")
        return data[:required]
        
    else:
        print(f"Se utilizará {label} (texto plano): {data.decode('utf-8', errors='ignore')}")
        return data

def encrypt_decrypt(cipher_cls, key, iv, plaintext, block_size):
    cipher = cipher_cls.new(key, cipher_cls.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), block_size))
    decipher = cipher_cls.new(key, cipher_cls.MODE_CBC, iv)
    pt = unpad(decipher.decrypt(ct), block_size)
    return ct, pt

print("Seleccione algoritmo de cifrado:")
print("1. DES")
print("2. 3DES")
print("3. AES-256")

choice = input("Opción: ").strip()

if choice == "1":
    algoname = "DES"
    key_size, iv_size, cipher_cls = 8, 8, DES
elif choice == "2":
    algoname = "3DES"
    key_size, iv_size, cipher_cls = 24, 8, DES3
elif choice == "3":
    algoname = "AES-256"
    key_size, iv_size, cipher_cls = 32, 16, AES
else:
    print("Opción inválida.")
    exit(1)

# ---- Entrada de clave ----
key_input = input(f"Ingrese la clave para {algoname}: ")
key_bytes = key_input.encode('utf-8')

# ---- Entrada de IV ----
iv_input = input(f"Ingrese el IV para {algoname}: ")
iv_bytes = iv_input.encode('utf-8')

# ---- Entrada de texto ----
text_input = input("Ingrese el texto a cifrar: ")
print()

# ---- Ajuste de longitudes ----
key = ensure_length("la clave", key_bytes, key_size)
iv = ensure_length("el IV", iv_bytes, iv_size)
print(f"Texto a cifrar (texto plano): {text_input}")
if cipher_cls == DES3:
    key = DES3.adjust_key_parity(key)

# ---- Cifrado / Descifrado ----
ct, pt = encrypt_decrypt(cipher_cls, key, iv, text_input, cipher_cls.block_size)
ct_b64 = base64.b64encode(ct).decode()

print(f"\nTexto cifrado ({algoname}, Base64): {ct_b64}")
print(f"Texto descifrado ({algoname}): {pt.decode(errors='replace')}")
