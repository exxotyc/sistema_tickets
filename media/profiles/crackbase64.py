from base64 import b64decode
from Crypto.Cipher import DES3

# Clave DES-EDE3 de 24 bytes (Triple DES)
key = b'rcmail-!24ByteD**'  # Asegúrate de que sea de 24 bytes exactos

# Valores cifrados en base64
data = {
    'contraseña': 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/',
    'secreto_de_autorización': 'DpYqv6maI9HxDL5GhcCd8JaQQW==',
    'token_de_solicitud': 'TIsOaABA1zHSXZOBpH6up5XFyayNRHaw'
}

def decrypt_des3_cbc(value, key):
    try:
        raw = b64decode(value)
        iv = raw[:8]  # Vector de inicialización de 8 bytes
        cipher_text = raw[8:]  # El resto es el texto cifrado
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = cipher.decrypt(cipher_text)
        # Quita padding (relleno)
        decrypted = decrypted.rstrip(b'\x00')[:-1]
        return decrypted.decode(errors='replace')
    except Exception as e:
        return f"[ERROR] {e}"

# Descifrar todos los valores
for k, v in data.items():
    result = decrypt_des3_cbc(v, key)
    print(f"[+] Decrypted {k}: {result}")
