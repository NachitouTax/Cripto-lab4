from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt_des(key, iv, plaintext):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_des(key, iv, ciphertext):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), DES.block_size)
    return decrypted.decode('utf-8')

def encrypt_aes(key, iv, plaintext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes(key, iv, ciphertext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted.decode('utf-8')

def encrypt_3des(key, iv, plaintext):
    cipher = DES3.new(key.encode('utf-8'), DES3.MODE_CBC, iv.encode('utf-8'))
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_3des(key, iv, ciphertext):
    cipher = DES3.new(key.encode('utf-8'), DES3.MODE_CBC, iv.encode('utf-8'))
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), DES3.block_size)
    return decrypted.decode('utf-8')

def main():
    print("Seleccione el algoritmo:")
    print("1. DES")
    print("2. AES-256")
    print("3. 3DES")
    choice = input("Ingrese el número del algoritmo: ")

    key = input("Ingrese la key (para DES y 3DES, debe ser de 8/24 bytes; para AES-256, debe ser de 32 bytes): ")
    iv = input("Ingrese el vector de inicialización (IV) (debe ser de 16 bytes): ")
    plaintext = input("Ingrese el texto a cifrar: ")

    if choice == '1':
        # DES
        if len(key) != 8:
            print("La key para DES debe ser de 8 bytes.")
            return
        if len(iv) != 16:
            print("El IV debe ser de 16 bytes.")
            return
        ciphertext = encrypt_des(key, iv, plaintext)
        print("Texto cifrado (DES):", ciphertext)
        decrypted = decrypt_des(key, iv, ciphertext)
        print("Texto descifrado (DES):", decrypted)

    elif choice == '2':
        # AES-256
        if len(key) != 32:
            print("La key para AES-256 debe ser de 32 bytes.")
            return
        if len(iv) != 16:
            print("El IV debe ser de 16 bytes.")
            return
        ciphertext = encrypt_aes(key, iv, plaintext)
        print("Texto cifrado (AES-256):", ciphertext)
        decrypted = decrypt_aes(key, iv, ciphertext)
        print("Texto descifrado (AES-256):", decrypted)

    elif choice == '3':
        # 3DES
        if len(key) != 24:
            print("La key para 3DES debe ser de 24 bytes.")
            return
        if len(iv) != 16:
            print("El IV debe ser de 16 bytes.")
            return
        ciphertext = encrypt_3des(key, iv, plaintext)
        print("Texto cifrado (3DES):", ciphertext)
        decrypted = decrypt_3des(key, iv, ciphertext)
        print("Texto descifrado (3DES):", decrypted)

    else:
        print("Opción no válida.")

if __name__ == "__main__":
    main()
