from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt_decrypt_message(algorithm):
    if algorithm == 'DES':
        # Longitud de clave y IV para DES
        key_length = 8  # 8 bytes = 64 bits
        iv_length = 8
        mode = DES.MODE_CBC

    elif algorithm == 'AES-256':
        # Longitud de clave y IV para AES-256
        key_length = 32  # 32 bytes = 256 bits
        iv_length = 16
        mode = AES.MODE_CBC

    elif algorithm == '3DES':
        # Longitud de clave y IV para 3DES
        key_length = 24  # 24 bytes = 192 bits
        iv_length = 8
        mode = DES3.MODE_CBC

    else:
        print("Algoritmo no soportado.")
        return

    # Solicitar clave, IV y texto desde la terminal
    key = input(f"Ingresa la clave de {key_length} bytes para {algorithm}: ").encode()
    iv = input(f"Ingresa el vector de inicialización de {iv_length} bytes para {algorithm}: ").encode()
    plaintext = input("Ingresa el texto a cifrar: ").encode()

    # Validar longitud de la clave y IV
    if len(key) != key_length:
        print(f"La clave debe tener {key_length} bytes.")
        return
    if len(iv) != iv_length:
        print(f"El IV debe tener {iv_length} bytes.")
        return

    # Cifrado
    if algorithm == 'DES':
        cipher = DES.new(key, mode, iv)
    elif algorithm == 'AES-256':
        cipher = AES.new(key, mode, iv)
    elif algorithm == '3DES':
        cipher = DES3.new(key, mode, iv)

    # Cifrado y codificación
    ciphertext = cipher.encrypt(pad(plaintext, cipher.block_size))
    encoded_ciphertext = base64.b64encode(ciphertext).decode()
    print(f"\nTexto cifrado (base64): {encoded_ciphertext}")

    # Descifrado
    cipher_dec = None
    if algorithm == 'DES':
        cipher_dec = DES.new(key, mode, iv)
    elif algorithm == 'AES-256':
        cipher_dec = AES.new(key, mode, iv)
    elif algorithm == '3DES':
        cipher_dec = DES3.new(key, mode, iv)

    decrypted_data = unpad(cipher_dec.decrypt(base64.b64decode(encoded_ciphertext)), cipher_dec.block_size)
    print(f"Texto descifrado: {decrypted_data.decode()}")

# Menú para elegir el algoritmo
def main():
    print("Elige el algoritmo de cifrado:")
    print("1. DES")
    print("2. AES-256")
    print("3. 3DES")

    option = input("Selecciona el número del algoritmo: ")

    if option == '1':
        encrypt_decrypt_message('DES')
    elif option == '2':
        encrypt_decrypt_message('AES-256')
    elif option == '3':
        encrypt_decrypt_message('3DES')
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    main()
