from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import sys

def adjust_key(key, required_length):
    if len(key) < required_length:
        # Rellenar con bytes aleatorios si la clave es demasiado corta
        additional_bytes = get_random_bytes(required_length - len(key))
        adjusted_key = key + additional_bytes
    elif len(key) > required_length:
        # Truncar al último byte si la clave es demasiado larga
        adjusted_key = key[-required_length:]
    else:
        # Si la longitud es correcta, no se modifica
        adjusted_key = key

    print("Clave ajustada utilizada (en hexadecimal):", adjusted_key.hex())
    return adjusted_key

def get_inputs():
    print("Seleccione el algoritmo de cifrado:")
    print("1 - DES")
    print("2 - AES-256")
    print("3 - 3DES")
    option = input("Ingrese el número del algoritmo: ").strip()

    if option == '1':
        key_length = 8
        iv_length = 8
        cipher_class = DES
    elif option == '2':
        key_length = 32
        iv_length = 16
        cipher_class = AES
    elif option == '3':
        key_length = 24
        iv_length = 8
        cipher_class = DES3
    else:
        print("Opción no válida.")
        sys.exit(1)
    
    print(f"Ingrese la clave en hexadecimal (de cualquier longitud, ajustada a {key_length} bytes si es necesario): ")
    key_hex = input().strip()
    try:
        key = binascii.unhexlify(key_hex)
    except binascii.Error:
        print("Clave en formato hexadecimal no válida.")
        sys.exit(1)
    
    key = adjust_key(key, key_length)  # Ajustar la clave según la longitud requerida
    
    print(f"Ingrese el vector de inicialización (IV) en hexadecimal (debe ser de {iv_length} caracteres hexadecimales): ")
    iv_hex = input().strip()
    try:
        iv = binascii.unhexlify(iv_hex)
    except binascii.Error:
        print("IV en formato hexadecimal no válido.")
        sys.exit(1)
    
    if len(iv) != iv_length:
        print(f"El IV debe tener {iv_length} bytes.")
        sys.exit(1)
    
    print("Ingrese el texto a cifrar: ")
    text = input().encode('utf-8')
    
    return cipher_class, key, iv, text

def encrypt(algorithm, key, iv, text):
    cipher = algorithm.new(key, algorithm.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(pad(text, algorithm.block_size))
    return encrypted_text

def decrypt(algorithm, key, iv, encrypted_text):
    cipher = algorithm.new(key, algorithm.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_text), algorithm.block_size)
    return decrypted_text

def main():
    cipher_class, key, iv, text = get_inputs()
    
    encrypted_text = encrypt(cipher_class, key, iv, text)
    print("Texto cifrado (en hexadecimal):", encrypted_text.hex())
    
    decrypted_text = decrypt(cipher_class, key, iv, encrypted_text)
    print("Texto descifrado:", decrypted_text.decode('utf-8'))

if __name__ == "__main__":
    main()
