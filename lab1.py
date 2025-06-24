def caesar_cipher_encrypt(text, shift):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def caesar_cipher_decrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)

def brute_force_caesar(ciphertext):
    for shift in range(1, 26):
        print(f"Shift {shift}: {caesar_cipher_decrypt(ciphertext, shift)}")

# XOR decryption with base64
import base64

def xor_decrypt_base64(b64_string, key):
    cipher_bytes = base64.b64decode(b64_string)
    key_bytes = key.encode()
    plaintext = bytearray()
    for i in range(len(cipher_bytes)):
        plaintext.append(cipher_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return plaintext.decode()

# Sample usage
ciphertext = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."
brute_force_caesar(ciphertext)

xor_message = "Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ="
key = "cipher"
print(xor_decrypt_base64(xor_message, key))
