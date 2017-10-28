"""
Client Module for Encryption and Decryption
"""
import os
import json
import hmac
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac, padding

#Padding/Unpadding for AES encryption
sym_pad = padding.PKCS7(256).padder()
sym_unpad = padding.PKCS7(256).unpadder()

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

"""
RSA-OAEP object to load public key
AES object to generate 256-bit key
encrypt message with AES key, prepended with IV
Generate HMAC 256-bit key and HMAC (SHA-256) on ciphertext to create integrity tag 
Concatenate AES & HMAC keys and encrypt with RSA 
Create json object with RSA ciphertext, AES ciphertext, IV, and HMAC tag
note size of each key
"""
def encrypter(message, public_key):
    #Loading RSA Public Key
    key_file = open(public_key, 'rb') #opens the public key file, read only and binary mode
    load_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    public_key = load_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #Pads the message
    padded_message = sym_pad.update(message.encode('utf-8'))
    padded_message += sym_pad.finalize()

    #AES Message Encryption
    aes_key = os.urandom(32) #256-bit Key
    iv = os.urandom(16) #128-bit IV (16 bytes)
    #AES-CBC encryptor object
    aes_encrypt = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    ciph_text = aes_encrypt.update(padded_message) + aes_encrypt.finalize()

    #HMAC Tag Creation
    hmac_key = os.urandom(32) #256-bit key used for HMAC
    hmac_tag = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    hmac_tag.update(ciph_text)
    tag = hmac_tag.finalize()

    #Encrypting AES and HMAC Key using RSA
    conc_key = aes_key + hmac_key #concatanates keys (512-bit total)
    ciph_key = load_public_key.encrypt(
        conc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Creates JSON output, currently dict object
    output = {"RSA_cipher": ciph_key, "AES_cipher": ciph_text, "IV": iv, "tag": tag}
    return output
    #json_data = b'[{"RSA_cipher": ciph_key, "AES_cipher": ciph_text, "IV": iv, "tag": hmac_tag}]'
    #json_decode = json_data.decode('utf8').replace("'", '"')
    #json_output = json.dumps(json_decode)

"""
Initialize RSA-OAEP object with 2048-bit key size
Load private key into RSA-OAEP object
Decrypt RSA ciph_key to recover the pair of 256-bit keys
HMAC with the recovered HMAC key and compare the new HMAC tag to the one passed in the json object, return failure if this fails
Decrypt the AES ciphertext with the AES key and IV from encryption
Unpad the decrypted ciphetext
"""
def decrypter(json_object, private_key):
    key_file = open(private_key, 'rb') #opens file containing RSA private key
    load_private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    private_key = load_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    #parsed_json = json.loads(json_object) #parsed JSON object

    #decrypts the concatanated cipher keys that was encrypted using RSA
    concat_key = load_private_key.decrypt(
        json_object["RSA_cipher"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_key = concat_key[:len(concat_key)//2] #first half of concatanated key
    hmac_key = concat_key[len(concat_key)//2:] #second half of concataneted key

    #Generates HMAC tag for integrity check with the HMAC tag created from the ciphertext
    hmac_tag = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    hmac_tag.update(json_object["AES_cipher"])
    tag = hmac_tag.finalize()
    #Integrity check to ensure message wasn't modified
    if(tag != json_object["tag"]):
        print("New HMAC Tag:" + str(tag))
        print("Old HMAC Tag:" + str(json_object["tag"]))
        return "failure"
    else:
        #decrypts the AES encrypted ciphertext and removes the padding
        aes_decrypt = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(json_object["IV"]),
            backend=default_backend()
        ).decryptor()
        padded_message = aes_decrypt.update(json_object["AES_cipher"]) + aes_decrypt.finalize()
        #Unpads the message and returns it as plaintext
        message = sym_unpad.update(padded_message)
        return (message + sym_unpad.finalize()).decode('utf-8')

encrypt_test = encrypter("apple bottom jeans", "public_key.pem")
orig_message = decrypter(encrypt_test, "private_key.pem")
print(orig_message)
