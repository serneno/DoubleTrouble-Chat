import os
#import Crypto
from cryptography.hazmat.primitives import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import RSA
from Crypto import Random
import json
import hmac
import hashlib

def encrypter(message, public_key):
    key_file = open(public_key, 'rb') #opens the public key file, read only and binary mode
    rsa_key = RSA.importKey(key_file.read()) #imports RSA key
    rsa_cipher = PKCS1_OAEP.new(rsa_key) #creates RSA object using the RSA key with OAEP
    aes_key = os.urandom(32) #256-bit key used for AES
    iv = os.urandom(AES.block_size) #128-bit IV (16 bytes)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, iv) #AES object 
    ciph_text = iv + cipher.encrypt(message) #generates ciphertext with AES key and prepadded with IV
    hmac_key = os.urandom(32) #256-bit key used for HMAC
    hmac_obj = hmac.new(hmac_key, ciph_text, hashlib.sha256) #create HMAC object using the shared public key and SHA256
    hmac_tag = hmac_obj.digest() #creates the hmac tag, not sure if implemented correctly
    conc_key = aes_key + hmac_key #concatanates keys (512-bit total)
    ciph_key = rsa_cipher.encrypt(conc_key) #encrypts the concatenation of the AES and HMAC key 
    json_data = {"RSA_cipher" = ciph_key, "AES_cipher" = ciph_text, "tag" = hmac_tag}
    json_output = json.dumps(json_data)

    return json_output
    #pub_key = load_pem_public_key(public_key, backend=default_backend()) #RSA Public Key
    #aes_gen_key = AESGCM.generate_key(bit-length=256) #Generates 256-bit AES Key
    #aesgcm = AESGCM(aes_gen_key)
    #encrypt message with AES key, prepended with IV
    #HMAC (SHA-256) on ciphertext to create integrity tag 
    #concatenate AES & HMAC keys and encrypt with RSA
    #create json object with RSA ciphertext, AES ciphertext, HMAC tag
    #note size of each key

def decrypter(json_object):
    
    orig_message = "apple"

    return orig_message


