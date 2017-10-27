import os
import json
import hmac
import hashlib
#import Crypto
#from cryptography.hazmat.primitives import load_pem_public_key
#from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size) #Adds padding
unpad = lambda s: s[:-ord(s[len(s)-1:])] #removes padding

def encrypter(message, public_key):
    #rsa_object = RSA.generate(2048) #initialize 2048-bit RSA object
    key_file = open(public_key, 'r') #opens the public key file, read only and binary mode
    rsa_key = RSA.importKey(key_file.read()) #imports RSA key
    rsa_cipher = PKCS1_OAEP.new(rsa_key) #creates RSA object using the RSA public key with OAEP
    message = pad(message)
    aes_key = os.urandom(32) #256-bit key used for AES
    iv = os.urandom(AES.block_size) #128-bit IV (16 bytes)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, iv) #AES object 
    ciph_text = iv + aes_obj.encrypt(message) #generates ciphertext with AES key and prepadded with IV
    hmac_key = os.urandom(32) #256-bit key used for HMAC
    hmac_obj = hmac.new(hmac_key, ciph_text, hashlib.sha256) #create HMAC object using the shared public key and SHA256
    hmac_tag = hmac_obj.digest() #creates the hmac tag, not sure if implemented correctly
    #print("AES Key:" + str(aes_key) + " length: " + str(len(aes_key)))
    #print("HMAC Key:" + str(hmac_key) + " length: " + str(len(hmac_key)))
    conc_key = aes_key + hmac_key #concatanates keys (512-bit total)
    ciph_key = rsa_cipher.encrypt(conc_key) #encrypts the concatenation of the AES and HMAC key 
    #json_data = b'[{"RSA_cipher": ciph_key, "AES_cipher": ciph_text, "IV": iv, "tag": hmac_tag}]'
    json_output = {"RSA_cipher": ciph_key, "AES_cipher": ciph_text, "IV": iv, "tag": hmac_tag}
    #json_decode = json_data.decode('utf8').replace("'", '"')
    #json_output = json.dumps(json_decode)

    return json_output
    #pub_key = load_pem_public_key(public_key, backend=default_backend()) #RSA Public Key
    #aes_gen_key = AESGCM.generate_key(bit-length=256) #Generates 256-bit AES Key
    #aesgcm = AESGCM(aes_gen_key)
    #encrypt message with AES key, prepended with IV
    #HMAC (SHA-256) on ciphertext to create integrity tag 
    #concatenate AES & HMAC keys and encrypt with RSA
    #create json object with RSA ciphertext, AES ciphertext, HMAC tag
    #note size of each key

def decrypter(json_object, private_key):
    #rsa_obj = RSA.generate(2048) #creates a 2048-bit RSA object
    key_file = open(private_key, 'r') #opens file containing RSA private key
    rsa_private_key = RSA.importKey(key_file.read(), "doubletrouble")
    rsa_cipher = PKCS1_OAEP.new(rsa_private_key) #initialzes RSA object using OAEP and private key
    #parsed_json = json.loads(json_object) #parsed JSON object 
    concat_key = rsa_cipher.decrypt(json_object["RSA_cipher"]) #decrypts the concatanated cipher keys that was encrypted using RSA
    aes_key = concat_key[:len(concat_key)//2] #first half of concatanated key
    hmac_key = concat_key[len(concat_key)//2:] #second half of concataneted key
    #print("Decrypting...")
    #print("AES Key:" + str(aes_key) + " length: " + str(len(aes_key)))
    #print("HMAC Key:" + str(hmac_key) + " length: " + str(len(hmac_key)))
    hmac_obj = hmac.new(hmac_key, json_object["AES_cipher"], hashlib.sha256)
    hmac_tag = hmac_obj.digest()
    #Integrity check to ensure message wasn't modified
    if(hmac_tag != json_object["tag"]):
        return "failure"
    else: 
        aes_obj = AES.new(aes_key, AES.MODE_CBC, json_object["IV"]) #creates AES object using same AES key during encryption and same IV
        ciphertext = json_object["AES_cipher"][16:]
        #return "success"
        return unpad(aes_obj.decrypt(ciphertext)).decode('utf-8') #removes padding
        
        #return message

encrypt_test = encrypter("apple bottom jeans", "public.pem")
orig_message = decrypter(encrypt_test, "private.pem")
print(orig_message)