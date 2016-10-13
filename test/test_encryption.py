#!/usr/bin/python

# test that privcount's encryption and decryption functions work

# this test will exit successfully if the decrypted data matches the original
# encrypted data

from os import urandom
from base64 import b64encode, b64decode

from privcount.util import load_public_key_file, load_private_key_file, encrypt, decrypt

PUBLIC_KEY_PATH = 'keys/sk.cert'
PRIVATE_KEY_PATH = 'keys/sk.pem'

# This is the maximum number of bytes OpenSSL will encrypt with PrivCount's
# current public key size (determined by trying different values)
ENCRYPTION_LENGTH_MAX = 446

print "Loading public key {}:".format(PUBLIC_KEY_PATH)
pub_key = load_public_key_file(PUBLIC_KEY_PATH)

print "Loading private key {}:".format(PRIVATE_KEY_PATH)
priv_key = load_private_key_file(PRIVATE_KEY_PATH)

print "Generating {} bytes of plaintext:".format(ENCRYPTION_LENGTH_MAX)
plaintext = b64encode(urandom(ENCRYPTION_LENGTH_MAX))[:ENCRYPTION_LENGTH_MAX]

print "Encrypting {} bytes of plaintext:".format(len(plaintext))
ciphertext = encrypt(pub_key, plaintext)

print "Decrypting {} bytes of base64-encoded ciphertext:".format(
          len(ciphertext))
resulttext = decrypt(priv_key, ciphertext)

assert plaintext == resulttext

print "Decrypted data was identical to the original data!"
