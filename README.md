# Python-2x2HillCipher
A Python API to facilitate the encoding and decoding of 2x2 Hill Cipher.

# Instructions:
import pyhill

.key = [a,b,c,d]

.inversekey(self, key(array)) will return the inverse of the inputted key, will return "ERR" if the key is not inversible.

.encrypt(self, plaintext(str)) will return the encrypted data using a set key.

.decrypt(self, ciphertext(str)) will return the decrypted data using a set key. (inversed)
