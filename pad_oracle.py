"""
It contains the encryption and decryption machinery.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class PaddingOracle:
    """
    Contains methods for padding, unpadding, encrypting and decrypting a given text/ciphertext.
    Key and IV (aka initial value) are the values necessaries to encrypt and decrypt.
    They are encoded to bytes using latin-1.
    """
    key = '0'.encode('latin-1')
    i_v = '0'.encode('latin-1')

    def __init__(self, k, i_v):
        self.key = k
        self.i_v = i_v

    @staticmethod
    def pad(plain_text):
        """
        It adds a padding to a given plaintext, using PKCS7.
        The block size is the AES one (i.e. 128 bit)
        :param plain_text: The plaintext to be padded.
        :return: The initial plaintext, padded.
        """
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        plain_text = padder.update(plain_text) + padder.finalize()
        return plain_text

    @staticmethod
    def unpad(plain_text):
        """
        It removes padding from a given plaintext, which was padded using PKCS7.
        The block size is the AES one (i.e. 128 bit)
        :param plain_text: The plaintext to be unpadded.
        :return: The initial plaintext, unpadded.
        """
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plain_text = unpadder.update(plain_text) + unpadder.finalize()
        return plain_text

    def encrypt(self, msg):
        """
        It pads and then encrypt a given message, using AES and CBC.
        :param msg: The message to encrypt.
        :return: The encrypted message.
        """
        pmsg = self.pad(msg)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.i_v))
        encrypt = cipher.encryptor()
        cipher_text = encrypt.update(pmsg) + encrypt.finalize()
        return cipher_text

    def decrypt(self, cipher_text):
        """
        It decrypts and then unpad a given ciphertext, using AES and CBC.
        :param cipher_text: The ciphertext to decrypt.
        :return: It returns the unpadded plaintext.
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.i_v))
        decrypt = cipher.decryptor()
        padded_message = decrypt.update(cipher_text) + decrypt.finalize()
        return self.unpad(padded_message)
