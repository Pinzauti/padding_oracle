"""
Here we simulate the behaviour of the TLS protocol and execute a padding oracle attack.
"""
import random
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
from pad_oracle import PaddingOracle

PLAIN_TEXT = 'hidetestsmessageanotherblockye'.encode('latin-1')

IV = '0123456789012345'.encode('latin-1')
KEY = '0123456789012345'.encode('latin-1')
KEY_MAC = '0123456789012345'.encode('latin-1')

p = PaddingOracle(KEY, IV)


def padding_oracle(cipher_text):
    """
    It first decrypts (using AES and CBC) a given ciphertext and then check if the padding of the
    resulting plaintext is correct or not and then check the if the MAC tag is valid or not.
    A sleep is added in order to keep track of when the scripts check the MAC tag, without it
    would be not possible to keep track of time differences even using nanoseconds.
    :param cipher_text: The ciphertext of which to check the padding and the MAC.
    :return: It returns different messages depending on the outcome of the function; all messages
    are encrypted.
    """
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    decrypt = cipher.decryptor()
    padded_plain_text = decrypt.update(cipher_text) + decrypt.finalize()
    try:
        plain_text_and_mac = p.unpad(padded_plain_text)
    except ValueError:

        return p.encrypt(b'Incorrect padding')
    try:
        time.sleep(1)
        sign = hmac.HMAC(KEY_MAC, hashes.SHA256())
        sign.update(plain_text_and_mac[32:])
        sign.verify(plain_text_and_mac[:32])
    except InvalidSignature:
        return p.encrypt(b'Incorrect signature')
    return b'Encryption successful'


def retrieve_last_block():
    """
    At the beginning the tag of the plaintext is computed and then the plaintext and the MAC tag
    are encrypted (MAC-then-encrypt).
    The rest of the function is very similar to the one in the simple version, there is however a
    major difference:
    the correct letter is not chosen based on the boolean response of the padding_oracle function,
    instead all the times necessaries to perform the padding_oracle function are stored in an
    array, and then the correct letter is chosen based on the maximum time that was necessary
    to execute the function, that is because it means that the MAC check was executed (which
    requires more time) and therefore the padding was correct (there is no MAC check if the
    padding is not correct).
    :return: None.
    """
    sign = hmac.HMAC(KEY_MAC, hashes.SHA256())
    sign.update(PLAIN_TEXT)
    to_be_padded = sign.finalize() + PLAIN_TEXT
    cipher_text = p.encrypt(to_be_padded)
    intermediate = [0] * 16
    solution = [0] * 16
    j = 15
    while j >= 0:
        ran = ''.encode('latin-1')
        for _ in range(j):
            ran = ran + bytes(chr(random.randint(0, 255)), encoding='latin-1')
        cipher_correct_padding = ''.encode('latin-1')
        for k in range(1, 16 - j):
            character_correct_padding = intermediate[j + k] ^ (16 - j)
            cipher_correct_padding = cipher_correct_padding + bytes(chr(character_correct_padding),
                                                                    encoding='latin-1')
        guess = {}
        guess.clear()
        length_time = [0] * 256
        for i in range(256):
            guess[i] = ran + bytes(chr(i), encoding='latin-1') + \
                  cipher_correct_padding + cipher_text[48:]
            chronometer = time.perf_counter_ns()
            padding_oracle(guess[i])
            length_time[i] = time.perf_counter_ns() - chronometer
        intermediate[j] = guess[length_time.index(max(length_time))][j] ^ (16 - j)
        solution[j] = intermediate[j] ^ cipher_text[32 + j]
        j = j - 1

    if p.pad(PLAIN_TEXT)[16:] == bytes(solution):
        print(f'Success, the last block of the ciphertext {cipher_text.hex()} was correctly '
              f'retrieved and it is, with padding: {bytes(solution)}. The original '
              f'plaintext was {PLAIN_TEXT}.')


retrieve_last_block()
