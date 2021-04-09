from Crypto.Cipher import AES
from Crypto.Util import strxor
from Crypto.Util.Padding import pad, unpad
import struct

def generate_ivs(key, initiv):
    current = initiv
    cipher = AES.new(key, AES.MODE_ECB)
    while True:
        current = cipher.encrypt(current)
        yield current


def decrypt_cbc_ecb(key, ciphertext):
    aes_ecb = AES.new(key, AES.MODE_ECB)
    return aes_ecb.decrypt(ciphertext)


def decrypt_cbc_pkcs7(key, iv, ciphertext):
    aes_cbc = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes_cbc.decrypt(ciphertext), aes_cbc.block_size, 'pkcs7')


def encrypt_cbc_pkcs7(key, iv, plaintext):
    aes_cbc = AES.new(key, AES.MODE_CBC, iv)
    return aes_cbc.encrypt(pad(plaintext, aes_cbc.block_size, 'pkcs7'))


def decrypt_cfb(key, iv, ciphertext):
    aes_cfb = AES.new(key, AES.MODE_CFB, iv)
    return aes_cfb.decrypt(ciphertext)


def decrypt_cbc(key, iv, ciphertext):
    aes_cbc = AES.new(key, AES.MODE_CBC, iv)
    return aes_cbc.decrypt(ciphertext)


def encrypt_cbc_ecb(key, plaintext):
    aes_ecb = AES.new(key, AES.MODE_ECB)
    return aes_ecb.encrypt(plaintext)


def encrypt_cbc_cts(key, iv, plaintext):
    cipher = AES.new(key, (AES.MODE_CBC), iv=iv)
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    block_size = cipher.block_size
    length = len(plaintext)
    if length > block_size:
        final_block_size = (length - 1) % block_size + 1
        head_blocks = cipher.encrypt(plaintext[:length - final_block_size])
        final_block = head_blocks[-block_size:]
        second_final_block = cipher_ecb.encrypt(strxor.strxor(final_block[:final_block_size], plaintext[-final_block_size:]) + final_block[final_block_size:])
        return head_blocks[:-block_size] + second_final_block + final_block[:final_block_size]
    return cipher.encrypt(plaintext)


def decrypt_cbc_cts(key, iv, ciphertext):
    cipher = AES.new(key, (AES.MODE_CBC), iv=iv)
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    block_size = cipher.block_size
    length = len(ciphertext)
    if length > block_size:
        final_block_size = (length - 1) % block_size + 1
        sec_final_block = cipher_ecb.decrypt(ciphertext[-final_block_size - block_size:-final_block_size])
        if length > 0:
            sec_final_block = strxor.strxor(sec_final_block[:final_block_size], ciphertext[-final_block_size:]) + sec_final_block[final_block_size:]
        final_block = cipher_ecb.decrypt(ciphertext[-final_block_size:] + sec_final_block[final_block_size:])
        if length - final_block_size - block_size == 0:
            return strxor.strxor(final_block, iv) + sec_final_block[:final_block_size]
        final_two_blocks = strxor.strxor(final_block, ciphertext[-final_block_size - 2 * block_size:-final_block_size - block_size]) + sec_final_block[:final_block_size]
        return cipher.decrypt(ciphertext[:-final_block_size - block_size]) + final_two_blocks
    else:
        return cipher.decrypt(ciphertext)


def get_randbytes_as_bytes(nbytes, rng):
    return (struct.pack)('@' + 'I' * (nbytes >> 2), *[rng.get_random_number() for _ in range(nbytes >> 2)])


def drop_randbytes(nbytes, rng):
    for _ in range(nbytes >> 2):
        rng.get_random_number()


def get_huk_key_iv(n1, n2, svcid=2147483647):
    rng = mt.mersenne_rng(seed=svcid)
    drop_randbytes(n1 * 16 * 4, rng)
    key = get_randbytes_as_bytes(16, rng)
    drop_randbytes(n2 * 16 * 4, rng)
    iv = get_randbytes_as_bytes(16, rng)
    return (key, iv)


def decrypt_file_from_bytes(content, key, initiv):
    content_len = len(content)
    p = 0
    decrypted = []
    ivs = generate_ivs(key, initiv)
    while p < content_len - 4096:
        segment = content[p:p + 4096]
        p = p + 4096
        decrypted.append(decrypt_cbc(key, next(ivs), segment))

    remaining = content_len - p
    final_segment = content[p:p + remaining]
    final_iv = next(ivs)
    if remaining < 17:
        decrypted.append(decrypt_cfb(key, final_iv, final_segment))
    else:
        if remaining % 16 == 0:
            decrypted.append(decrypt_cbc(key, final_iv, final_segment))
        else:
            decrypted.append(decrypt_cbc_cts(key, final_iv, final_segment))

    return b''.join(decrypted)