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


def decrypt_cfb(key, iv, ciphertext):
    aes_cfb = AES.new(key, AES.MODE_CFB, iv)
    return aes_cfb.decrypt(ciphertext)


def decrypt_cbc(key, iv, ciphertext):
    aes_cbc = AES.new(key, AES.MODE_CBC, iv)
    return aes_cbc.decrypt(ciphertext)


def decrypt_cbc_cts(key, iv, ciphertext):
    cipher = AES.new(key, (AES.MODE_CBC), iv=iv)
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    block_size = cipher.block_size
    length = len(ciphertext)
    if length > block_size:
        final_block_size = (length - 1) % block_size + 1
        sec_final_block = cipher_ecb.decrypt(
            ciphertext[-final_block_size - block_size : -final_block_size]
        )
        if length > 0:
            sec_final_block = (
                strxor.strxor(
                    sec_final_block[:final_block_size], ciphertext[-final_block_size:]
                )
                + sec_final_block[final_block_size:]
            )
        final_block = cipher_ecb.decrypt(
            ciphertext[-final_block_size:] + sec_final_block[final_block_size:]
        )
        if length - final_block_size - block_size == 0:
            return strxor.strxor(final_block, iv) + sec_final_block[:final_block_size]
        final_two_blocks = (
            strxor.strxor(
                final_block,
                ciphertext[
                    -final_block_size - 2 * block_size : -final_block_size - block_size
                ],
            )
            + sec_final_block[:final_block_size]
        )
        return (
            cipher.decrypt(ciphertext[: -final_block_size - block_size])
            + final_two_blocks
        )
    else:
        return cipher.decrypt(ciphertext)


def decrypt_file_from_bytes(content, key, initiv):
    content_len = len(content)
    p = 0
    decrypted = []
    ivs = generate_ivs(key, initiv)
    while p < content_len - 4096:
        segment = content[p : p + 4096]
        p = p + 4096
        decrypted.append(decrypt_cbc(key, next(ivs), segment))

    remaining = content_len - p
    final_segment = content[p : p + remaining]
    final_iv = next(ivs)
    if remaining < 17:
        decrypted.append(decrypt_cfb(key, final_iv, final_segment))
    else:
        if remaining % 16 == 0:
            decrypted.append(decrypt_cbc(key, final_iv, final_segment))
        else:
            decrypted.append(decrypt_cbc_cts(key, final_iv, final_segment))

    return b"".join(decrypted)
