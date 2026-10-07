import hashlib
import hmac
import os
import secrets
import refinery
print(refinery.__file__)

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
from refinery.lib.crypto import CBC
from refinery.lib.crypto.aria import ARIA


PQ_METHODS = {
    512: ml_kem_512,
    768: ml_kem_768,
    1024: ml_kem_1024
}


def derive_key(key, length, info):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)


def generate_key(third_method='random', key_size_aes=32, key_size_blocks=20, key_size_third=128, key_size_post_quantum=128, post_quantum_level=768):
    pq = PQ_METHODS[post_quantum_level]
    pq_public_key, pq_secret_key = pq.keygen()

    key = (
        f'{post_quantum_level:04d}'
        + secrets.token_bytes(key_size_aes).hex()
        + secrets.token_bytes(key_size_blocks).hex()
        + secrets.token_bytes(key_size_third).hex()
        + secrets.token_bytes(key_size_post_quantum).hex()
        + pq_public_key.hex()
        + pq_secret_key.hex()
    )

    if third_method == 'random':
        third_method = secrets.choice(['chacha', 'camellia', 'aria', 'sm4'])

    match third_method:
        case 'chacha':
            method = 'сс'
        case 'camellia':
            method = 'с'
        case 'aria':
            method = 'а'
        case 'sm4':
            method = 'ц'

    position = secrets.randbelow(len(key) + 1)

    return key[:position] + method + key[position:]


def generate_key_to_encrypt_key(key_size=32):
    return secrets.token_bytes(key_size)


def encrypt_encryption_key(text, key):
    if isinstance(text, str):
        text = text.encode()

    nonce = os.urandom(12)

    return nonce + AESGCM(key).encrypt(nonce, text, None)


def decrypt_encryption_key(text, key):
    nonce = text[:12]

    return AESGCM(key).decrypt(nonce, text[12:], None).decode()


def parse_key(key, decryption_key=None, key_size_aes=32, key_size_blocks=20, key_size_third=128, key_size_post_quantum=128):
    if decryption_key is not None:
        key = decrypt_encryption_key(key, decryption_key)

    if 'сс' in key:
        method = 'chacha'
        key = key.replace('сс', '', 1)

    elif 'с' in key:
        method = 'camellia'
        key = key.replace('с', '', 1)

    elif 'а' in key:
        method = 'aria'
        key = key.replace('а', '', 1)

    elif 'ц' in key:
        method = 'sm4'
        key = key.replace('ц', '', 1)

    else:
        raise ValueError('Method not found')

    pq_level = int(key[:4])
    key = key[4:]

    aes_end = key_size_aes * 2
    blocks_end = aes_end + key_size_blocks * 2
    third_end = blocks_end + key_size_third * 2
    pq_end = third_end + key_size_post_quantum * 2

    aes_key = bytes.fromhex(key[:aes_end])
    blocks_key = bytes.fromhex(key[aes_end:blocks_end])
    third_key = bytes.fromhex(key[blocks_end:third_end])
    pq_key = bytes.fromhex(key[third_end:pq_end])

    pq = PQ_METHODS[pq_level]

    public_end = pq_end + pq.PUBLIC_KEY_SIZE * 2
    secret_end = public_end + pq.SECRET_KEY_SIZE * 2

    pq_public_key = bytes.fromhex(key[pq_end:public_end])
    pq_secret_key = bytes.fromhex(key[public_end:secret_end])

    return method, aes_key, blocks_key, third_key, pq_key, pq_public_key, pq_secret_key, pq_level


def encrypt_aes(text, key):
    if isinstance(text, str):
        text = text.encode()

    key = derive_key(key, 32, b'aes')
    nonce = os.urandom(12)

    return nonce + AESGCM(key).encrypt(nonce, text, None)


def decrypt_aes(text, key):
    key = derive_key(key, 32, b'aes')

    return AESGCM(key).decrypt(text[:12], text[12:], None)


def block_order(amount, key, salt):
    order = list(range(amount))

    for i in range(amount - 1, 0, -1):
        value = hmac.new(key, salt + i.to_bytes(8, 'big'), hashlib.sha256).digest()
        j = int.from_bytes(value, 'big') % (i + 1)

        order[i], order[j] = order[j], order[i]

    return order


def encrypt_blocks(text, key, block_size=32):
    if isinstance(text, str):
        text = text.encode()

    text = len(text).to_bytes(8, 'big') + text
    text += os.urandom((-len(text)) % block_size)

    blocks = [text[i:i + block_size] for i in range(0, len(text), block_size)]

    salt = os.urandom(16)
    order = block_order(len(blocks), key, salt)

    return block_size.to_bytes(2, 'big') + salt + b''.join(blocks[i] for i in order)


def decrypt_blocks(text, key):
    block_size = int.from_bytes(text[:2], 'big')
    salt = text[2:18]
    text = text[18:]

    blocks = [text[i:i + block_size] for i in range(0, len(text), block_size)]
    order = block_order(len(blocks), key, salt)

    original = [None] * len(blocks)

    for moved, position in enumerate(order):
        original[position] = blocks[moved]

    text = b''.join(original)
    size = int.from_bytes(text[:8], 'big')

    return text[8:8 + size]


def encrypt_cbc(text, key, algorithm, method):
    iv = os.urandom(16)

    if method == 'sm4':
        material = derive_key(key, 48, b'sm4')
        encryption_key = material[:16]
        mac_key = material[16:]

    else:
        material = derive_key(key, 64, method.encode())
        encryption_key = material[:32]
        mac_key = material[32:]

    padder = padding.PKCS7(128).padder()
    text = padder.update(text) + padder.finalize()

    cipher = Cipher(algorithm(encryption_key), modes.CBC(iv)).encryptor()
    encrypted = cipher.update(text) + cipher.finalize()

    tag = hmac.new(mac_key, iv + encrypted, hashlib.sha256).digest()

    return iv + tag + encrypted


def decrypt_cbc(text, key, algorithm, method):
    iv = text[:16]
    tag = text[16:48]
    encrypted = text[48:]

    if method == 'sm4':
        material = derive_key(key, 48, b'sm4')
        encryption_key = material[:16]
        mac_key = material[16:]

    else:
        material = derive_key(key, 64, method.encode())
        encryption_key = material[:32]
        mac_key = material[32:]

    if not hmac.compare_digest(tag, hmac.new(mac_key, iv + encrypted, hashlib.sha256).digest()):
        raise ValueError('Authentication failed')

    cipher = Cipher(algorithm(encryption_key), modes.CBC(iv)).decryptor()
    text = cipher.update(encrypted) + cipher.finalize()

    unpadder = padding.PKCS7(128).unpadder()

    return unpadder.update(text) + unpadder.finalize()


def encrypt_aria(text, key):
    iv = os.urandom(16)

    material = derive_key(key, 64, b'aria')
    encryption_key = material[:32]
    mac_key = material[32:]

    padder = padding.PKCS7(128).padder()
    text = padder.update(text) + padder.finalize()

    encrypted = bytes(ARIA(encryption_key, CBC(iv)).encrypt(text))
    tag = hmac.new(mac_key, iv + encrypted, hashlib.sha256).digest()

    return iv + tag + encrypted


def decrypt_aria(text, key):
    iv = text[:16]
    tag = text[16:48]
    encrypted = text[48:]

    material = derive_key(key, 64, b'aria')
    encryption_key = material[:32]
    mac_key = material[32:]

    if not hmac.compare_digest(tag, hmac.new(mac_key, iv + encrypted, hashlib.sha256).digest()):
        raise ValueError('Authentication failed')

    text = bytes(ARIA(encryption_key, CBC(iv)).decrypt(encrypted))

    unpadder = padding.PKCS7(128).unpadder()

    return unpadder.update(text) + unpadder.finalize()


def encrypt_third(text, key, method):
    if method == 'chacha':
        key = derive_key(key, 32, b'chacha')
        nonce = os.urandom(12)

        return nonce + ChaCha20Poly1305(key).encrypt(nonce, text, None)

    if method == 'camellia':
        return encrypt_cbc(text, key, algorithms.Camellia, method)

    if method == 'aria':
        return encrypt_aria(text, key)

    if method == 'sm4':
        return encrypt_cbc(text, key, algorithms.SM4, method)


def decrypt_third(text, key, method):
    if method == 'chacha':
        key = derive_key(key, 32, b'chacha')

        return ChaCha20Poly1305(key).decrypt(text[:12], text[12:], None)

    if method == 'camellia':
        return decrypt_cbc(text, key, algorithms.Camellia, method)

    if method == 'aria':
        return decrypt_aria(text, key)

    if method == 'sm4':
        return decrypt_cbc(text, key, algorithms.SM4, method)


def encrypt_quantum(text, public_key, mixing_key, level):
    pq = PQ_METHODS[level]

    kem_text, shared_secret = pq.encaps(public_key)

    key = derive_key(shared_secret + mixing_key, 32, b'post-quantum')
    nonce = os.urandom(12)

    header = b'PQ1' + level.to_bytes(2, 'big') + len(kem_text).to_bytes(2, 'big')
    encrypted = AESGCM(key).encrypt(nonce, text, header)

    return header + kem_text + nonce + encrypted


def decrypt_quantum(text, secret_key, mixing_key):
    level = int.from_bytes(text[3:5], 'big')
    kem_size = int.from_bytes(text[5:7], 'big')

    kem_text = text[7:7 + kem_size]
    nonce = text[7 + kem_size:19 + kem_size]
    encrypted = text[19 + kem_size:]

    shared_secret = PQ_METHODS[level].decaps(secret_key, kem_text)
    key = derive_key(shared_secret + mixing_key, 32, b'post-quantum')

    return AESGCM(key).decrypt(nonce, encrypted, text[:7])


def encrypt(text, key, key_size_aes=32, key_size_blocks=20, key_size_third=128, key_size_post_quantum=128, block_size=32):
    method, aes_key, blocks_key, third_key, pq_key, pq_public_key, _, pq_level = parse_key(key, None, key_size_aes, key_size_blocks, key_size_third, key_size_post_quantum)

    text = encrypt_aes(text, aes_key)
    text = encrypt_blocks(text, blocks_key, block_size)
    text = encrypt_third(text, third_key, method)
    text = encrypt_quantum(text, pq_public_key, pq_key, pq_level)

    return text


def decrypt(text, encrypted_key, decryption_key, key_size_aes=32, key_size_blocks=20, key_size_third=128, key_size_post_quantum=128, decode=False):
    method, aes_key, blocks_key, third_key, pq_key, _, pq_secret_key, _ = parse_key(encrypted_key, decryption_key, key_size_aes, key_size_blocks, key_size_third, key_size_post_quantum)

    text = decrypt_quantum(text, pq_secret_key, pq_key)
    text = decrypt_third(text, third_key, method)
    text = decrypt_blocks(text, blocks_key)
    text = decrypt_aes(text, aes_key)

    return text.decode() if decode else text


if __name__ == '__main__':
    key_size_aes = 32
    key_size_blocks = 20
    key_size_third = 128
    key_size_post_quantum = 128

    encryption_key = generate_key(
        'random',
        key_size_aes,
        key_size_blocks,
        key_size_third,
        key_size_post_quantum,
        768
    )

    decryption_key = generate_key_to_encrypt_key(32)

    encrypted_text = encrypt(
        'say hello to most ineffective encryption :) ',
        encryption_key,
        key_size_aes,
        key_size_blocks,
        key_size_third,
        key_size_post_quantum
    )

    encrypted_encryption_key = encrypt_encryption_key(encryption_key, decryption_key)

    decrypted_text = decrypt(
        encrypted_text,
        encrypted_encryption_key,
        decryption_key,
        key_size_aes,
        key_size_blocks,
        key_size_third,
        key_size_post_quantum,
        True
    )

    print('encrypted:', encrypted_text.hex())
    print(encrypted_encryption_key)
    print('encrypted key:', encrypted_encryption_key.hex())
    print('decrypted:', decrypted_text)