# absolute-cinemencryption

*(like "absolute cinema" + encryption)*

![Absolute Encryption](https://api.memegen.link/images/custom/_/ENCRYPTION.png?background=https%3A%2F%2Fi.imgflip.com%2F9knug9.png&font=impact&color=white%2Cblack&width=828)

So, this is basically a combination of multiple encryption methods in one system.

Firstly, the original text is encrypted using normal AES.

Then, the encrypted data is passed through a moving-blocks algorithm, which rearranges blocks of the ciphertext using a separate randomly generated key.

Next, a third encryption method is chosen randomly using a cryptographically secure random generator. The currently supported methods can include things such as ChaCha, Camellia, ARIA, or SM4.

Finally, the result goes through an additional post-quantum/hybrid encryption layer.

The idea is not to rely on one single cipher, but to pass the data through several independent stages, with separate key material used for each stage.

## Key structure

The main encryption key is formed in several parts.

Firstly, a random AES key is generated.

Then, a smaller random key used by the moving-blocks algorithm is generated and added directly after it.

After that, another random key is generated for the third encryption method.

A separate key is also generated for the post-quantum layer.

All of these pieces are joined together into one large key string.

The third encryption method is represented by a Cyrillic character inserted at a random position inside the key. Since the rest of the key only contains normal hexadecimal/ASCII characters, the Cyrillic marker can later be found, used to determine the encryption method, and removed before the remaining key is split back into its original parts.

So, conceptually, the key looks like:

```text
AES key
+ moving-blocks key
+ third-method key
+ post-quantum key
+ post-quantum key material
```

with one Cyrillic method marker inserted somewhere at a random position.

When the key is parsed, that marker is detected first. The marker determines which third cipher was used, and the remaining string is then split back into the separate keys according to their configured lengths.

## Encryption order

The text is encrypted in this order:

```text
plaintext
    ↓
AES
    ↓
moving blocks
    ↓
randomly selected third cipher
    ↓
post-quantum / hybrid encryption
    ↓
ciphertext
```

Decryption simply performs the same operations in reverse order.

## Protecting the encryption key

The large combined encryption key is not intended to be stored directly.

Instead, it is encrypted separately using AES and another independent key.

This means there are effectively two levels of key material:

```text
data encryption key
    ↓
contains all keys used to encrypt the actual text


key-encryption key
    ↓
used only to encrypt/decrypt the data encryption key
```

During decryption, the user first provides the separate key-encryption key.

That key is used to decrypt the large combined encryption key.

The recovered key is then parsed, the Cyrillic method marker is detected and removed, the individual keys are restored, and those keys are used to decrypt the ciphertext in reverse order.

The general decryption flow is:

```text
encrypted combined key
    ↓
AES decrypt using key-encryption key
    ↓
combined key with Cyrillic marker
    ↓
detect method
    ↓
remove marker
    ↓
split into individual keys
    ↓
decrypt ciphertext in reverse order
    ↓
plaintext
```


This is more experimental(or joke), but i guess this algorithm is super effective if we want to secure the system for 3 trillion years instead of just 1 trillion
