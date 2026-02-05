# Encrypted Message Steganography Tool (Python)

## Description

This project demonstrates a simple combination of cryptography and steganography
to protect sensitive text messages.

The tool encrypts text using AES (CBC mode) and hides the encrypted data
inside a JPEG image. The encrypted message can later be extracted
and decrypted using the correct key.

⚠️ This project is intended for educational and demonstration purposes.

## Features

- AES encryption (CBC mode)
- Random key generation
- Hiding encrypted data inside JPEG images
- Extraction and decryption of hidden messages
- Simple CLI interface

## Technologies Used

- Python
- PyCryptodome (AES encryption)
- Basic file-based steganography

## How It Works

1. Plaintext is encrypted using AES-CBC with a random key.
2. The encrypted data is appended after the JPEG end-of-file marker.
3. The modified image looks unchanged but contains hidden data.
4. The encrypted data can be extracted and decrypted using the same key.

## Usage

### Encrypt and hide message
```bash
python crypto_stego.py
```

## Security Notes

- AES-CBC is used for encryption.
- No authentication (HMAC) is implemented.
- Steganography method is simple and detectable by forensic tools.
- Not intended for production or real-world secure communication.
