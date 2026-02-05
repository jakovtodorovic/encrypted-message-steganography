import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt_text(plaintext: str, key_hex: str) -> bytes:
    """
    Encrypt plaintext using AES-CBC.
    Returns IV + ciphertext.
    """
    key = bytes.fromhex(key_hex)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    return iv + ciphertext


def decrypt_text(ciphertext: bytes, key_hex: str) -> str:
    """
    Decrypt AES-CBC encrypted data.
    """
    key = bytes.fromhex(key_hex)
    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)

    return plaintext.decode()


def hide_data_in_image(image_file: str, hidden_data: bytes, output_image: str):
    """
    Hide encrypted data inside a JPEG image
    by appending it after the EOF marker.
    """
    with open(image_file, "rb") as img:
        image_data = img.read()

    combined_data = image_data + b"\xff\xd9" + hidden_data

    with open(output_image, "wb") as out:
        out.write(combined_data)


def extract_data_from_image(image_file: str) -> bytes | None:
    """
    Extract hidden data from a JPEG image.
    """
    with open(image_file, "rb") as img:
        image_data = img.read()

    marker_index = image_data.rfind(b"\xff\xd9")
    if marker_index != -1:
        return image_data[marker_index + 2:]

    return None


def main():
    while True:
        print("\nSelect an option:")
        print("1. Encrypt and hide text in image")
        print("2. Extract and decrypt text from image")
        print("3. Exit")

        choice = input("Enter option number: ")

        if choice == "1":
            text_file = input("Enter text file name (e.g. message.txt): ")
            image_file = input("Enter image file name (e.g. image.jpg): ")
            output_image = input("Enter output image name: ")

            with open(text_file, "r") as f:
                plaintext = f.read()

            key_hex = os.urandom(16).hex()
            print(f"\nEncryption key (SAVE THIS): {key_hex}")

            encrypted_data = encrypt_text(plaintext, key_hex)
            hide_data_in_image(image_file, encrypted_data, output_image)

            print(f"Encrypted data successfully hidden in '{output_image}'.")

        elif choice == "2":
            image_file = input("Enter image file name with hidden data: ")
            key_hex = input("Enter encryption key (hex): ")

            encrypted_data = extract_data_from_image(image_file)

            if encrypted_data:
                try:
                    decrypted_text = decrypt_text(encrypted_data, key_hex)
                    print("\nDecrypted message:")
                    print(decrypted_text)

                    output_file = input("Enter output text file name: ")
                    with open(output_file, "w") as out:
                        out.write(decrypted_text)

                    print(f"Message saved to '{output_file}'.")

                except ValueError:
                    print("Error: Invalid key or corrupted data.")
            else:
                print("No hidden data found.")

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()

