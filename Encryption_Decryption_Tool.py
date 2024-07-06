def encrypt_file(filename, key):
    try:
        with open(filename, 'rb') as input_file, open(filename + '.encrypted', 'wb') as output_file:
            key_index = 0
            count = 0
            byte = input_file.read(1)

            print("Starting encryption...")

            while byte:
                encrypted_byte = bytes([byte[0] ^ key[key_index % len(key)]])
                output_file.write(encrypted_byte)
                key_index += 1
                count += 1
                byte = input_file.read(1)

            print(f"Encryption complete. {count} bytes processed.")

    except IOError as e:
        print(f"An error occurred: {e}")


def decrypt_file(filename, key):
    try:
        with open(filename + '.encrypted', 'rb') as input_file, open(filename + '.decrypted', 'wb') as output_file:
            key_index = 0
            count = 0
            byte = input_file.read(1)

            print("Starting decryption...")

            while byte:
                decrypted_byte = bytes([byte[0] ^ key[key_index % len(key)]])
                output_file.write(decrypted_byte)
                key_index += 1
                count += 1
                byte = input_file.read(1)

            print(f"Decryption complete. {count} bytes processed.")

    except IOError as e:
        print(f"An error occurred: {e}")


def main():
    filename = input("Enter filename: ")
    key = input("Enter encryption key: ").encode()

    choice = input("Encrypt (e) or Decrypt (d) the file? (e/d): ")

    if choice == 'e':
        encrypt_file(filename, key)
        print("File encrypted successfully.")
    elif choice == 'd':
        decrypt_file(filename, key)
        print("File decrypted successfully.")
    else:
        print("Invalid choice.")
        return 1

    return 0


if __name__ == "__main__":
    main()
