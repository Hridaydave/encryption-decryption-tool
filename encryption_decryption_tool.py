from cryptography.fernet import Fernet

def generate_key():
    """Generates a random key for encryption/decryption."""
    key = Fernet.generate_key()
    return key.decode()  # Convert key to a string

def encrypt_message(message, key):
    """Encrypts a message using the provided key."""
    try:
        fernet = Fernet(key.encode())
        encrypted_message = fernet.encrypt(message.encode()).decode()
        return encrypted_message
    except Exception as e:
        print("Encryption error:", e)
        return None  # Indicate encryption failure

def decrypt_message(encrypted_message, key):
    """Decrypts an encrypted message using the provided key."""
    try:
        fernet = Fernet(key.encode())
        decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()
        return decrypted_message
    except Exception as e:
        print("Decryption error:", e)
        return None  # Indicate decryption failure

def main():
    """Handles user interaction for encryption/decryption."""
    print("Welcome to the Encryption/Decryption System!")

    while True:
        mode = input("Enter 'e' to encrypt or 'd' to decrypt (or 'q' to quit): ")
        if mode.lower() == 'q':
            break

        if mode.lower() not in ('e', 'd'):
            print("Invalid option. Please enter 'e', 'd', or 'q'.")
            continue

        # Get user input for message and key (replace with secure key management)
        message = input("Enter your message: ")

        if mode.lower() == 'e':
            key = generate_key()  # Generate a new key for encryption
            print("Your encryption key:", key)
            encrypted_message = encrypt_message(message, key)
            if encrypted_message:
                print("Encrypted message:", encrypted_message)
        else:
            encrypted_message = input("Enter the encrypted message: ")
            key = input("Enter the encryption/decryption key: ")
            decrypted_message = decrypt_message(encrypted_message, key)
            if decrypted_message:
                print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
 # type: ignore