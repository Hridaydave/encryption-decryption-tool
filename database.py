import sqlite3
from cryptography.fernet import Fernet

# Connect to SQLite database
conn = sqlite3.connect('encrypted_messages.db')
cursor = conn.cursor()

# Create table to store encrypted messages and keys
cursor.execute('''CREATE TABLE IF NOT EXISTS messages
                  (id INTEGER PRIMARY KEY,
                   encrypted_message TEXT,
                   encryption_key TEXT)''')
conn.commit()

def generate_key():
    """Generates a random key for encryption/decryption."""
    key = Fernet.generate_key()
    return key.decode()

def encrypt_message(message, key):
    """Encrypts a message using the provided key."""
    try:
        fernet = Fernet(key.encode())
        encrypted_message = fernet.encrypt(message.encode()).decode()
        return encrypted_message
    except Exception as e:
        print("Encryption error:", e)
        return None

def decrypt_message(encrypted_message, key):
    """Decrypts an encrypted message using the provided key."""
    try:
        fernet = Fernet(key.encode())
        decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()
        return decrypted_message
    except Exception as e:
        print("Decryption error:", e)
        return None

def save_to_database(encrypted_message, key):
    """Saves encrypted message and key to the database."""
    cursor.execute("INSERT INTO messages (encrypted_message, encryption_key) VALUES (?, ?)", (encrypted_message, key))
    conn.commit()

def retrieve_latest_message():
    """Retrieves the latest encrypted message and its key from the database."""
    cursor.execute("SELECT encrypted_message, encryption_key FROM messages ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if row:
        return row[0], row[1]
    else:
        return None, None

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

        if mode.lower() == 'e':
            # Generate a new key for encryption
            key = generate_key()
            print("Your encryption key:", key)
            message = input("Enter your message: ")
            encrypted_message = encrypt_message(message, key)
            if encrypted_message:
                print("Encrypted message:", encrypted_message)
                # Save encrypted message and key to the database
                save_to_database(encrypted_message, key)
        else:
            # Retrieve the latest encrypted message and its key from the database
            encrypted_message, key = retrieve_latest_message()
            if not key:
                print("No encrypted message found in the database.")
                continue
            encrypted_message_input = input("Enter the encrypted message: ")
            if encrypted_message_input != encrypted_message:
                print("The entered encrypted message does not match the latest encrypted message.")
                continue
            decryption_key_input = input("Enter the encryption/decryption key: ")
            if decryption_key_input != key:
                print("Incorrect key entered.")
                continue
            decrypted_message = decrypt_message(encrypted_message, key)
            if decrypted_message:
                print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()

# Close the database connection
conn.close()
