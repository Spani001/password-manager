import hashlib
import json
import os
from cryptography.fernet import Fernet
import getpass


class PersonalPasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.key = self._derive_key(master_password)
        self.cipher = Fernet(self.key)
        self.vault_file = "password_vault.json"
        self.passwords = self._load_vault()

    def _derive_key(self, password):
        """Derive encryption key from master password"""
        password_bytes = password.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', password_bytes, b'salt_', 100000)
        return Fernet.generate_key()

    def _load_vault(self):
        """Load encrypted passwords from file"""
        if os.path.exists(self.vault_file):
            try:
                with open(self.vault_file, 'r') as f:
                    encrypted_data = json.load(f)
                    decrypted_data = {}
                    for service, encrypted_password in encrypted_data.items():
                        decrypted_data[service] = self.cipher.decrypt(
                            encrypted_password.encode()
                        ).decode()
                    return decrypted_data
            except:
                return {}
        return {}

    def _save_vault(self):
        """Save encrypted passwords to file"""
        encrypted_data = {}
        for service, password in self.passwords.items():
            encrypted_data[service] = self.cipher.encrypt(
                password.encode()
            ).decode()

        with open(self.vault_file, 'w') as f:
            json.dump(encrypted_data, f, indent=2)

    def add_password(self, service, password):
        """Add a new password entry"""
        self.passwords[service] = password
        self._save_vault()
        print(f"Password for {service} added successfully!")

    def get_password(self, service):
        """Retrieve a password for a service"""
        if service in self.passwords:
            return self.passwords[service]
        else:
            print(f"No password found for {service}")
            return None

    def list_services(self):
        """List all stored services"""
        if self.passwords:
            print("Stored services:")
            for service in self.passwords.keys():
                print(f"- {service}")
        else:
            print("No passwords stored yet.")

    def delete_password(self, service):
        """Delete a password entry"""
        if service in self.passwords:
            del self.passwords[service]
            self._save_vault()
            print(f"Password for {service} deleted successfully!")
        else:
            print(f"No password found for {service}")


def main():
    print("=== Personal Password Manager ===")
    master_password = getpass.getpass("Enter master password: ")

    pm = PersonalPasswordManager(master_password)

    while True:
        print("\nOptions:")
        print("1. Add password")
        print("2. Get password")
        print("3. List services")
        print("4. Delete password")
        print("5. Exit")

        choice = input("Choose an option (1-5): ")

        if choice == '1':
            service = input("Enter service name: ")
            password = getpass.getpass("Enter password: ")
            pm.add_password(service, password)

        elif choice == '2':
            service = input("Enter service name: ")
            password = pm.get_password(service)
            if password:
                print(f"Password for {service}: {password}")

        elif choice == '3':
            pm.list_services()

        elif choice == '4':
            service = input("Enter service name to delete: ")
            pm.delete_password(service)

        elif choice == '5':
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
