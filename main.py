from secure_messaging import SecureMessagingApp
import getpass
import os

class MessengerCLI:
    def __init__(self):
        self.app = SecureMessagingApp()
        self.current_user = None

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def main_menu(self):
        while True:
            self.clear_screen()
            print("\n=== Secure Messenger ===")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == '1':
                self.register()
            elif choice == '2':
                self.login()
            elif choice == '3':
                print("\nGoodbye!")
                break
            else:
                input("Invalid choice. Press Enter to continue...")

    def register(self):
        self.clear_screen()
        print("\n=== Register New User ===")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")

        if password != confirm_password:
            input("Passwords don't match. Press Enter to continue...")
            return

        if self.app.register_user(username, password):
            input("Registration successful! Press Enter to continue...")
        else:
            input("Username already exists. Press Enter to continue...")

    def login(self):
        self.clear_screen()
        print("\n=== Login ===")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")

        if self.app.authenticate_user(username, password):
            self.current_user = username
            self.user_menu()
        else:
            input("Invalid credentials. Press Enter to continue...")

    def user_menu(self):
        while True:
            self.clear_screen()
            print(f"\n=== Welcome {self.current_user} ===")
            print("1. Send Message")
            print("2. View Messages")
            print("3. Logout")
            
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == '1':
                self.send_message()
            elif choice == '2':
                self.view_messages()
            elif choice == '3':
                self.current_user = None
                break
            else:
                input("Invalid choice. Press Enter to continue...")

    def send_message(self):
        self.clear_screen()
        print("\n=== Send Message ===")
        recipient = input("Enter recipient username: ")
        message = input("Enter your message: ")

        if self.app.send_message(self.current_user, recipient, message):
            input("Message sent successfully! Press Enter to continue...")
        else:
            input("Failed to send message. Press Enter to continue...")

    def view_messages(self):
        self.clear_screen()
        print("\n=== Your Messages ===")
        messages = self.app.get_messages(self.current_user)
        
        if not messages:
            input("No messages found. Press Enter to continue...")
            return

        for sender, content, timestamp in messages:
            print(f"\nFrom: {sender}")
            print(f"Time: {timestamp}")
            print(f"Message: {content}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    cli = MessengerCLI()
    cli.main_menu()