import os 
import sys
import re
from passlib.hash import sha512_crypt

SHADOW_FILE = './app/shadow'
PASSWD_FILE = './app/passwd'

class User:
    def __init__(self, username, password, salt):


        self.username = username
        self.password = password
        self.salt = salt
        self.hashed_password = sha512_crypt.hash(password, salt_size=8, salt=salt, rounds=5000)

        # Add thce user to the OS
        self.update_passwd_file()
        self.update_shadow_file()

    def get_hashed_password(self):
        return self.hashed_password

    def set_hashed_password(self, password, salt):
        self.hashed_password = sha512_crypt.hash(password, salt_size=8, salt=salt, rounds=5000)

    def get_username(self):
        return self.username

    def get_password(self):
        return self.password

    def set_password(self, new_password):
        self.password = new_password

    def get_salt(self):
        return self.salt

    def set_salt(self, new_salt):
        self.salt = new_salt

    @staticmethod
    def user_exists(username):
        with open(SHADOW_FILE, 'r') as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        with open(PASSWD_FILE, 'r') as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        return False

    def update_passwd_file(self):
        count = 1000

        with open(PASSWD_FILE, 'r') as f:
            for line in f:
                temp1 = line.split(':')
                while count <= int(temp1[3]) < 65534:
                    count = int(temp1[3]) + 1
        count = str(count)

        passwd_line = f"{self.username}:x:{count}:{count}:,,,:/home/{self.username}:/bin/bash"

        with open(PASSWD_FILE, 'a+') as passwd_file:
            passwd_file.write(passwd_line + '\n')

    def update_shadow_file(self):
        shadow_line = f"{self.username}:{self.hashed_password}:17710:0:99999:7:::"
        with open(SHADOW_FILE, 'a+') as shadow_file:
            shadow_file.write(shadow_line + '\n')

    def __str__(self):
        return (f"Username:\t{self.username}\nPassword:\t{self.password}\nSalt:\t\t{self.salt}\n"
                f"Hash:\t\t{self.hashed_password}")
    def authenticate(self):
        """Authenticate the user."""
        with open('./app/shadow', 'r') as fp:
            for line in fp:
                temp = line.split(':')
                if temp[0] == self.username:
                    salt_and_pass = temp[1].split('$')
                    salt = salt_and_pass[2]
                    # Calculate hash using the retrieved salt and the password
                    calculated_hash = sha512_crypt.hash(self.password, salt_size=8, salt=salt, rounds=5000)
                    return calculated_hash == temp[1]
        return False
    
    def update_shadow_hash(self, new_password, new_salt=None):
        with open(SHADOW_FILE, 'r') as f:
            lines = f.readlines()
        with open(SHADOW_FILE, 'w') as f:
            for line in lines:
                if line.startswith(self.username + ":"):
                    temp = line.split(':')
                    salt_and_pass = temp[1].split('$')
                    salt = salt_and_pass[2]
                    if new_salt is None:
                        new_salt = salt
                    new_hash = sha512_crypt.hash(new_password, salt_size=8, salt=new_salt, rounds=5000)
                    temp[1] = new_hash
                    f.write(':'.join(temp))
                else:
                    f.write(line)
    
    def remove_user(self):
        for filepath in [SHADOW_FILE, PASSWD_FILE]:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            with open(filepath, 'w') as f:
                for line in lines:
                    if not line.startswith(self.username + ":"):
                        f.write(line)
def create_input():
    username = input("Username: ")
    password = input("Password: ")
    confirm = input("Confirm Password: ")
    salt = input("Salt: ")
    if not re.match(r"^[a-z0-9]{8}$", salt):
        print("Invalid salt. Please enter exactly 8 lowercase letters and digits.")
        sys.exit()
    token = input("Initial Token: ")
    return username, password, confirm, salt, token

def get_login():
    username = input("Username: ")
    password = input("Password: ")
    current_token = input("Current Token: ")
    next_token = input("Next Token: ")
    return username, password, current_token, next_token

def update_password():
    username = input("Username: ")
    password = input("Password: ")
    new_password = input("New Password: ")
    confirm_new_password = input("Confirm New Password: ")
    new_salt = input("New Salt: ")
    if not re.match(r"^[a-z0-9]{8}$", new_salt):
        print("Invalid salt. Please enter exactly 8 lowercase letters and digits.")
        sys.exit()
    
    current_token = input("Current Token: ")
    next_token = input("Next Token: ")
    return username, password, new_password, confirm_new_password, new_salt, current_token, next_token

def delete_user():
    username = input("Username: ")
    password = input("Password: ")
    current_token = input("Current Token: ")
    return username, password, current_token

def main():
    while True:
        print("\nSelect an action:")
        print("1) Create a user")
        print("2) Login")
        print("3) Update password")
        print("4) Delete user account")

        choice = input("Choice: ")

        if choice == "1":
            username, password, confirm, salt, token = create_input()
            if password != confirm:
                print("FAILURE: passwords do not match")
                continue
            if User.user_exists(username):
                print(f"FAILURE: user {username} already exists")
                continue
            User(username, password + token, salt)
            print(f"SUCCESS: {username} created")

        elif choice == "2":
            username, password, current_token, next_token = get_login()
            if not User.user_exists(username):
                print(f"FAILURE: user {username} does not exist")
                continue
            user = User.__new__(User)
            user.username = username
            user.password = password + current_token
            if not user.authenticate():
                print("FAILURE: either passwd or token incorrect")
                continue
            user.update_shadow_hash(password + next_token)
            print("SUCCESS: Login Successful")

        elif choice == "3":
            username, password, new_password, confirm_new_pasword, new_salt, current_token, next_token = update_password()
            if new_password != confirm_new_pasword:
                print("FAILURE: passwords do not match")
                continue
            if not User.user_exists(username):
                print(f"FAILURE: user {username} does not exist")
                continue
            user = User.__new__(User)
            user.username = username
            user.password = password + current_token
            if not user.authenticate():
                print("FAILURE: either passwd or token incorrect")
                continue
            user.update_shadow_hash(new_password + next_token, new_salt)
            print(f"SUCCESS: user {username} updated")

        elif choice == "4":
            username, password, current_token = delete_user()
            if not User.user_exists(username):
                print(f"FAILURE: user {username} does not exist")
                continue
            user = User.__new__(User)
            user.username = username
            user.password = password + current_token
            if not user.authenticate():
                print("FAILURE: either passwd or token incorrect")
                continue
            user.remove_user()
            print(f"SUCCESS: user {username} deleted")
        else: 
            print("Not a valid input")


if __name__ == '__main__':
    main()