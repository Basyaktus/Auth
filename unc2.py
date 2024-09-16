import hashlib
import os
from tkinter import *
from tkinter import ttk
from tkinter import messagebox

def create_password(username, password):
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, hashed_password

def check_password(stored_salt, stored_hash, password):
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), stored_salt, 100000)
    return hashed_password == stored_hash

def create_password_gui():
    username = username_entry.get()
    password = password_entry.get()
    if not username:
        messagebox.showerror("Error", "Username field cannot be empty.")
        return
    if not password:
        messagebox.showerror("Error", "Password field cannot be empty.")
        return
    salt, hashed_password = create_password(username, password)
    with open("password_data.txt", "wb") as f:
        f.write(username.encode() + b':' + salt + b':' + hashed_password)
    messagebox.showinfo("Success", "Password created and stored securely.")

def check_password_gui():
    username = username_entry.get()
    password = password_entry.get()
    if not username:
        messagebox.showerror("Error", "Username field cannot be empty.")
        return
    if not password:
        messagebox.showerror("Error", "Password field cannot be empty.")
        return
    print(f"Checking password for username: {username}")
    try:
        with open("password_data.txt", "rb") as f:
            stored_data = f.read().split(b':')
            stored_username = stored_data[0]
            stored_salt = stored_data[1]
            stored_hash = stored_data[2]
        print(f"Stored username: {stored_username.decode()}")
        if stored_username.decode() == username:
            print("Username matches")
            if check_password(stored_salt, stored_hash, password):
                print("Password matches")
                messagebox.showinfo("Success", "Password is correct.")
            else:
                print("Password does not match")
                messagebox.showerror("Error", "Username or password is incorrect.")
        else:
            print("Username does not match")
            messagebox.showerror("Error", "Username or password is incorrect.")
    except FileNotFoundError:
        print("Password data file not found")
        messagebox.showerror("Error", "No stored password found. Please create a password first.")
    except Exception as e:
        print(f"An error occurred: {e}")
        messagebox.showerror("Error", "An unexpected error occurred.")

root = Tk()
root.title("Password")

main_label = Label(root, text="Authentication", font=("Arial", 15))
main_label.pack()

username_label = Label(root, text="Username", font=("Arial", 10), pady=10)
username_label.pack()

username_entry = Entry(root, width=30)
username_entry.pack()

password_label = Label(root, text="Password", font=("Arial", 10), pady=10)
password_label.pack()

password_entry = Entry(root, width=30, show="*")
password_entry.pack()

btn_create = Button(root, text="Sign in", width=15, command=create_password_gui)
btn_create.pack(pady=10)

btn_check = Button(root, text="Log in", width=15, command=check_password_gui)
btn_check.pack(pady=10)

root.mainloop()