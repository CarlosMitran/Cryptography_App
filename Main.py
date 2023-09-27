from tkinter import *
from tkinter import ttk
import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import re


def write_input(json_file, inputs):
    list1 = open_json(json_file)
    found = find_username(list1, inputs)
    if found:
        print("Welcome!, " + inputs["username"])
        return True
    list1.append(inputs)
    try:
        with open(json_file, "w", encoding="UTF-8", newline="") as file:
            json.dump(list1, file, indent=2)
            print("User " + inputs["username"] + " created")
    except FileNotFoundError as ex:
        raise Exception("Wrong file or file path") from ex


def open_json(json_file):
    try:
        with open(json_file, "r", encoding="UTF-8", newline="") as file:
            data_list = json.load(file)
    except FileNotFoundError:
        data_list = []
    except json.JSONDecodeError as ex:
        raise Exception("JSON Decode Error - Wrong JSON Format") from ex
    return data_list



def find_username(data_list, inputs):
    for item in data_list:

        if item["username"] == inputs["username"]:
            if verify_key(inputs["password"], item["password"], item["salt"]):
                incorrectPasswordLabel = Label(root, text="Incorrect password", font='Century 12', fg="#FF5733")
                incorrectPasswordLabel.pack()
                passwordBox.delete(0, END)
                raise Exception("Incorrect password")
            # print("Welcome!, " + inputs["username"]) lo quito porque sino se imprime 3 veces
            newsalt = os.urandom(16)
            saltascii = encode_to_ascii(newsalt)
            item["salt"] = saltascii
            return True
    return False


def create_dict(user, password, salt):
    user_list = {"username": user, "password": password, "salt": salt}
    print(user_list)
    write_input("test.json", user_list)


root = Tk()
root.geometry("750x500")


def get_values():
    user = userBox.get()
    print(user)
    password = passwordBox.get()
    print(password)
    salt = os.urandom(16)
    password, saltascii = calculate_key(password, salt)
    create_dict(user, password, saltascii)
    if find_username(open_json("test.json"), {"username": user, "password": password, "salt": saltascii}):
        root.geometry("1500x950")
        for widget in root.winfo_children():
            widget.destroy()
        welcomeLabel = Label(root, text="Welcome! " + user, font=('Century 20 bold'))
        welcomeLabel.place(x=25, y=25)

def calculate_key(inputs, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )

    key = kdf.derive(inputs.encode())
    keyascii = encode_to_ascii(key)
    saltascii = encode_to_ascii(salt)

    print(keyascii)
    print(saltascii)
    return keyascii, saltascii

def verify_key(password, key, salt):
    salt = decode_to_bytes(salt)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    key64 = base64.b64encode(key)
    keybytes = base64.b64decode(key64)
    kdf.verify(password.encode(), keybytes)

    return True


def encode_to_ascii(key):
    key64 = base64.b64encode(key)
    keyascii = str(key64.decode("utf-8"))

    return keyascii

def decode_to_bytes(key):
    key64 = key.encode('utf-8')
    bytekey = base64.b64decode(key64)

    return bytekey




space1 = Label(root, text=" ")
space1.pack(pady=10)
title = Label(root, text="Log in:", font=('Century 20 bold'))
title.pack(pady=30)
userLabel = ttk.Label(root, text="Username:", font=('Century 12'))
userLabel.pack()
userBox = ttk.Entry(root, font=('Century 12'), width=40)
userBox.pack()
space2 = Label(root, text=" ")
space2.pack(pady=5)
passwordLabel = ttk.Label(root, text="Password:", font=('Century 12'))
passwordLabel.pack()
passwordBox = ttk.Entry(root, show= '*', font=('Century 12'), width=40)
passwordBox.pack()
loginWarning = Label(root, text="(If user does not exist, it will be created)", font=('Century 12 italic'))
loginWarning.pack(pady=10)

loginButton = ttk.Button(root, text="Log in", command=get_values)
loginButton.pack()
root.mainloop()
