from tkinter import *
from tkinter import ttk
import json
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
            if item["password"] != inputs["password"]:
                raise Exception("Username already in use")
            return True
    return False

def create_dict(user,password):
    user_list = {"username": user, "password": password}
    write_input("test.json", user_list)

root = Tk()
root.geometry("750x500")

def get_values():
    user = userBox.get()
    print(user)
    password = passwordBox.get()
    print(password)
    create_dict(user, password)

space1 = Label(root, text=" ")
space1.pack(pady = 10)
title = Label(root, text="Log in:", font=('Century 20 bold'))
title.pack(pady = 30)
userText = ttk.Label(root, text="Username:", font=('Century 12'))
userText.pack()
userBox = ttk.Entry(root, font=('Century 12'), width=40)
userBox.pack()
space2 = Label(root, text=" ")
space2.pack(pady = 5)
passwordText = ttk.Label(root, text="Password:", font=('Century 12'))
passwordText.pack()
passwordBox = ttk.Entry(root, font=('Century 12'), width=40)
passwordBox.pack()
loginwarning = Label(root, text="(If user does not exist, it will be created)", font=('Century 12 italic'))
loginwarning.pack(pady = 10)

loginButton = ttk.Button(root, text="Log in", command=get_values)
loginButton.pack()
root.mainloop()


