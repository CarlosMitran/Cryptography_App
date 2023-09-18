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
    user = use.get()
    print(user)
    password = passd.get()
    print(password)
    create_dict(user, password)


use = ttk.Entry(root, font=('Century 12'), width=40)
use.pack(pady= 30)
passd = ttk.Entry(root, font=('Century 12'), width=40)
passd.pack(pady= 30)

button = ttk.Button(root, text="Enter", command=get_values)
button.pack()
root.mainloop()


