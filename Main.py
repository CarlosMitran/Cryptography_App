from tkinter import *
from tkinter import ttk
import json
import os

import cryptography.exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import re
import time

"""
To do:

-- Cifrado Autenticado
-- Sign out
-- Añadir datos y ver datos 
-- Interfaz gráfica de los datos a mostrar, sign out, boton de ver datos, boton de añadir datos4

"""


def write_input(json_file, inputs):  # create user
    list1 = open_json(json_file)
    list1.append(inputs)
    try:
        with open(json_file, "w", encoding="UTF-8", newline="") as file:
            json.dump(list1, file, indent=2)
    except FileNotFoundError as ex:
        raise Exception("Wrong file or file path") from ex


def write_newsalt(json_file, data_list):
    try:
        with open(json_file, "w", encoding="UTF-8", newline="") as file:
            json.dump(data_list, file, indent=2)
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


def create_user(data_list, inputs):
    for item in data_list:
        if item["username"] == inputs["username"]:
            try:
                verify_key(inputs["password"], item["password"], item["salt"])
                newsalt = os.urandom(16)
                item["password"], item["salt"] = calculate_key(inputs["password"], newsalt)
                write_newsalt("users.json", data_list)
                return True

                # raise Exception("Incorrect password")
            # print("Welcome!, " + inputs["username"]) lo quito porque sino se imprime 3 veces
            except cryptography.exceptions.InvalidKey:
                incorrectPasswordLabel = Label(root, text="Incorrect password", font='Century 12', fg="#FF5733")
                incorrectPasswordLabel.pack()
                passwordBox.delete(0, END)
                return False
    adduser(inputs)


def adduser(data_list):
    newsalt = os.urandom(16)
    key, saltascii = calculate_key(data_list["password"], newsalt)
    create_dict(data_list["username"], key, saltascii)
    read_data(data_list["username"])
    # add_data(userBox.get())
    # showUser({"username": data_list["username"], "password": data_list["password"]})


def create_dict(user, password, salt):
    user_list = {"username": user, "password": password, "salt": salt}
    write_input("users.json", user_list)


root = Tk()
root.geometry("750x500")


def get_values():
    user = userBox.get()
    print(user)
    password = passwordBox.get()
    print(password)
    if create_user(open_json("users.json"), {"username": user, "password": password}):
        print("Logged in user " + user)
        # answer = input("Do you want to write or read? W/R\n")
        for widget in root.winfo_children():
            widget.destroy()
        root.geometry("750x500")
        optionLabel = Label(root, text="Select your option:", font=('Century 20 bold'))
        optionLabel.pack(pady=80)

        option = 0

        def write_clicked(option):
            option += 1
            return option

        def read_clicked(option):
            option += 2
            return option

        writeButton = ttk.Button(root, text="Write data", command=write_clicked(option))
        writeButton.pack()
        readButton = ttk.Button(root, text="Read data", command=read_clicked(option))
        readButton.pack()
        if option == 1:
            print("Enter the following data\n")
            add_data(user)
        if option == 2:
            for item in (open_json("userdata.json")):
                if item["username"] == user:
                    print(item)

        # showUser(inputs={"username": user, "password": password})


def read_data(user):
    item = find_user(open_json("userdata.json"), user)
    if item is False:
        print("Enter the following data\n")
        add_data(user)


def add_data(user):
    # Enter user data screen
    root.geometry("750x800")
    dniLabel = ttk.Label(root, text="DNI:", font=('Century 12'))
    dniLabel.pack()
    dniBox = ttk.Entry(root, font=('Century 12'), width=40);
    dniBox.pack()
    nameLabel = ttk.Label(root, text="Name:", font=('Century 12'))
    nameLabel.pack()
    nameBox = ttk.Entry(root, font=('Century 12'), width=40);
    nameBox.pack()
    surnameLabel = ttk.Label(root, text="Surname:", font=('Century 12'))
    surnameLabel.pack()
    surnameBox = ttk.Entry(root, font=('Century 12'), width=40);
    surnameBox.pack()
    hospitalLabel = ttk.Label(root, text="Hospital:", font=('Century 12'))
    hospitalLabel.pack()
    hospitalBox = ttk.Entry(root, font=('Century 12'), width=40);
    hospitalBox.pack()
    symptomsLabel = ttk.Label(root, text="Symptoms:", font=('Century 12'))
    symptomsLabel.pack()
    symptomsBox = ttk.Entry(root, font=('Century 12'), width=40);
    symptomsBox.pack()

    DNI = dniBox.get()  # dnientry()
    Nombre = nameBox.get()  # Name("Nombre: ")
    Apellido = Checktext(surnameBox.get())  # Name("Apellido: ")
    Hospital = Checktext(hospitalBox.get())  # Checktext("Hospital: ")
    Symptoms = Checktext(symptomsBox.get())  # Checktext("Symptoms: ")
    Date = Checkdate()
    user_list = {"username": user, "Nombre": Nombre, "Apellido": Apellido,
                 "DNI": DNI, "Hospital": Hospital, "Symptoms": Symptoms, "Date": Date}
    write_input("userdata.json", user_list)


def Name(str):
    text = input("Please enter " + str)
    try:
        my_regex = re.compile(r'^[A-Z][A-Z a-z]*$')
        res = my_regex.fullmatch(text)
        if not res:
            raise Exception("Only strings with capital letter at the beggining and no digits are allowed")
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return text


def dnientry():
    DNI = input("Please enter DNI\n")
    try:
        my_regex = re.compile(r'\b\d{8}[A-Z]\b')
        res = my_regex.fullmatch(DNI)
        if not res:
            raise Exception("DNI must contain 7 numbers and a final letter")
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return DNI


def Checktext(str):
    text = input("Please enter " + str)
    try:
        my_regex = re.compile(r'^[A-Z][A-Z a-z,]*$')
        res = my_regex.fullmatch(text)
        if not res:
            raise Exception("Only strings with capital letter at the beginning and no digits are allowed")
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return text


def Checkdate():
    date = input("Please enter date in dd/mm/yy format")
    try:
        my_regex = re.compile(r'\b(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/\d{2}\b')
        res = my_regex.fullmatch(date)
        if not res:
            raise Exception("date must be in format dd/mm/yy")
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return date


def find_user(data_list, user):
    for item in data_list:
        if item["username"] == user:
            return item
    return False


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
    password = bytes(password, "utf-8")
    keybytes = decode_to_bytes(key)
    kdf.verify(password, keybytes)

    return True


def encode_to_ascii(key):
    key64 = base64.b64encode(key)
    keyascii = key64.decode("ascii")

    return keyascii


def decode_to_bytes(key):
    keybytes1 = base64.b64decode(key)
    key64 = base64.b64encode(keybytes1)
    bytekey = base64.b64decode(key64)

    return bytekey


def showUser(inputs):
    root.geometry("1500x950")
    for widget in root.winfo_children():
        widget.destroy()
    welcomeLabel = Label(root, text="Welcome! " + inputs["username"], font=('Century 20 bold'))
    welcomeLabel.place(x=25, y=25)


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
passwordBox = ttk.Entry(root, show='*', font=('Century 12'), width=40)
passwordBox.pack()
loginWarning = Label(root, text="(If user does not exist, it will be created)", font=('Century 12 italic'))
loginWarning.pack(pady=10)

loginButton = ttk.Button(root, text="Log in", command=get_values)
loginButton.pack()

root.mainloop()
