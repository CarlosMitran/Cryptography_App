from tkinter import *
from tkinter import ttk
import json
import os

import cryptography.exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64
import re
import time

"""
To do:

-- Cifrado Autenticado


"""


# Tkinter pantallas
def login():
    destroy_widgets()
    root.geometry("750x500")
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
    loginButton = ttk.Button(root, text="Log in", command=lambda: get_values(userBox, passwordBox))
    loginButton.pack()


def add_data(user):
    destroy_widgets()
    # Enter user data screen
    root.geometry("750x800")
    space1 = Label(root, text=" ")
    space1.pack(pady=10)
    dniLabel = ttk.Label(root, text="DNI:", font='Century 12')
    dniLabel.pack()
    dniBox = ttk.Entry(root, font='Century 12', width=40)
    dniBox.pack()
    nameLabel = ttk.Label(root, text="Name:", font='Century 12')
    nameLabel.pack()
    nameBox = ttk.Entry(root, font='Century 12', width=40)
    nameBox.pack()
    surnameLabel = ttk.Label(root, text="Surname:", font='Century 12')
    surnameLabel.pack()
    surnameBox = ttk.Entry(root, font='Century 12', width=40)
    surnameBox.pack()
    hospitalLabel = ttk.Label(root, text="Hospital:", font='Century 12')
    hospitalLabel.pack()
    hospitalBox = ttk.Entry(root, font='Century 12', width=40)
    hospitalBox.pack()
    symptomsLabel = ttk.Label(root, text="Symptoms:", font='Century 12')
    symptomsLabel.pack()
    symptomsBox = ttk.Entry(root, font='Century 12', width=40)
    symptomsBox.pack()
    dateLabel = ttk.Label(root, text="Date:", font='Century 12')
    dateLabel.pack()
    dateBox = ttk.Entry(root, font='Century 12', width=40)
    dateBox.pack()
    user_list = {"username": user, "Nombre": nameBox, "Apellido": surnameBox,
                 "DNI": dniBox, "Hospital": hospitalBox, "Symptoms": symptomsBox, "Date": dateBox}
    writeButton = ttk.Button(root, text="Write data", command=lambda: get_data(user_list))
    writeButton.pack()


def display_data(list):
    destroy_widgets()
    root.geometry("750x800")
    DNI = ""
    for item in list:
        if item["DNI"] != DNI:
            dniLabel = ttk.Label(root, text=item["DNI"], font=('Century 12'))
            dniLabel.pack()
            nameLabel = ttk.Label(root, text=item["Nombre"] + " " + item["Apellido"], font=('Century 12'))
            nameLabel.pack()
        dateLabel = ttk.Label(root, text=item["Date"], font='Century 12')
        dateLabel.pack()
        hospitalLabel = ttk.Label(root, text=item["Hospital"], font='Century 12')
        hospitalLabel.pack()
        symptomsLabel = ttk.Label(root, text=item["Symptoms"], font='Century 12')
        symptomsLabel.pack()
        DNI = item["DNI"]

    writeButton = ttk.Button(root, text="Write new data", command=lambda: add_data(item["username"]))
    writeButton.pack()
    LogOutButton = ttk.Button(root, text="Log out", command=login)
    LogOutButton.pack()


def destroy_widgets():
    for widget in root.winfo_children():
        widget.destroy()


# Proceso de buscar datos

def get_values(user_value, password_value):
    user = user_value.get()
    password = password_value.get()
    if create_user(open_json("users.json"), {"username": user, "password": password}):
        return read_data(user)

# Crear users y añadirles información
def create_user(data_list, inputs):
    for item in data_list:
        if item["username"] == inputs["username"]:
            try:
                verify_key(inputs["password"], item["password"], item["salt"])
                newsalt = os.urandom(16)
                item["password"], item["salt"] = calculate_key(inputs["password"], newsalt)
                write_newsalt("users.json", data_list)
                return True

            except cryptography.exceptions.InvalidKey:
                incorrectPasswordLabel = Label(root, text="Incorrect password", font='Century 12', fg="#FF5733")
                incorrectPasswordLabel.pack()

                return False
    return adduser(inputs)


# Crea un user + contraseña y cifra
def adduser(data_list):
    newsalt = os.urandom(16)
    key, saltascii = calculate_key(data_list["password"], newsalt)
    create_dict(data_list["username"], key, saltascii)
    read_data(data_list["username"])


# Crea un diccionario donde guardar user contraseña cifrada encodedada a base 64 y salt encodeada a b64 y la escribe al json
def create_dict(user, password, salt):
    user_list = {"username": user, "password": password, "salt": salt}
    write_input("users.json", user_list)


def read_data(user):
    item = find_user(open_json("userdata.json"), user)
    if item is False:
        return add_data(user)
    display_data(item)


def get_data(data_list):
    DNI = data_list["DNI"].get()
    Nombre = data_list["Nombre"].get()
    Apellido = data_list["Apellido"].get()
    Hospital = data_list["Hospital"].get()
    Symptoms = data_list["Symptoms"].get()
    Date = data_list["Date"].get()
    user_list = {"username": data_list["username"], "Nombre": Nombre, "Apellido": Apellido,
                 "DNI": DNI, "Date": Date, "Hospital": Hospital, "Symptoms": Symptoms}
    if checkregex(user_list):
        for item in user_list:
            if item == "DNI":
                dniBytes = bytes(DNI, "utf-8")
                aad = bytes(user_list["username"], "utf-8")
                dniKey = ChaCha20Poly1305.generate_key()
                chachaDni = ChaCha20Poly1305(dniKey)
                nonceDni = os.urandom(12)
                dniEncrypted = chachaDni.encrypt(nonceDni, dniBytes, aad)
                dniEncryptedAscii = encode_to_ascii(dniEncrypted)
            if item == "Nombre":
                nombreBytes = bytes(Nombre, "utf-8")
                aad = bytes(user_list["username"], "utf-8")
                nombreKey = ChaCha20Poly1305.generate_key()
                chachaNombre = ChaCha20Poly1305(nombreKey)
                nonceNombre = os.urandom(12)
                nombreEncrypted = chachaNombre.encrypt(nonceNombre, nombreBytes, aad)
                nombreEncryptedAscii = encode_to_ascii(nombreEncrypted)
            if item == "Apellido":
                apellidoBytes = bytes(Apellido, "utf-8")
                aad = bytes(user_list["username"], "utf-8")
                apellidoKey = ChaCha20Poly1305.generate_key()
                chachaApellido = ChaCha20Poly1305(apellidoKey)
                nonceApellido = os.urandom(12)
                apellidoEncrypted = chachaApellido.encrypt(nonceApellido, apellidoBytes, aad)
                apellidoEncryptedAscii = encode_to_ascii(apellidoEncrypted)
            if item == "Hospital":
                hospitalBytes = bytes(Hospital, "utf-8")
                aad = bytes(user_list["username"], "utf-8")
                hospitalKey = ChaCha20Poly1305.generate_key()
                chachaHospital = ChaCha20Poly1305(hospitalKey)
                nonceHospital = os.urandom(12)
                hospitalEncrypted = chachaHospital.encrypt(nonceHospital, hospitalBytes, aad)
                hospitalEncryptedAscii = encode_to_ascii(hospitalEncrypted)

        user_list_encrypted = {"username": data_list["username"], "Nombre": nombreEncryptedAscii, "Apellido": apellidoEncryptedAscii,
                              "DNI": dniEncryptedAscii, "Date": Date, "Hospital": hospitalEncryptedAscii, "Symptoms": Symptoms}
        write_input("userdata.json", user_list_encrypted)

        #decrypt
        dniDecrypt = chachaDni.decrypt(nonceDni, dniEncrypted, aad)
        nombreDecrypt = chachaNombre.decrypt(nonceNombre, nombreEncrypted, aad)
        apellidoDecrypt = chachaApellido.decrypt(nonceApellido, apellidoEncrypted, aad)
        hospitalDecrypt = chachaHospital.decrypt(nonceHospital, hospitalEncrypted, aad)
        dniAscii = encode_to_ascii(dniDecrypt)
        nombreAscii = encode_to_ascii(nombreDecrypt)
        apellidoAscii = encode_to_ascii(apellidoDecrypt)
        hospitalAscii = encode_to_ascii(hospitalDecrypt)
        user_list_decrypted = {"username": data_list["username"], "Nombre": nombreAscii, "Apellido": apellidoAscii,
                              "DNI": dniAscii, "Date": Date, "Hospital": hospitalAscii, "Symptoms": Symptoms}
        read_data(user_list_decrypted["username"])


def find_user(data_list, user):
    list1 = []
    for item in data_list:
        if item["username"] == user:
            list1.append(item)

    if len(list1) > 0:
        return list1

    return False


# Json manipulation
def write_input(json_file, inputs):  # create user
    list1 = open_json(json_file)
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


# Cryptography related

#   Part 1
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


def write_newsalt(json_file, data_list):
    try:
        with open(json_file, "w", encoding="UTF-8", newline="") as file:
            json.dump(data_list, file, indent=2)
    except FileNotFoundError as ex:
        raise Exception("Wrong file or file path") from ex


# Regex checks
def checkregex(list1):
    DNI = dnientry(list1["DNI"])
    Nombre = Checktext(list1["Nombre"])
    Apellido = Checktext(list1["Apellido"])
    Hospital = Checktext(list1["Hospital"])
    Symptoms = Checktext(list1["Symptoms"])
    Date = Checkdate(list1["Date"])
    if any((Nombre, Apellido, DNI, Hospital, Symptoms, Date)) is False:
        return False
    return True

def dnientry(DNI):
    try:
        my_regex = re.compile(r'\b\d{8}[A-Z]\b')
        res = my_regex.fullmatch(DNI)
        if not res:
            incorrectLabel = Label(root,
                                   text="DNI must contain 7 numbers and a final letter",
                                   font='Century 12', fg="#FF5733")
            incorrectLabel.pack()
            return False
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return DNI


def Checktext(text):
    try:
        my_regex = re.compile(r'^[A-Z][A-Z a-z,]*$')
        res = my_regex.fullmatch(text)
        if not res:
            incorrectLabel = Label(root,
                                   text="Only strings with capital letter at the beginning and no digits are allowed",
                                   font='Century 12', fg="#FF5733")
            incorrectLabel.pack()
            return False
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return text


def Checkdate(date):
    try:
        my_regex = re.compile(r'\b(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/\d{2}\b')
        res = my_regex.fullmatch(date)
        if not res:
            incorrectLabel = Label(root, text="The date must be in format dd/mm/yy", font='Century 12', fg="#FF5733")
            incorrectLabel.pack()
            return False
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return date


# Main function


root = Tk()
login()
root.mainloop()
