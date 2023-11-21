import tkinter
from tkinter import *
from tkinter import ttk
import json
import os

import cryptography.exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import re
import time

"""Esto es una mala práctica, y la key debería ser generada y guerdada fuera de el código fuente y del storage, pero para el contexto 
específico de la práctica es un mal necesario"""
dataKey = b"\xc2\x03\x82N\x8b\x8a\xca\xb3YN.\xac\xe5}'\xa1\xb5\x06\xf0\xe02\xf6\x8d\x1c.\xbf@\xc9\xe5\xa0\x8f\xb2"


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


def pantalla_pass_firma(data_list):
    destroy_widgets()
    root.geometry("750x500")
    space1 = Label(root, text=" ")
    space1.pack(pady=10)
    title = Label(root, text="Al ser un nuevo usuario,\n necesita crear una contraseña de firmado",
                  font=('Century 20 bold'))
    title.pack(pady=30)
    space2 = Label(root, text=" ")
    space2.pack(pady=5)
    passwordLabel = ttk.Label(root, text="Password:", font=('Century 12'))
    passwordLabel.pack()
    passwordBox = ttk.Entry(root, show='*', font=('Century 12'), width=40)
    passwordBox.pack()
    firmar = ttk.Button(root, text="Firmar", command=lambda: guardar_pass_firma(data_list, str(passwordBox.get())))
    firmar.pack()


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
    readlist = decript(list)
    for item in readlist:
        if item["DNI"] != DNI:
            space1 = Label(root, text=" ")
            space1.pack(pady=10)
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
    LogOutButton = ttk.Button(root, text="Log out", command=lambda: login)
    LogOutButton.pack()
    GenerateFirma = ttk.Button(root, text="Generar firma", command=lambda: pantalla_firma(readlist))
    GenerateFirma.pack()


def pantalla_firma(readlist):
    destroy_widgets()
    root.geometry("750x500")
    userLabel = ttk.Label(root, text="Introduzca el nombre del paciente", font=('Century 12'))
    userLabel.pack()
    userBox = ttk.Entry(root, font=('Century 12'), width=40)
    userBox.pack()
    space1 = Label(root, text=" ")
    space1.pack(pady=10)
    title = Label(root, text="Introduzca la contraseña de firmado", font=('Century 20 bold'))
    title.pack(pady=30)
    space2 = Label(root, text=" ")
    space2.pack(pady=5)
    passwordLabel = ttk.Label(root, text="Password:", font=('Century 12'))
    passwordLabel.pack()
    passwordBox = ttk.Entry(root, show='*', font=('Century 12'), width=40)
    passwordBox.pack()
    loginWarning = Label(root, text="(If user does not exist, it will be created)", font=('Century 12 italic'))
    loginWarning.pack(pady=10)
    firmar = ttk.Button(root, text="Firmar", command=lambda: generate_firma(readlist, str(passwordBox.get()), userBox.get()))
    firmar.pack()


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
    return pantalla_pass_firma(inputs)


# Crea un user + contraseña y cifra
def adduser(data_list, passfirma):
    newsalt = os.urandom(16)
    key, saltascii = calculate_key(data_list["password"], newsalt)
    create_dict(data_list["username"], key, saltascii)
    crearclaves(data_list["username"], passfirma)
    read_data(data_list["username"])


def guardar_pass_firma(data_list, password):
    write_input("firmas.json", {"Usuario": data_list["username"], "Password": password})
    adduser(data_list, password)


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
        write_input("userdata.json", encryptlist(user_list))
        return read_data(user_list["username"])


def encryptlist(user_list):
    aad = bytes(user_list["username"], "utf-8")
    chacha = ChaCha20Poly1305(dataKey)
    dniEncrypted, nonceDNI, dniEncryptedAscii = encrypt(user_list["DNI"], aad, chacha)
    nombreEncrypted, nonceNombre, nombreEncryptedAscii = encrypt(user_list["Nombre"], aad, chacha)
    apellidoEncrypted, nonceApellido, apellidoEncryptedAscii = encrypt(user_list["Apellido"], aad, chacha)
    hospitalEncrypted, nonceHospital, hospitalEncryptedAscii = encrypt(user_list["Hospital"], aad, chacha)

    user_list_encrypted = {"username": user_list["username"], "Nombre": nombreEncryptedAscii,
                           "nonceNombre": encode_to_ascii(nonceNombre),
                           "Apellido": apellidoEncryptedAscii, "nonceApellido": encode_to_ascii(nonceApellido),
                           "DNI": dniEncryptedAscii, "nonceDni": encode_to_ascii(nonceDNI), "Date": user_list["Date"],
                           "Hospital": hospitalEncryptedAscii, "nonceHospital": encode_to_ascii(nonceHospital),
                           "Symptoms": user_list["Symptoms"]}

    return user_list_encrypted


def erase_user(user):
    list1 = open_json("userdata.json")
    list2 = []
    for item in list1:
        if item["username"] != user:
            list2.append(item)
    return list2


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


def generate_firma(readlist, passwordbox, username):
    doctorName = False
    password = bytes(passwordbox, "utf-8")
    for item in readlist:
        if (item["Nombre"] == username):
            doctorName = item["username"]

    if doctorName is False:
        return False

    with open(doctorName + ".txt", 'rb') as file:
        # Read the entire content of the file
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=password,
        )
    messagelist = []
    for item in readlist:
        if item["username"] == username:
            messagelist.append(item)
    messagebytes = bytes(messagelist)
    signature = private_key.sign(
        messagebytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    public_key = private_key.public_key()
    public_key.verify(
        signature,
        messagebytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    space1 = Label(root, text=" ")
    space1.pack(pady=10)
    title = Label(root, text="Firmado y verificado con éxito", font=('Century 20 bold'))
    title.pack(pady=30)



def crearclaves(username, passfirma):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(str.encode(passfirma))
    )
    with open(username + ".txt", 'wb') as f:
        f.write(pem)


def decript(data_list):
    listdisplay = []
    for item in data_list:
        username = item["username"]
        DNI = decode_to_bytes(item["DNI"])
        Nombre = decode_to_bytes(item["Nombre"])
        Apellido = decode_to_bytes(item["Apellido"])
        Hospital = decode_to_bytes(item["Hospital"])

        nonceDNI = decode_to_bytes(item["nonceDni"])
        nonceNombre = decode_to_bytes(item["nonceNombre"])
        nonceApellido = decode_to_bytes(item["nonceApellido"])
        nonceHospital = decode_to_bytes(item["nonceHospital"])

        aad = bytes(item["username"], "UTF-8")
        chacha = ChaCha20Poly1305(dataKey)
        dniDecrypt = chacha.decrypt(nonceDNI, DNI, aad)
        nombreDecrypt = chacha.decrypt(nonceNombre, Nombre, aad)
        apellidoDecrypt = chacha.decrypt(nonceApellido, Apellido, aad)
        hospitalDecrypt = chacha.decrypt(nonceHospital, Hospital, aad)
        dniAscii = str(dniDecrypt, "UTF-8")
        nombreAscii = str(nombreDecrypt, "UTF-8")
        apellidoAscii = str(apellidoDecrypt, "UTF-8")
        hospitalAscii = str(hospitalDecrypt, "UTF-8")
        listdisplay.append({"username": item["username"], "Nombre": nombreAscii, "Apellido": apellidoAscii,
                            "DNI": dniAscii, "Date": item["Date"], "Hospital": hospitalAscii,
                            "Symptoms": item["Symptoms"]})
    newlist = []
    for item in listdisplay:
        # Rotación de claves
        newlist.append(encryptlist(item))
    oldlist = erase_user(username)
    completelist = oldlist + newlist
    write_newsalt("userdata.json", completelist)
    return listdisplay


def encrypt(to_encrypt, aad, chacha):
    dataBytes = bytes(to_encrypt, "utf-8")
    noncedata = os.urandom(12)
    dataEncrypted = chacha.encrypt(noncedata, dataBytes, aad)
    dataEncryptedAscii = encode_to_ascii(dataEncrypted)
    return dataEncrypted, noncedata, dataEncryptedAscii


def encode_to_ascii(key):
    key64 = base64.b64encode(key)
    keyascii = key64.decode("ascii")

    return keyascii


def decode_to_bytes(key):
    keybytes1 = base64.b64decode(key)
    key64 = base64.b64encode(keybytes1)
    bytekey = base64.b64decode(key64)

    return bytekey


# Regex checks
def checkregex(list1):
    DNI = dnientry(list1["DNI"])
    Nombre = Checktext(list1["Nombre"])
    Apellido = Checktext(list1["Apellido"])
    Hospital = Checktext(list1["Hospital"])
    Symptoms = Checktext(list1["Symptoms"])
    Date = Checkdate(list1["Date"])
    if all((Nombre, Apellido, DNI, Hospital, Symptoms, Date)) is True:
        return True

    return False


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

    return True


def Checktext(text):
    try:
        my_regex = re.compile(r'^[A-Z][A-Z a-z]*$')
        res = my_regex.fullmatch(text)
        if not res:
            incorrectLabel = Label(root,
                                   text="Only strings with capital letter at the beginning and no digits are allowed",
                                   font='Century 12', fg="#FF5733")
            incorrectLabel.pack()
            return False
    except KeyError as ex:
        raise Exception("Bad label") from ex

    return True


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

    return True


# Main function


root = Tk()
login()
root.mainloop()
