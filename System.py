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
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
import re
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def certificar():
    destroy_widgets()
    root.geometry("750x500")
    space1 = Label(root, text=" ")
    space1.pack(pady=10)
    title = Label(root, text="Validación de Certificados", font=('Century 20 bold'))
    title.pack(pady=30)
    userLabel = ttk.Label(root, text="Nombre del doctor:", font=('Century 12'))
    userLabel.pack()
    userBox = ttk.Entry(root, font=('Century 12'), width=40)
    userBox.pack()
    space2 = Label(root, text=" ")
    space2.pack(pady=5)
    passwordLabel = ttk.Label(root, text="Nombre del paciente", font=('Century 12'))
    passwordLabel.pack()
    passwordBox = ttk.Entry(root, font=('Century 12'), width=40)
    passwordBox.pack()
    loginButton = ttk.Button(root, text="Log in",
                             command=lambda: validarentrada(str(userBox.get()), str(passwordBox.get())))
    loginButton.pack()


def validarentrada(doctorName, pacient):
    try:
        with open(doctorName + ".txt", 'rb') as file:
            # Read the entire content of the file
            return validarPass(doctorName, pacient)
    except FileNotFoundError as ex:
        raise Exception("Wrong file or file path") from ex


def validarPass(doctorName, pacient):
    destroy_widgets()
    root.geometry("750x500")
    space1 = Label(root, text=" ")
    space1.pack(pady=10)
    title = Label(root, text="Introduzca su clave privada", font=('Century 20 bold'))
    title.pack(pady=30)
    space2 = Label(root, text=" ")
    space2.pack(pady=5)
    passwordLabel = ttk.Label(root, text="Contraseña:", font=('Century 12'))
    passwordLabel.pack()
    passwordBox = ttk.Entry(root, show='*', font=('Century 12'), width=40)
    passwordBox.pack()
    loginButton = ttk.Button(root, text="Log in",
                             command=lambda: generarcertificados(doctorName, str(passwordBox.get()), pacient))
    loginButton.pack()


def generarcertificados(doctorName, password, pacient):
    passbytes = bytes(password, "utf-8")
    with open(doctorName + ".txt", 'rb') as file:
    # Read the entire content of the file
        key = serialization.load_pem_private_key(
            file.read(),
            password=passbytes,
        )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([

        # Provide various details about who we are.

        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),

        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),

        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),

        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),

        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),

    ])).add_extension(

        x509.SubjectAlternativeName([

            # Describe what sites we want this certificate for.

            x509.DNSName("mysite.com"),

            x509.DNSName("www.mysite.com"),

            x509.DNSName("subdomain.mysite.com"),

        ]),

        critical=False,

        # Sign the CSR with our private key.

    ).sign(key, hashes.SHA256())

    # Write our CSR out to disk.

    with open("CSR/certificado" + pacient + ".pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    readcert(pacient)


def readcert(username):
    with open("ac1cert.pem", "rb") as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data)
    public_key = cert.public_key()
    signatureload = cert.signature
    with open(username + "signedData" + ".txt", "r") as file:
        messageload = file.read()

    messageloadbytes = bytes(messageload, "utf-8")

    public_key.verify(
        signatureload,
        messageloadbytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("El certificado ha sido verificado")


def destroy_widgets():
    for widget in root.winfo_children():
        widget.destroy()


root = Tk()
certificar()
root.mainloop()
