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
import shutil

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
    loginButton = ttk.Button(root, text="Log in",
                             command=lambda: validarentrada(str(userBox.get())))
    loginButton.pack()


def validarentrada(doctorName):
    try:
        with open(doctorName + ".txt", 'rb') as file:
            # Read the entire content of the file
            return validarPass(doctorName)
    except FileNotFoundError as ex:
        incorrectPasswordLabel = Label(root, text="El doctor no está en la base de datos", font='Century 12', fg="#FF5733")
        incorrectPasswordLabel.pack()


def validarPass(doctorName):
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
                             command=lambda: generarCSR(doctorName, str(passwordBox.get())))
    loginButton.pack()


def generarCSR(doctorName, password):
    passbytes = bytes(password, "utf-8")
    try:
        with open(doctorName + ".txt", 'rb') as file:
            # Read the entire content of the file
            key = serialization.load_pem_private_key(
                file.read(),
                password=passbytes,
            )
    except ValueError:
        incorrectPasswordLabel = Label(root, text="Incorrect password", font='Century 12', fg="#FF5733")
        incorrectPasswordLabel.pack()

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([

        # Provide various details about who we are.

        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),

        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),

        x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganés"),

        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "System"),

        x509.NameAttribute(NameOID.COMMON_NAME, doctorName),

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

    # Write our CERT out to disk.

    with open("AC1/solicitudes/CSR" + doctorName + ".pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    createcert(doctorName)


def createcert(doctorName):
    with open("AC1/serial", "r") as f:
        num = f.read()

    os.chdir("AC1")
    os.system("ls")
    os.system("openssl req -in ./solicitudes/CSR" + doctorName + ".pem -text -noout")
    os.system("openssl ca -in ./solicitudes/CSR" + doctorName + ".pem -notext -config ./openssl_AC1.cnf")
    os.chdir("..")
    source_path = "AC1/nuevoscerts/"+num[0]+num[1]+".pem"
    print(source_path)
    destination_path = "CERT/CERT"+doctorName+".pem"
    # Copy the file
    shutil.copyfile(source_path, destination_path)
    validarCert(doctorName)

def validarCert(username):
    with open("CERT/" + "CERT" + username + ".pem", "rb") as f:
        pem_data = f.read()
    with open("AC1/ac1cert.pem", 'rb') as file:
        certbytes = file.read()
    certcnf = x509.load_pem_x509_certificate(certbytes)
    public_key = certcnf.public_key()
    cert = x509.load_pem_x509_certificate(pem_data)
    loginButton = ttk.Button(root, text="Volver",
                             command=lambda: certificar())
    loginButton.pack()

    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        CorrectPasswordLabel = Label(root, text="Certificado verificado correctamente", font='Century 12')
        CorrectPasswordLabel.pack()
        return True
    except cryptography.exceptions.InvalidSignature:
        incorrectPasswordLabel = Label(root, text="Verificación fallida", font='Century 12', fg="#FF5733")
        incorrectPasswordLabel.pack()





def destroy_widgets():
    for widget in root.winfo_children():
        widget.destroy()


root = Tk()
certificar()
root.mainloop()
