from app_window import HospitalManagementSystem
from signup_window import SignUpWindow

import tkinter as tk
from tkinter import messagebox

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import pyotp

import os
import json


class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Inicio de Sesión")
        self.master.geometry("500x750")

        self.create_widgets() #Función para crear la interfaz de la ventana de LogIn

    def create_widgets(self):
        self.label_username = tk.Label(self.master, text="USUARIO")
        self.label_username.pack(pady=5)

        self.entry_username = tk.Entry(self.master, width=35)
        self.entry_username.pack(pady=5)

        self.label_password = tk.Label(self.master, text="CONTRASEÑA")
        self.label_password.pack(pady=5)

        self.entry_password = tk.Entry(self.master, show="*", width=35)
        self.entry_password.pack(pady=5)

        self.label_token = tk.Label(self.master, text="TWO-FACTOR AUTHENTICATION TOKEN")
        self.label_token.pack(pady=5)

        self.entry_token = tk.Entry(self.master, width=35)
        self.entry_token.pack(pady=5)

        self.button_login = tk.Button(self.master, text="Iniciar sesión", command=self.access_verification, width = 10)
        self.button_login.pack(pady=10)

        self.button_signup = tk.Button(self.master, text="¿No tienes cuenta? Regístrate", width=40, command=self.signup_form)
        self.button_signup.pack(pady=20)

    def access_verification(self):
        #Obtenemos los datos introducidos en los inputs
        username_input = self.entry_username.get()
        password_input = self.entry_password.get()
        token_input = self.entry_token.get()

        #Abrimos el fichero JSON con las credenciales de los usuarios
        with open("../JsonFiles/login_users_credentials.json", "r") as file:
            login_users_credentials = json.load(file)

        for user_account in login_users_credentials:
            #Si el usuario esta registrado...
            if user_account["username"] == username_input:
                #Generamos la misma clave simétrica con la que se encriptaron sus datos recuperando el SALT almacenado
                #por última vez, y la contraseña que acaba de introducir
                try:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt= bytes.fromhex(user_account["salt"]),
                        iterations=480000,
                    )
                        
                    symmetrical_key = base64.urlsafe_b64encode(kdf.derive(password_input.encode()))
                    f = Fernet(symmetrical_key)

                    #Desencriptamos su contraseña y clave de 2FA
                    decrypted_password = (f.decrypt(user_account["pass"].encode())).decode()
                    decrypted_token = (f.decrypt(user_account["tokenPass"].encode())).decode()
                #Si la clave es incorrecta, se denega el acceso
                except:
                    messagebox.showerror("Error de inicio de sesión", "Credenciales incorrectas")
                    return

                #Si las credenciales son correctas, se desencripta la clave de 2FA
                totp = pyotp.TOTP(decrypted_token)  

                #Si el token subyacente a la clave es el indicado en el instante de ingreso...
                if totp.verify(token_input):

                    #Generamos un nuevo SALT, para generar una clave de cifrado simétrica diferente a la anterior
                    salt = os.urandom(16)

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=480000,
                    )

                    symmetrical_key = base64.urlsafe_b64encode(kdf.derive(decrypted_password.encode()))
                    f = Fernet(symmetrical_key)

                    #Encriptamos todas sus credenciales de nuevo con un SALT distinto
                    password_encrypted = f.encrypt(decrypted_password.encode())
                    otp_0_encrypted = f.encrypt(decrypted_token.encode())

                    user_account["pass"] = password_encrypted.decode()
                    user_account["tokenPass"] = otp_0_encrypted.decode()
                    #Almacenamos el nuevo SALT (SALT dinámico por cada inicio de sesión)
                    user_account["salt"] = str(salt.hex())

                    updated_login_user_credentials = json.dumps(login_users_credentials, indent=2)

                    with open("../JsonFiles/login_users_credentials.json", "w") as file:
                        file.write(updated_login_user_credentials)

                    #Se permite el acceso al gestor
                    self.master.destroy()
                    hospitalMngWnd = tk.Tk()
                    HospitalManagementSystem(hospitalMngWnd)
                    return
            
        messagebox.showerror("Error de inicio de sesión", "Credenciales incorrectas")

    #En el caso de no tener cuenta, se abre paso a la ventana de SignUp
    def signup_form(self):
        signUpWnd = tk.Tk()
        SignUpWindow(signUpWnd)
