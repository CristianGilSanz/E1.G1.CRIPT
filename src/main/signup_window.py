import tkinter as tk
from tkinter import messagebox

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import pyotp

import os
import json
import re

import qrcode

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage

class SignUpWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Crear cuenta")
        self.master.geometry("500x700")

        self.create_widgets()
    
    def create_widgets(self):
        self.label_daily_server_access_key = tk.Label(self.master, text="Cl@VE DE ACCESO AL SERVIDOR")
        self.label_daily_server_access_key.pack(pady=5)

        self.entry_daily_server_access_key = tk.Entry(self.master, show="*", width=35)
        self.entry_daily_server_access_key.pack(pady=5)

        self.label_DNI = tk.Label(self.master, text="DNI")
        self.label_DNI.pack(pady=5)

        self.entry_DNI = tk.Entry(self.master, width=35)
        self.entry_DNI.pack(pady=5)

        self.label_pem_peer_private_key = tk.Label(self.master, text="Cl@ve privada")
        self.label_pem_peer_private_key.pack(pady=5)

        self.entry_pem_peer_private_key = tk.Entry(self.master, show="*", width=35)
        self.entry_pem_peer_private_key.pack(pady=5)

        self.label_new_username = tk.Label(self.master, text="Nuevo nombre de usuario")
        self.label_new_username.pack(pady=5)

        self.entry_new_username = tk.Entry(self.master, width=35)
        self.entry_new_username.pack(pady=5)

        self.label_email = tk.Label(self.master, text="Correo electrónico")
        self.label_email.pack(pady=5)

        self.entry_email = tk.Entry(self.master, width=35)
        self.entry_email.pack(pady=5)

        self.label_new_password = tk.Label(self.master, text="Nueva contraseña")
        self.label_new_password.pack(pady=5)

        self.entry_new_password = tk.Entry(self.master, show="*", width=35)
        self.entry_new_password.pack(pady=5)

        self.label_confirm_password = tk.Label(self.master, text="Confirmar contraseña")
        self.label_confirm_password.pack(pady=5)

        self.entry_confirm_password = tk.Entry(self.master, show="*", width=35)
        self.entry_confirm_password.pack(pady=5)

        self.button_signup = tk.Button(self.master, text="Enviar", command=self.enviar_datos)
        self.button_signup.pack(pady=10)

    def enviar_datos(self):
        daily_server_access_key = self.entry_daily_server_access_key.get()
        DNI = self.entry_DNI.get()
        pem_peer_private_key = self.entry_pem_peer_private_key.get()
        new_username = self.entry_new_username.get()
        email= self.entry_email.get()
        new_password = self.entry_new_password.get()
        confirm_password = self.entry_confirm_password.get()

        with open("../JsonFiles/server_credentials.json", "r") as file:
            server_credentials = json.load(file)

        try:

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt= bytes.fromhex(server_credentials["salt"]),
                iterations=480000,
            )
                                    
            symmetrical_master_key = base64.urlsafe_b64encode(kdf.derive(daily_server_access_key.encode()))
            f = Fernet(symmetrical_master_key)

            decrypted_pem_server_private_key = (f.decrypt(server_credentials["pem_server_private_key"].encode())).decode()
                
            decrypted_pem_server_public_key = (f.decrypt(server_credentials["pem_server_public_key"].encode())).decode()

            decrypted_sender_pass = (f.decrypt(server_credentials["sender_pass"].encode())).decode()

            decrypted_host = (f.decrypt(server_credentials["host"].encode())).decode()
            decrypted_user = (f.decrypt(server_credentials["user"].encode())).decode()
            decrypted_password = (f.decrypt(server_credentials["password"].encode())).decode()
            decrypted_database = (f.decrypt(server_credentials["database"].encode())).decode()
                    
        except:
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Petición denegada")
            self.master.deiconify()
            return

        with open("../JsonFiles/signup_users_credentials.json", "r") as file:
            signup_users_credentials = json.load(file)

        for new_user_account in signup_users_credentials:
            
            if new_user_account["DNI"] != DNI:
                self.master.withdraw()
                messagebox.showerror("Error de registro", "Petición denegada")
                self.master.deiconify()
                return

            pem_peer_public_key = new_user_account["public_key"]
            

            #--------------SERVER KEYS: Deserializar--------------#

            not_serialised_server_private_key = serialization.load_pem_private_key(
                decrypted_pem_server_private_key.encode(),
                password=None,
                backend=default_backend()
            )

            not_serialised_server_public_key = serialization.load_pem_public_key(
                decrypted_pem_server_public_key.encode(),
                backend=default_backend()
            )

            #--------------PEER KEYS: Deserializar--------------#

            not_serialised_peer_private_key = serialization.load_pem_private_key(
                pem_peer_private_key.encode(),
                password=None,
                backend=default_backend()
            )

            not_serialised_peer_public_key = serialization.load_pem_public_key(
                pem_peer_public_key.encode(),
                backend=default_backend()
            )

            #--------------HANDSHAKES--------------#
            shared_key_server_peer = not_serialised_server_private_key.exchange(
            ec.ECDH(), not_serialised_peer_public_key)

            shared_key_peer_server = not_serialised_peer_private_key.exchange(
            ec.ECDH(), not_serialised_server_public_key)

            if shared_key_server_peer != shared_key_peer_server:
                self.master.withdraw()
                messagebox.showerror("Error de registro", "Petición denegada")
                self.master.deiconify()
                return
        
        if new_username=="":
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Introduzca un nombre de usuario")
            self.master.deiconify()
            return
        
        with open("../JsonFiles/login_users_credentials.json", "r") as file:
            login_users_credentials = json.load(file)

        for user_account in login_users_credentials:
            if user_account["username"] == new_username:
                self.master.withdraw()
                messagebox.showerror("Error de registro", "El nombre de usuario ya está en uso")
                self.master.deiconify()
                return
            
        if not re.match(r'^[\w.-]+@[\w.-]+\.\w+$',email):
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Introduzca una dirección de correo válida")
            self.master.deiconify()
            return

        for user_account in login_users_credentials:
            if user_account["email"] == email:
                self.master.withdraw()
                messagebox.showerror("Error de registro", "El correo electrónico ya está en uso")
                self.master.deiconify()
                return
        
        if not re.match(r'(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\u0020-\u002f\u003A-\u0040\u005B-\u0060\u007B-\u007E]).{8,}',new_password):
            self.master.withdraw()
            messagebox.showerror("Error de registro", "La contraseña ha de contener:\n\n   ·Mínimo 8 caracteres de longitud.\n   ·Al menos una letra minúscula.\n   ·Al menos una letra mayúscula.\n   ·Al menos un dígito.\n   ·Al menos un carácter especial.")
            self.master.deiconify()
            return
        
        if new_password != confirm_password:
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Las contraseñas no coinciden.")
            self.master.deiconify()
            return
        
        sender_address = "centrodesaludcryptoshield@gmail.com"
        sender_pass = decrypted_sender_pass
        receiver_address = email

        mail_content = '''Hola {}, bienvenido al Centro de Salud CryptoShield.

Sus credenciales han sido registradas con éxito en nuestro sistema. Ya puede acceder en cualquier momento a su cuenta con su nombre de usuario y contraseña.
        
Además, necesitará de un doble factor de autenticación para iniciar sesión que le suministramos en forma en el código QR adjunto a este correo.
Puede escanearlo directamente con Google Authenticator en su dispositivo móvil pa su utilización.

Gracias por confiar en nosotros.

Centro de Salud CryptoShield'''.format(new_username)
        
        message = MIMEMultipart()
        message['From'] = sender_address
        message['To'] = receiver_address
        message['Subject'] = 'Centro de Salud CryptoShield: ¡Aquí tienes tu 2FA! 🔐.'
        
        message.attach(MIMEText(mail_content, 'plain'))
        
        otp_0 = pyotp.random_base32()
        uri = pyotp.totp.TOTP(otp_0).provisioning_uri(name= new_username, issuer_name="HospitalManagementSystem")

        qr_save_path = "E1.G1.CRIPT/src/temp_outputs/" + str(new_username) + "_qrcode.png"
        
        qrcode.make(uri).save(qr_save_path)
        
        with open(qr_save_path, 'rb') as qr_file:
            qr_code = qr_file.read()
        
        qr_mime = MIMEImage(qr_code, name = "qr_" + new_username)
        
        message.attach(qr_mime)

        session = smtplib.SMTP('smtp.gmail.com', 587) 
        session.starttls()
        session.login(sender_address, sender_pass) 
        text = message.as_string()
        session.sendmail(sender_address, receiver_address, text)
        session.quit()

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )

        symmetrical_key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
        f = Fernet(symmetrical_key)

        new_password_encrypted = f.encrypt(new_password.encode())
        otp_0_encrypted = f.encrypt(otp_0.encode())

        new_user_dict = {"username": new_username, "email": email, "pass": new_password_encrypted.decode(), "tokenPass": otp_0_encrypted.decode(), "salt": str(salt.hex())}
        
        login_users_credentials.append(new_user_dict)

        new_login_users_credentials = json.dumps(login_users_credentials, indent=2)

        with open("../JsonFiles/login_users_credentials.json", "w") as file:
            file.write(new_login_users_credentials)

        for new_user_account in signup_users_credentials:
            if new_user_account["DNI"] == DNI:
                signup_users_credentials.remove(new_user_account)
        
        updated_signup_users_credentials = json.dumps(signup_users_credentials, indent=2) 

        with open("../JsonFiles/signup_users_credentials.json", "w") as file:
            file.write(updated_signup_users_credentials)

        os.remove(qr_save_path)

        self.entry_DNI.delete(0, tk.END)
        self.entry_pem_peer_private_key.delete(0, tk.END)
        self.entry_email.delete(0, tk.END)
        self.entry_new_username.delete(0, tk.END)
        self.entry_new_password.delete(0, tk.END)
        self.entry_confirm_password.delete(0, tk.END)

        self.master.destroy()

        messagebox.showinfo("Registro", "Su cuenta ha sido registrada con éxito.")