import tkinter as tk
from tkinter import messagebox

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
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

        self.create_widgets()  #Función para crear la interfaz de la ventana de LogIn
    
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

        self.button_signup = tk.Button(self.master, text="Enviar", command=self.signup_verification)
        self.button_signup.pack(pady=10)

    def signup_verification(self):
        #Obtenemos los datos introducidos en los inputs
        daily_server_access_key = self.entry_daily_server_access_key.get()
        DNI = self.entry_DNI.get()
        pem_peer_private_key = self.entry_pem_peer_private_key.get()
        new_username = self.entry_new_username.get()
        email= self.entry_email.get()
        new_password = self.entry_new_password.get()
        confirm_password = self.entry_confirm_password.get()

        #Abrimos el fichero JSON con las credenciales del servidor (base de datos MySQL)
        with open("../JsonFiles/server_credentials.json", "r") as file:
            server_credentials = json.load(file)

        try:
            #Derivamos la clave simétrica de cifrado del servidor a partir del ultimo SALT de encriptado público
            #y la clave maestra de acceso proporcionada por la administración del sistema
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes.fromhex(server_credentials["salt"]),
                iterations=480000,
            )

            symmetrical_master_key = base64.urlsafe_b64encode(kdf.derive(daily_server_access_key.encode()))
            f = Fernet(symmetrical_master_key)

            #Desencriptamos las credenciales de identidad y acceso del servidor
            decrypted_pem_server_private_key = (f.decrypt(server_credentials["pem_server_private_key"].encode())).decode()
                
            decrypted_pem_server_public_key = (f.decrypt(server_credentials["pem_server_public_key"].encode())).decode()

            decrypted_sender_pass = (f.decrypt(server_credentials["sender_pass"].encode())).decode()

            decrypted_host = (f.decrypt(server_credentials["host"].encode())).decode()
            decrypted_user = (f.decrypt(server_credentials["user"].encode())).decode()
            decrypted_password = (f.decrypt(server_credentials["password"].encode())).decode()
            decrypted_database = (f.decrypt(server_credentials["database"].encode())).decode()

        #Si la clave maestra es incorrecta se deniega la petición de registro
        except:
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Petición denegada")
            self.master.deiconify()
            return

        #Si las credenciales de solicitud al servidor son correctas, examinamos el fichero de usuarios autorizados
        #pendientes de registro
        with open("../JsonFiles/signup_users_credentials.json", "r") as file:
            signup_users_credentials = json.load(file)

        #Buscamos si el usuario esta autorizado para su registro y guardamos su clave pública
        found_DNI = False
        pem_peer_public_key= None

        for new_user_account in signup_users_credentials:
            if new_user_account["DNI"] == DNI:
                pem_peer_public_key = new_user_account["public_key"]
                found_DNI = True
                break

        if not found_DNI:
            self.master.withdraw()
            messagebox.showerror("Error de registro", "DNI no registrado")
            self.master.deiconify()
            return

        #Recuperamos el par de claves de cifrado asimétrico del servidor y comprobamos si la clave privada del
        #usuario genera la misma clave compartida o 'handshake'
        try:
            #Desearializamos la clave privada y pública del sistema tras ser desencriptada

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

            #Deserializamos la clave privada (introducida por el usuario) y pública del usuario a registrarse

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

            #Comprobamos que los pares de claves (privadas y públicas cruzadas) del usuario y el sistema generan
            #el mismo 'handshake' (cifrado asimétrico)
            if shared_key_server_peer != shared_key_peer_server:
                self.master.withdraw()
                messagebox.showerror("Error de registro", "Petición denegada")
                self.master.deiconify()
                return

        #De lo contrario, se deniega la petición
        except:
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Petición denegada")
            self.master.deiconify()
            return

        #Verificamos que el nombre de usuario ha de ser no vacío
        if new_username == "":
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Introduzca un nombre de usuario")
            self.master.deiconify()
            return

        #Inspeccionamos las cuentas ya registradas para registrar cuentas unívocas
        with open("../JsonFiles/login_users_credentials.json", "r") as file:
            login_users_credentials = json.load(file)

        #Si el nombre de usuario ya está registrado, pedimos otro
        for user_account in login_users_credentials:
            if user_account["username"] == new_username:
                self.master.withdraw()
                messagebox.showerror("Error de registro", "El nombre de usuario ya está en uso")
                self.master.deiconify()
                return
        #Si el email no presenta un formato válido, se pide de nuevo
        if not re.match(r'^[\w.-]+@[\w.-]+\.\w+$',email):
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Introduzca una dirección de correo válida")
            self.master.deiconify()
            return

        #Si el email está en uso por otro usuario, se pide otro
        for user_account in login_users_credentials:
            if user_account["email"] == email:
                self.master.withdraw()
                messagebox.showerror("Error de registro", "El correo electrónico ya está en uso")
                self.master.deiconify()
                return

        #Si la contraseña no es segura, se solicita otra
        if not re.match(r'(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\u0020-\u002f\u003A-\u0040\u005B-\u0060\u007B-\u007E]).{8,}', new_password):
            self.master.withdraw()
            messagebox.showerror("Error de registro", "La contraseña ha de contener:\n\n   ·Mínimo 8 caracteres de longitud.\n   ·Al menos una letra minúscula.\n   ·Al menos una letra mayúscula.\n   ·Al menos un dígito.\n   ·Al menos un carácter especial.")
            self.master.deiconify()
            return

        #Si las contraseñas no coinciden, se pide revisarlas
        if new_password != confirm_password:
            self.master.withdraw()
            messagebox.showerror("Error de registro", "Las contraseñas no coinciden.")
            self.master.deiconify()
            return

        #Construimos los datos necesarios para enviar un correo vía protocolo TLS a la dirección de correo del usuario
        #para notificarle de que su cuenta ha sido correctamente registrada, y adjuntarle un código QR con su 2FA
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

        #Se general la clave primaria del generador de tokens temporales para el 2FA del sistema
        otp_0 = pyotp.random_base32()
        uri = pyotp.totp.TOTP(otp_0).provisioning_uri(name= new_username, issuer_name="HospitalManagementSystem")

        qr_save_path = "../temp_outputs/" + str(new_username) + "_qrcode.png"
        
        qrcode.make(uri).save(qr_save_path)
        
        with open(qr_save_path, 'rb') as qr_file:
            qr_code = qr_file.read()
        
        qr_mime = MIMEImage(qr_code, name="QR_" + new_username)
        
        message.attach(qr_mime)

        session = smtplib.SMTP('smtp.gmail.com', 587) 
        session.starttls()
        session.login(sender_address, sender_pass) 
        text = message.as_string()
        session.sendmail(sender_address, receiver_address, text)
        session.quit()

        #Guardamos las credenciales de inicio de sesión sensibles derivando una clave de cifrado con un SALT aleatorio
        #(irá cambiando en cada inicio de sesión) y la contraseña del usario.
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

        #Borramos las credenciales del usuario del fichero de personal autorizado pendiente de registro
        for new_user_account in signup_users_credentials:
            if new_user_account["DNI"] == DNI:
                signup_users_credentials.remove(new_user_account)
        
        updated_signup_users_credentials = json.dumps(signup_users_credentials, indent=2) 

        with open("../JsonFiles/signup_users_credentials.json", "w") as file:
            file.write(updated_signup_users_credentials)

        #Eliminamos el QR generado que porporciona el 2FA al usuario que acaba de registrarse
        os.remove(qr_save_path)

        #Limpiamos los campos y destruimos la ventana una vez el registro se ha completado con éxito
        self.entry_DNI.delete(0, tk.END)
        self.entry_pem_peer_private_key.delete(0, tk.END)
        self.entry_email.delete(0, tk.END)
        self.entry_new_username.delete(0, tk.END)
        self.entry_new_password.delete(0, tk.END)
        self.entry_confirm_password.delete(0, tk.END)

        self.master.destroy()

        messagebox.showinfo("Registro", "Su cuenta ha sido registrada con éxito.")
