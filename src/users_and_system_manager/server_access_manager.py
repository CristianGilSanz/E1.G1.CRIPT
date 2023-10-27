from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import json
import os
import base64
import sys
import pymysql

old_master_key = str(input("\nIntroduce la contraseña maestra: "))

with open("../JsonFiles/server_credentials.json", "r") as file:
    server_credentials = json.load(file)

try:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(server_credentials["salt"]),
        iterations=480000,
    )
                        
    old_symmetrical_master_key = base64.urlsafe_b64encode(kdf.derive(old_master_key.encode()))
    f = Fernet(old_symmetrical_master_key)

    decrypted_pem_server_private_key = (f.decrypt(server_credentials["pem_server_private_key"].encode())).decode()
    decrypted_pem_server_public_key = (f.decrypt(server_credentials["pem_server_public_key"].encode())).decode()

    decrypted_sender_pass = (f.decrypt(server_credentials["sender_pass"].encode())).decode()

    decrypted_host = (f.decrypt(server_credentials["host"].encode())).decode()
    decrypted_user = (f.decrypt(server_credentials["user"].encode())).decode()
    decrypted_password = (f.decrypt(server_credentials["password"].encode())).decode()
    decrypted_database = (f.decrypt(server_credentials["database"].encode())).decode()

except:
    print("Error: credenciales incorrectas")
    sys.exit()

connection = pymysql.connect(host=decrypted_host, user=decrypted_user, password=decrypted_password, database=decrypted_database)
cursor = connection.cursor()
cursor.execute("SELECT * FROM PATIENTS")
rows = cursor.fetchall()

if rows:
    for row in rows:
        list_row = list(row)
        DNI = str(row[2])

        try:
            row_decrypted = ([f.decrypt(str(attribute).encode()).decode() for attribute in row])
        except:
            print("La base de datos presenta entradas modificadas o corruptas. Por favor suprimalas antes de continuar.")
            sys.exit()
        
        cursor.execute("DELETE FROM PATIENTS WHERE `DNI`=%s", DNI)
        cursor.execute("INSERT INTO PATIENTS (`Estado del reg.`, `CIPA`, `DNI` ,`Nombre`, `Apellidos`, `Sexo`, `Edad`, `Teléfono`, `Email`, `Dirección`, `Grupo sanguíneo`, `Patología/s`, `Medicamento/s`, `Tratamiento/s`, `Vacunas`, `Próx. revisión`, `Centro médico de ref.`, `Médico de cabecera`) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (tuple(row_decrypted)))
        connection.commit()

connection.close()

while True:
    new_master_key = str(input("\nIntroduce una nueva contraseña maestra: "))
    confirmed_new_master_key = str(input("Confirme esta nueva contraseña maestra: "))
    if new_master_key == confirmed_new_master_key:
        break
    
    print("Error: Las contraseñas no coinciden. Por favor, inténtalo de nuevo.")

salt = os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)

symmetrical_new_master_key = base64.urlsafe_b64encode(kdf.derive(new_master_key.encode()))

t = Fernet(symmetrical_new_master_key)

pem_server_private_key_encrypted = t.encrypt(decrypted_pem_server_private_key.encode())
pem_server_public_key_encrypted = t.encrypt(decrypted_pem_server_public_key.encode())

sender_pass_encrypted = t.encrypt(decrypted_sender_pass.encode())

host_encrypted = t.encrypt(decrypted_host.encode())
user_encrypted = t.encrypt(decrypted_user.encode())
password_encrypted = t.encrypt(decrypted_password.encode())
database_encrypted = t.encrypt(decrypted_database.encode())

server_credentials_dict = {"pem_server_private_key": pem_server_private_key_encrypted.decode(), "pem_server_public_key": pem_server_public_key_encrypted.decode(), "sender_pass": sender_pass_encrypted.decode(), "host": host_encrypted.decode(), "user": user_encrypted.decode(), "password": password_encrypted.decode(), "database": database_encrypted.decode(), "salt": str(salt.hex())}

server_credentials = json.dumps(server_credentials_dict, indent=2)

with open("../JsonFiles/server_credentials.json", "w") as file:
    file.write(server_credentials)

connection = pymysql.connect(host=decrypted_host, user=decrypted_user, password=decrypted_password, database=decrypted_database)
cursor = connection.cursor()
cursor.execute("SELECT * FROM PATIENTS")
rows = cursor.fetchall()

for row in rows:

    DNI = str(row[2])
    
    row_encrypted = ([t.encrypt(str(attribute).encode()).decode() for attribute in row])
   
    cursor.execute("DELETE FROM PATIENTS WHERE `DNI`=%s", DNI)

    cursor.execute("INSERT INTO PATIENTS (`Estado del reg.`, `CIPA`, `DNI`, `Nombre`, `Apellidos`, `Sexo`, `Edad`, `Teléfono`, `Email`, `Dirección`, `Grupo sanguíneo`, `Patología/s`, `Medicamento/s`, `Tratamiento/s`, `Vacunas`, `Próx. revisión`, `Centro médico de ref.`, `Médico de cabecera`) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (tuple(row_encrypted)))
    connection.commit()        

connection.close()

print("\nLas credenciales del sistema se han cifrado y guardado correctamente con la nueva clave maestra.")
