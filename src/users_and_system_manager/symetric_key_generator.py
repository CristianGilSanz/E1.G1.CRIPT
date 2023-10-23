from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import json

#--------------PEER KEYS--------------#
peer_private_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
)

peer_public_key = peer_private_key.public_key()

pem_peer_private_key = peer_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

pem_peer_public_key = peer_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

DNI = str(input("Introduce el DNI del empleado: "))

with open("../JsonFiles/signup_users_credentials.json", "r") as file:
    signup_users_credentials = json.load(file)

new_user_account = {"DNI": DNI, "public_key": pem_peer_public_key.decode()}

signup_users_credentials.append(new_user_account)

updated_signup_users_credentials = json.dumps(signup_users_credentials, indent=2) 

with open("../JsonFiles/signup_users_credentials.json", "w") as file:
    file.write(updated_signup_users_credentials)
    
print("\n##############    ----- PEER PRIVADA -----    ##############\n")
print(pem_peer_private_key.decode())

print("\n##############    ----- PEER PÚBLICA -----    ##############\n")
print(pem_peer_public_key.decode())











