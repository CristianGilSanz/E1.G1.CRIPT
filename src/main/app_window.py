from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkcalendar import DateEntry

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

import base64

import json
import re


class HospitalManagementSystem:
    def __init__(self, master, current_user, current_user_password, user_cert):
        self.master = master
        self.master.title("Gestor de Hospital")
        self.master.geometry("1525x850")

        self.current_user = current_user
        self.current_user_password = current_user_password
        self.user_cert = user_cert

        self.server_connection_window()  #Función que crea una ventana de bloqueo previa de acceso al sistema
                                         #que solicita la clave maestra de acceso al servidor (base de datos MySQL)

    def server_connection_window(self):
        self.connection_window = Toplevel(self.master)
        self.connection_window.title("Conexión al servidor")
        self.connection_window.geometry("400x300")

        self.label_server_password = Label(self.connection_window, text="Ingresa la clave:")
        self.label_server_password.pack(pady=20)

        self.entry_server_password = Entry(self.connection_window, show="*")
        self.entry_server_password.pack(pady=10)

        self.button_connect_to_server = Button(self.connection_window, text="Conectar con el servidor", command=self.check_server_password)
        self.button_connect_to_server.pack(pady=20)

        self.connection_window.attributes('-topmost', True)
        
    def check_server_password(self):

        with open("../JsonFiles/server_credentials.json", "r") as file:
            server_credentials = json.load(file)

        try:
            #Generamos la clave simétrica de cifrado a partir del SALT público almacenado y la contraseña de acceso al
            #servidor introducida por el usuario.
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt= bytes.fromhex(server_credentials["salt"]),
                iterations=480000,
            )
                                    
            self.symmetrical_master_key = base64.urlsafe_b64encode(kdf.derive((self.entry_server_password.get()).encode()))
            f = Fernet(self.symmetrical_master_key)

            self.decrypted_sender_pass = (f.decrypt(server_credentials["sender_pass"].encode())).decode()


        #Si la clave es incorrecta, se denega el acceso al servidor
        except:
            messagebox.showerror("Conexión con el servidor", "Acceso denegado.")
            return

        self.connection_window.destroy()
        self.create_widgets() #Función para crear la interfaz de la ventana de HospitalManagementSystem

    
    def create_widgets(self):
        self.master.attributes('-topmost', True)

        self.title = Label(self.master, text="Centro de Salud: CryptoShield", bd=8, relief=GROOVE, font=("Arial",40,"bold"), bg="white", fg="black")
        self.title.pack(side=TOP, fill= X, padx=20, pady=10)

        self.Manage_Frame=Frame(self.master, bd=4, relief= RIDGE, bg="white")
        self.Manage_Frame.place(x=20, y=100, width=605, height=720)

        self.manage_title = Label(self.Manage_Frame, text="Gestor de Pacientes", font=("Arial",40,"bold"), bg="white")
        self.manage_title.grid(row= 0, columnspan=7, pady=20)

        self.label_CIPA = Label(self.Manage_Frame, text="CIPA", font=("Arial",15,"bold"), bg="white")
        self.label_CIPA.grid(row=1, column=0, pady=10, padx=10, sticky="w")
        self.entry_CIPA = Entry(self.Manage_Frame, width= 10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_CIPA.grid(row=1, column=1, pady=10, sticky="w")

        self.label_DNI = Label(self.Manage_Frame, text="DNI", font=("Arial",15,"bold"), bg="white")
        self.label_DNI.grid(row=2, column=0, pady=10, padx=10, sticky="w")
        self.entry_DNI = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_DNI.grid(row=2, column=1, pady=10, sticky="w")

        self.label_name = Label(self.Manage_Frame, text="Nombre", font=("Arial",15,"bold"), bg="white")
        self.label_name.grid(row=3, column=0, pady=10, padx=10, sticky="w")
        self.entry_name = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_name.grid(row=3, column=1, pady=10, sticky="w")

        self.label_surnames = Label(self.Manage_Frame, text="Apellidos", font=("Arial",15,"bold"), bg="white")
        self.label_surnames.grid(row=4, column=0, pady=10, padx=10, sticky="w")
        self.entry_surnames = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_surnames.grid(row=4, column=1, pady=10, sticky="w")

        self.label_gender = Label(self.Manage_Frame, text="Sexo", font=("Arial",15,"bold"), bg="white")
        self.label_gender.grid(row=5, column=0, pady=10, padx=10, sticky="w")
        self.entry_gender = ttk.Combobox(self.Manage_Frame, width=9, font=("Courier",15,"bold"))
        self.entry_gender["values"]=("Masculino", "Femenino", "Otro")
        self.entry_gender.grid(row=5, column=1, pady=10, sticky="w")

        self.label_age = Label(self.Manage_Frame, text="Edad", font=("Arial",15,"bold"), bg="white")
        self.label_age.grid(row=6, column=0, pady=10, padx=10, sticky="w")
        self.entry_age = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_age.grid(row=6, column=1, pady=10, sticky="w")

        self.label_phone = Label(self.Manage_Frame, text="Teléfono", font=("Arial",15,"bold"), bg="white")
        self.label_phone.grid(row=7, column=0, pady=10, padx=10, sticky="w")
        self.entry_phone = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_phone.grid(row=7, column=1, pady=10, sticky="w")

        self.label_email = Label(self.Manage_Frame, text="Email", font=("Arial",15,"bold"), bg="white")
        self.label_email.grid(row=8, column=0, pady=10, padx=10, sticky="w")
        self.entry_email = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_email.grid(row=8, column=1, pady=10, sticky="w")

        self.label_address = Label(self.Manage_Frame, text="Dirección", font=("Arial",15,"bold"), bg="white")
        self.label_address.grid(row=9, column=0, pady=10, padx=10, sticky="w")
        self.entry_address = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_address.grid(row=9, column=1, pady=10, sticky="w")
    
        self.label_blood_type = Label(self.Manage_Frame, text="Grupo sanguíneo", font=("Arial",15,"bold"), bg="white")
        self.label_blood_type.grid(row=1, column=3, pady=10, padx=15, sticky="w")
        self.entry_blood_type = ttk.Combobox(self.Manage_Frame, width=9, font=("Courier",15,"bold"))
        self.entry_blood_type["values"]=("A+","A-","B+","B-","AB+","AB-","O+","O-")
        self.entry_blood_type.grid(row=1, column=4, pady=10, sticky="w")

        self.label_health_problems = Label(self.Manage_Frame, text="Patología/s", font=("Arial",15,"bold"), bg="white")
        self.label_health_problems.grid(row=2, column=3, pady=10, padx=15, sticky="w")
        self.entry_health_problems = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_health_problems.grid(row=2, column=4, pady=10, sticky="w")

        self.label_medicines = Label(self.Manage_Frame, text="Medicamento/s", font=("Arial",15,"bold"), bg="white")
        self.label_medicines.grid(row=3, column=3, pady=10, padx=15, sticky="w")
        self.entry_medicines = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_medicines.grid(row=3, column=4, pady=10, sticky="w")

        self.label_treatments = Label(self.Manage_Frame, text="Tratamiento/s", font=("Arial",15,"bold"), bg="white")
        self.label_treatments.grid(row=4, column=3, pady=10, padx=15, sticky="w")
        self.entry_treatments = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_treatments.grid(row=4, column=4, pady=10, sticky="w")

        self.label_vaccines = Label(self.Manage_Frame, text="Vacunas", font=("Arial",15,"bold"), bg="white")
        self.label_vaccines.grid(row=5, column=3, pady=10, padx=15, sticky="w")
        self.entry_vaccines = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_vaccines.grid(row=5, column=4, pady=10, sticky="w")

        self.label_next_check_up = Label(self.Manage_Frame, text="Próx. revisión", font=("Arial",15,"bold"), bg="white")
        self.label_next_check_up.grid(row=6, column=3, pady=10, padx=15, sticky="w")
        self.entry_next_check_up = DateEntry(self.Manage_Frame, date_pattern='dd/mm/yyyy', width=18)
        self.entry_next_check_up.grid(row=6, column=4, pady=10, sticky="w")

        self.label_ref_medical_center = Label(self.Manage_Frame, text="Centro médico de ref. ", font=("Arial",10,"bold"), bg="white")
        self.label_ref_medical_center.grid(row=7, column=3, pady=10, padx=10, sticky="w")
        self.entry_ref_medical_center = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_ref_medical_center.grid(row=7, column=4, pady=10, sticky="w")

        self.label_main_doctor = Label(self.Manage_Frame, text="Médico de cabecera", font=("Arial",10,"bold"), bg="white")
        self.label_main_doctor.grid(row=8, column=3, pady=10, padx=10, sticky="w")
        self.entry_main_doctor = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief=GROOVE)
        self.entry_main_doctor.grid(row=8, column=4, pady=10, sticky="w")

        self.Button_Frame = Frame(self.Manage_Frame, bd=4, relief= RIDGE, bg="white")
        self.Button_Frame.place(x=10, y=620, width=575,)

        self.button_add = Button(self.Button_Frame, text="Añadir", width=10, command=self.add_patient).grid(row=0, column=0, padx=30, pady=20)
        self.button_update = Button(self.Button_Frame, text="Actualizar", width=10, command=self.update_data).grid(row=0, column=1, padx=30, pady=20)
        self.button_delete = Button(self.Button_Frame, text="Eliminar", width=10, command=self.delete_data).grid(row=0, column=2, padx=30, pady=20)
        self.button_clear = Button(self.Button_Frame, text="Vaciar", width=10, command=self.clear).grid(row=0, column=3, padx=30, pady=20)

        self.Detail_Frame=Frame(self.master, bd=4, relief=RIDGE, bg="white")
        self.Detail_Frame.place(x=635, y=100, width=870, height=720)

        self.label_filter = Label(self.Detail_Frame, text="Filtrar por", bg="white")
        self.label_filter.grid(row=0, column=0, pady=0, padx=10, sticky="w")

        self.entry_criteria= ttk.Combobox(self.Detail_Frame, width=10)
        self.entry_criteria["values"] = ("CIPA", "DNI")
        self.entry_criteria.grid(row=0, column=1, pady=0, padx=10)

        self.entry_filter_text= Entry(self.Detail_Frame, width=20, bd=3, relief=GROOVE)
        self.entry_filter_text.grid(row=0, column=2, pady= 0, padx=20, sticky="w")

        self.button_filter_by= Button(self.Detail_Frame, text= "Filtrar", width=20, command=self.filter_patients).grid(row=0, column=3, padx=20, pady=10)
        self.button_show_all= Button(self.Detail_Frame, text= "Mostrar todos", width=20, command=self.fetch_data).grid(row=0, column=4, padx=20, pady=10)

        self.Table_Frame= Frame(self.Detail_Frame, bd=4, relief= RIDGE)
        self.Table_Frame.place(x=10, y=60, width=840, height=640)

        self.scroll_x= Scrollbar(self.Table_Frame, orient=HORIZONTAL)
        self.scroll_y= Scrollbar(self.Table_Frame, orient=VERTICAL)
        
        self.treeview_patients= ttk.Treeview(self.Table_Frame, columns=("Estado del reg.","CIPA", "DNI", "Nombre", "Apellidos", "Sexo", "Edad", "Teléfono", "Email", "Dirección", "Grupo sanguíneo", "Patología/s", "Medicamento/s", "Tratamiento/s", "Vacunas", "Próx. revisión", "Centro médico de ref.", "Médico de cabecera"), xscrollcommand=self.scroll_x.set, yscrollcommand=self.scroll_y.set)

        self.scroll_x.pack(side=BOTTOM, fill=X)
        self.scroll_y.pack(side=RIGHT, fill=Y)
        
        self.scroll_x.config(command=self.treeview_patients.xview)
        self.scroll_y.config(command=self.treeview_patients.yview)

        self.treeview_patients.heading("Estado del reg.", text="Estado del reg.")

        self.treeview_patients.heading("CIPA", text="CIPA")
        self.treeview_patients.heading("DNI", text="DNI")
        self.treeview_patients.heading("Nombre", text="Nombre")
        self.treeview_patients.heading("Apellidos", text="Edad")
        self.treeview_patients.heading("Sexo", text="Sexo")
        self.treeview_patients.heading("Edad", text="Edad")
        self.treeview_patients.heading("Teléfono", text="Teléfono")
        self.treeview_patients.heading("Email", text="Email")
        self.treeview_patients.heading("Dirección", text="Dirección")

        self.treeview_patients.heading("Grupo sanguíneo", text="Grupo sanguíneo")
        self.treeview_patients.heading("Patología/s", text="Patología/s")
        self.treeview_patients.heading("Medicamento/s", text="Medicamento/s")
        self.treeview_patients.heading("Tratamiento/s", text="Tratamiento/s")
        self.treeview_patients.heading("Vacunas", text="Vacunas")
        self.treeview_patients.heading("Próx. revisión", text="Próx. revisión")
        self.treeview_patients.heading("Centro médico de ref.", text="Centro médico de ref.")
        self.treeview_patients.heading("Médico de cabecera", text="Médico de cabecera")

        self.treeview_patients["show"]="headings"

        self.treeview_patients.pack(padx=1, pady=1, fill= BOTH, expand=1)

        self.treeview_patients.bind("<ButtonRelease-1>", self.get_cursor)

        self.fetch_data()


    def add_patient(self, update=False):
        #Comprobamos que los datos del paciente son consistentes con el formato
        if not self.validate_data():
            return

        #Consultamos los diccionarios recuperados de la base de datos con pares cifrados y sin cifrar de DNI y CIPA
        #respectivamente (y viceversa) para poder mantener la integridad referencial de la base de datos y consistencia
        #de los pacientes registrados (No insertar pacientes con mismo DNI, cambiar datos inmutables, etc.)
        if self.entry_DNI.get() in self.encrypted_CIPAs.keys():
            messagebox.showerror("Registro de paciente", "El paciente ya está registrado.")
            return
        
        if self.entry_CIPA.get() in self.encrypted_DNIs.keys():
            messagebox.showerror("Registro de paciente", "El paciente ya esta registrado.")
            return

        #Recuperamos de los inputs los datos del paciente
        fields_to_encrypt = [
            self.entry_CIPA.get(),
            self.entry_DNI.get(),
            self.entry_name.get(),
            self.entry_surnames.get(),
            self.entry_gender.get(),
            self.entry_age.get(),
            self.entry_phone.get(),
            self.entry_email.get(),
            self.entry_address.get(),
            self.entry_blood_type.get(),
            self.entry_health_problems.get(),
            self.entry_medicines.get(),
            self.entry_treatments.get(),
            self.entry_vaccines.get(),
            self.entry_next_check_up.get(),
            self.entry_ref_medical_center.get(),
            self.entry_main_doctor.get()
        ]

        #Ciframos en tiempo de ejecución los datos del paciente con la clave de cifrado simétrico con la que
        #recuperamos las credenciales de acceso al servidor para insertar los datos cifrados
        try:

            f = Fernet(self.symmetrical_master_key)

            encrypted_fields = [f.encrypt(field.encode()).decode() for field in fields_to_encrypt]

            private_key_path = f"../AC/USERS_PRIVATE_KEYS/{self.current_user}_PK.pem"

            #Recuperamos la clave privada del usuario para firmar cada paciente que este inserta
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=self.current_user_password.encode(),  #Se ingresa la clave del usuario con la que está protegida su clave privada
                    backend=default_backend()
                )

            #Firmamos la concatenación de los atributos cifrados
            original_message = ''.join(encrypted_fields).encode()

            signed_record = private_key.sign(
                original_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            ) #La firma está en hexadecimal

            #Agregamos al registro dos atributos, la clave pública del firmante y la firma generada sobre los datos
            public_key = self.user_cert.public_key()

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            encrypted_fields.append(public_key_bytes.decode())
            encrypted_fields.append(signed_record.hex())

            #Insertamos el paciente con su información cifrada en la base de datos
            with open("../JsonFiles/patients_data.json", "r") as file:
                patients_data = json.load(file)

            patients_data.append(encrypted_fields)

            updated_patients_data = json.dumps(patients_data, indent=2)

            with open("../JsonFiles/patients_data.json", "w") as file:
                file.write(updated_patients_data)

        except:
            messagebox.showerror("Error de registro de paciente", "Las credenciales del nuevo paciente no son consistentes.")
            return

        self.clear()

        #Refrescamos la vista descifrada de los pacientes
        self.fetch_data()

        if update == False:
            messagebox.showinfo("Registro de paciente", "El paciente ha sido añadido con éxito.")

    def delete_data(self, update=False):
        #Función para borrar un paciente

        try:
            current_DNI = self.encrypted_DNIs[self.entry_CIPA.get()]
        except:
            messagebox.showerror("Error de borrado de paciente", "Coloquesé de nuevo sobre el paciente a borrar.")
            return

        #Borramos el paciente filtrando por su DNI cifrado (clave primaria)
        with open("../JsonFiles/patients_data.json", "r") as file:
            patients_data = json.load(file)

        for row in patients_data:
            if row[1]==current_DNI:
                patients_data.remove(row)

        updated_patients_data = json.dumps(patients_data, indent=2)

        with open("../JsonFiles/patients_data.json", "w") as file:
            file.write(updated_patients_data)

        if update == False:
            #Refrescamos la vista descifrada de los pacientes
            self.fetch_data()

            #Vaciamos los inputs
            self.clear()

            messagebox.showinfo("Borrado de paciente", "El paciente ha sido eliminado con éxito.")

    def update_data(self):
        #Función para actualizar información no inmutable de un paciente
        if not self.validate_data():
            return

        f = Fernet(self.symmetrical_master_key)

        try:
            #Si el CIPA no esta en el diccionario, el paciente no está registrado
            current_DNI = self.encrypted_DNIs[self.entry_CIPA.get()]
            #Si el DNI no está en el diccionario, el paciente no está registrado
            current_CIPA = self.encrypted_CIPAs[self.entry_DNI.get()]
        except:
            messagebox.showerror("Actualización de paciente", "La información del paciente que trata de actualizar es inmutable.\n\nCIPA y DNI no son modificables")
            return


        #Actualizamos el paciente, cifrando de nuevo toda su información, inclusive los datos actualizados
        self.delete_data(True)

        self.encrypted_DNIs = {}
        self.encrypted_CIPAs = {}

        self.add_patient(True)

        #Refrescamos la vista descifrada de los pacientes
        self.fetch_data()

        #Vaciamos los inputs
        self.clear()

        messagebox.showinfo("Registro de paciente", "El paciente ha sido actualizado con éxito.")

    def filter_patients(self):
        #Función para filtrar un paciente por su DNI o CIPA
        try:
            #Analizamos por que campo se esta filtrando y comprobamos si hay algún paciente con ese valor de campo
            if self.entry_criteria.get() == "CIPA":
                value = self.encrypted_DNIs[self.entry_filter_text.get()]

            elif self.entry_criteria.get() == "DNI":
                value = self.encrypted_CIPAs[self.entry_filter_text.get()]

            #Si el campo no existe, es erróneo o vacío, se notifica del error de filtrado
            else:
                messagebox.showerror("Error de filtrado", "Filtre por un campo válido de los proporcionados.")
                return
        #Si no exite el paciente filtrado, se indica por pantalla
        except:
            messagebox.showerror("Error de filtrado", "El " + str(self.entry_criteria.get()) + " introducido no se encuentra registrado.")
            return

        #Se recupera el paciente con dichas características
        with open("../JsonFiles/patients_data.json", "r") as file:
            patients_data = json.load(file)

        f = Fernet(self.symmetrical_master_key)

        patients_decrypted = []

        for row in patients_data:
            row_decrypted = []
            fields_to_decrypt= row[:-2]
            original_message = ''.join(row[:-2]).encode()

            #Se discriminan aquellos pacientes que no coincidan con el CIPA/DNI de filtrado
            if fields_to_decrypt[0] == value or fields_to_decrypt[1] == value:

                for attribute in fields_to_decrypt:
                    try:
                        decrypted_attribute = f.decrypt(str(attribute).encode()).decode()
                    except:
                        decrypted_attribute = "C0RRUPT3D D4T4"

                    row_decrypted.append(decrypted_attribute)

                public_key_bytes = row[-2].encode()
                public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

                signed_record = bytes.fromhex(row[-1])

                try:
                    public_key.verify(
                        signed_record,
                        original_message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    row_decrypted.insert(0, "VALIDADO & VERIFICADO")
                except:
                    row_decrypted.insert(0, "CORRUPTO")

                patients_decrypted.append(row_decrypted)

        #Se insertan los pacientes recuperados con los datos coincidentes al filtro en la vista descifrada del sistema
        if len(patients_decrypted) >= 0:
            self.treeview_patients.delete(*self.treeview_patients.get_children())
            for row in patients_decrypted:
                self.treeview_patients.insert("", END, value=row)

        #Vaciamos los inputs generales
        self.clear()

    def fetch_data(self):
        f = Fernet(self.symmetrical_master_key)

        patients_decrypted = []

        #Declaramos los diccionarios para guardar los pares de DNI y CIPA cifrados y sin cifrar respectivamente
        #(y viceversa) para así poder mantener la integridad referencial de la base de datos y consistencia
        #de los pacientes registrados. asi como la gestión de los mismos
        self.encrypted_DNIs = {}
        self.encrypted_CIPAs = {}

        with open("../JsonFiles/patients_data.json", "r") as file:
            patients_data = json.load(file)

        #Desencriptmos los registros en tiempo de ejecución para insertarlos visualmente descifrados
        for row in patients_data:
            row_decrypted = []
            fields_to_decrypt = row[:-2]
            original_message = ''.join(row[:-2]).encode()

            for attribute in fields_to_decrypt:
                try:
                    decrypted_attribute = f.decrypt(str(attribute).encode()).decode()
                #Si alguno de los datos de un paciente recuperado no puede descifrarse, se etiquta como corrupto. La
                #información validada y autentificada del paciente ha dejado de estarlo por alguna intrusión.
                except:
                    decrypted_attribute = "C0RRUPT3D D4T4"

                row_decrypted.append(decrypted_attribute)

            #Guardamos los DNI y CIPAS cirados y sin cifrar (y viceversa) de cada paciente para manejarlos de forma
            #cifrada en la base de datos
            self.encrypted_DNIs[str(row_decrypted[0])]=row[1]   #CIPA: DNI_encr
            self.encrypted_CIPAs[str(row_decrypted[1])]=row[0]  #DNI: CIPA_encr

            public_key_bytes = row[-2].encode()
            public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

            signed_record = bytes.fromhex(row[-1])

            #Además, vemos si la firma que hay en el registro del paciente se verifica con la concatenación de los datos
            #de este en el momento de recuperarlos, y  a su vez, con la clave pública del que lo firmó con su privada
            try:
                public_key.verify(
                    signed_record,
                    original_message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                row_decrypted.insert(0, "VALIDADO & VERIFICADO")
            except:
                row_decrypted.insert(0, "CORRUPTO")

            patients_decrypted.append(row_decrypted)

        #Insertamos en la vista de la aplicación los datos descifrados
        if len(patients_decrypted) >= 0:
            self.treeview_patients.delete(*self.treeview_patients.get_children())
            for row in patients_decrypted:
                self.treeview_patients.insert("",END, value=row)

        #Vaciamos los inputs
        self.clear()

        #Vaciamos los inputs de filtrado
        self.entry_criteria.delete(0, END)
        self.entry_filter_text.delete(0, END)

    def validate_data(self):
        # Función para validar el formato de los campos de información del paciente a insertar o actualizar
        regex_CIPA = r"^\d{11}$"
        regex_DNI = r"^\d{8}[A-HJ-NP-TV-Z]$"
        regex_name = r"^[A-ZÁÉÍÓÚÜ][a-záéíóúü]+(?: [A-ZÁÉÍÓÚÜ][a-záéíóúü]+)?$"
        regex_surnames = r"^[A-ZÁÉÍÓÚÜ][a-záéíóúü]+(?: [A-ZÁÉÍÓÚÜ][a-záéíóúü]+)?$"
        regex_gender = r"^(Masculino|Femenino|Otro)$"
        regex_age = r"^(?:[0-9]|[1-9][0-9]|1[0-4][0-9])$|150$"
        regex_phone = r"^(?:\+34|0034|34)[6789]\d{8}$"
        regex_email = r"^\S+@\S+\.\S+$"
        regex_address = r"^.+$"
        regex_blood_type = r"^(A\+|A-|B\+|B-|AB\+|AB-|O\+|O-)$"
        regex_health_problems = r"^.+$"
        regex_medicines = r"^.+$"
        regex_treatments = r"^.+$"
        regex_vaccines = r"^.+$"
        regex_next_check_up = r"^(0[1-9]|[12][0-9]|3[01])/(0[1-9]|1[0-2])/\d{4}$"
        regex_ref_medical_center = r"^.+$"
        regex_main_doctor = r"^[A-ZÁÉÍÓÚÜ][a-záéíóúü]+(?: [A-ZÁÉÍÓÚÜ][a-záéíóúü]+)?$"

        fields_to_validate = [
            (self.entry_CIPA.get(), regex_CIPA, "CIPA"),
            (self.entry_DNI.get(), regex_DNI, "DNI"),
            (self.entry_name.get(), regex_name, "Nombre"),
            (self.entry_surnames.get(), regex_surnames, "Apellidos"),
            (self.entry_gender.get(), regex_gender, "Sexo"),
            (self.entry_age.get(), regex_age, "Edad"),
            (self.entry_phone.get(), regex_phone, "Teléfono"),
            (self.entry_email.get(), regex_email, "Email"),
            (self.entry_address.get(), regex_address, "Dirección"),
            (self.entry_blood_type.get(), regex_blood_type, "Grupo sanguíneo"),
            (self.entry_health_problems.get(), regex_health_problems, "Patología/s"),
            (self.entry_medicines.get(), regex_medicines, "Medicamento/s"),
            (self.entry_treatments.get(), regex_treatments, "Tratamiento/s"),
            (self.entry_vaccines.get(), regex_vaccines, "Vacunas"),
            (self.entry_next_check_up.get(), regex_next_check_up, "Próxima revisión"),
            (self.entry_ref_medical_center.get(), regex_ref_medical_center, "Centro médico de ref."),
            (self.entry_main_doctor.get(), regex_main_doctor, "Médico de cabecera")
        ]

        for value, regex, field_name in fields_to_validate:
            if not re.match(regex, value):
                messagebox.showerror("Registro de paciente",
                                     f"El campo, {field_name}, no cumple con la expresión esperada.")
                return False

        return True

    def get_cursor(self, ev):
        #Función para recuperar los datos de información del paciente y que se sobreescriban en los inputs para su
        #manejo
        cursor_row = self.treeview_patients.focus()
        
        if cursor_row:
            contents = self.treeview_patients.item(cursor_row)
            row = contents["values"]

            self.clear()

            self.entry_CIPA.insert(0,row[1])
            self.entry_DNI.insert(0,row[2])
            self.entry_name.insert(0,row[3])
            self.entry_surnames.insert(0,row[4])
            self.entry_gender.insert(0,row[5])
            self.entry_age.insert(0,row[6])
            self.entry_phone.insert(0,row[7])
            self.entry_email.insert(0,row[8])
            self.entry_address.insert(0,row[9])
            self.entry_blood_type.insert(0,row[10])
            self.entry_health_problems.insert(0, row[11])
            self.entry_medicines.insert(0,row[12])
            self.entry_treatments.insert(0,row[13])
            self.entry_vaccines.insert(0, row[14])
            self.entry_next_check_up.insert(0,row[15])
            self.entry_ref_medical_center.insert(0,row[16])
            self.entry_main_doctor.insert(0,row[17])

    def clear(self):
        # Función para vaciar las entradas de datos para registrar o filtrar pacientes en el sistema
        self.entry_CIPA.delete(0, END)
        self.entry_DNI.delete(0, END)
        self.entry_name.delete(0, END)
        self.entry_surnames.delete(0, END)
        self.entry_gender.delete(0, END)
        self.entry_age.delete(0, END)
        self.entry_phone.delete(0, END)
        self.entry_email.delete(0, END)
        self.entry_address.delete(0, END)
        self.entry_blood_type.delete(0, END)
        self.entry_health_problems.delete(0, END)
        self.entry_medicines.delete(0, END)
        self.entry_treatments.delete(0, END)
        self.entry_vaccines.delete(0, END)
        self.entry_next_check_up.delete(0, END)
        self.entry_ref_medical_center.delete(0, END)
        self.entry_main_doctor.delete(0, END)
