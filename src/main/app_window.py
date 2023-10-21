from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkcalendar import DateEntry

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

import json
import re

import pymysql

class HospitalManagementSystem:
    def __init__(self, master):
        self.master = master
        self.master.title("Gestor de Hospital")
        self.master.geometry("1525x850")

        self.server_connection_window()

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
                
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt= bytes.fromhex(server_credentials["salt"]),
                iterations=480000,
            )
                                    
            self.symmetrical_master_key = base64.urlsafe_b64encode(kdf.derive((self.entry_server_password.get()).encode()))
            f = Fernet(self.symmetrical_master_key)

            self.decrypted_host = (f.decrypt(server_credentials["host"].encode())).decode()
            self.decrypted_user = (f.decrypt(server_credentials["user"].encode())).decode()
            self.decrypted_password = (f.decrypt(server_credentials["password"].encode())).decode()
            self.decrypted_database = (f.decrypt(server_credentials["database"].encode())).decode()

            self.connection_window.destroy()
            self.create_widgets()
                    
        except:
            messagebox.showerror("Conexión con el servidor", "Acceso denegado.")
            return
    
    def create_widgets(self):
        self.master.attributes('-topmost', True)

        self.title = Label(self.master, text="Centro de Salud: CryptoShield", bd=8, relief= GROOVE, font=("Arial",40,"bold"), bg="white", fg="black")
        self.title.pack(side=TOP, fill= X, padx=20, pady=10)

        self.Manage_Frame=Frame(self.master, bd=4, relief= RIDGE, bg="white")
        self.Manage_Frame.place(x=20, y=100, width=605, height=720)

        self.manage_title = Label(self.Manage_Frame, text="Gestor de Pacientes", font=("Arial",40,"bold"))
        self.manage_title.grid(row= 0, columnspan=7, pady=20)

        self.label_CIPA = Label(self.Manage_Frame, text="CIPA", font=("Arial",15,"bold"))
        self.label_CIPA.grid(row=1, column=0, pady=10, padx=10, sticky="w")
        self.entry_CIPA = Entry(self.Manage_Frame, width= 10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_CIPA.grid(row=1, column=1, pady=10, sticky="w")

        self.label_DNI = Label(self.Manage_Frame, text="DNI", font=("Arial",15,"bold"))
        self.label_DNI.grid(row=2, column=0, pady=10, padx=10, sticky="w")
        self.entry_DNI = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_DNI.grid(row=2, column=1, pady=10, sticky="w")

        self.label_name = Label(self.Manage_Frame, text="Nombre", font=("Arial",15,"bold"))
        self.label_name.grid(row=3, column=0, pady=10, padx=10, sticky="w")
        self.entry_name = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_name.grid(row=3, column=1, pady=10, sticky="w")

        self.label_surnames = Label(self.Manage_Frame, text="Apellidos", font=("Arial",15,"bold"))
        self.label_surnames.grid(row=4, column=0, pady=10, padx=10, sticky="w")
        self.entry_surnames = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_surnames.grid(row=4, column=1, pady=10, sticky="w")

        self.label_gender = Label(self.Manage_Frame, text="Sexo", font=("Arial",15,"bold"))
        self.label_gender.grid(row=5, column=0, pady=10, padx=10, sticky="w")
        self.entry_gender = ttk.Combobox(self.Manage_Frame, width=9, font=("Courier",15,"bold"), state="readonly")
        self.entry_gender["values"]=("Masculino", "Femenino", "Otro")
        self.entry_gender.grid(row=5, column=1, pady=10, sticky="w")

        self.label_age = Label(self.Manage_Frame, text="Edad", font=("Arial",15,"bold"))
        self.label_age.grid(row=6, column=0, pady=10, padx=10, sticky="w")
        self.entry_age = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_age.grid(row=6, column=1, pady=10, sticky="w")

        self.label_phone = Label(self.Manage_Frame, text="Teléfono", font=("Arial",15,"bold"))
        self.label_phone.grid(row=7, column=0, pady=10, padx=10, sticky="w")
        self.entry_phone = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_phone.grid(row=7, column=1, pady=10, sticky="w")

        self.label_email = Label(self.Manage_Frame, text="Email", font=("Arial",15,"bold"))
        self.label_email.grid(row=8, column=0, pady=10, padx=10, sticky="w")
        self.entry_email = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_email.grid(row=8, column=1, pady=10, sticky="w")

        self.label_address = Label(self.Manage_Frame, text="Dirección", font=("Arial",15,"bold"))
        self.label_address.grid(row=9, column=0, pady=10, padx=10, sticky="w")
        self.entry_address = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_address.grid(row=9, column=1, pady=10, sticky="w")
    
        self.label_blood_type = Label(self.Manage_Frame, text="Grupo sanguíneo", font=("Arial",15,"bold"))
        self.label_blood_type.grid(row=1, column=3, pady=10, padx=15, sticky="w")
        self.entry_blood_type = ttk.Combobox(self.Manage_Frame, width=9, font=("Courier",15,"bold"), state="readonly")
        self.entry_blood_type["values"]=("A+","A-","B+","B-","AB+","AB-","O+","O-")
        self.entry_blood_type.grid(row=1, column=4, pady=10, sticky="w")

        self.label_health_problems = Label(self.Manage_Frame, text="Patología/s", font=("Arial",15,"bold"))
        self.label_health_problems.grid(row=2, column=3, pady=10, padx=15, sticky="w")
        self.entry_health_problems = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_health_problems.grid(row=2, column=4, pady=10, sticky="w")

        self.label_medicines = Label(self.Manage_Frame, text="Medicamento/s", font=("Arial",15,"bold"))
        self.label_medicines.grid(row=3, column=3, pady=10, padx=15, sticky="w")
        self.entry_medicines = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_medicines.grid(row=3, column=4, pady=10, sticky="w")

        self.label_treatments = Label(self.Manage_Frame, text="Tratamiento/s", font=("Arial",15,"bold"))
        self.label_treatments.grid(row=4, column=3, pady=10, padx=15, sticky="w")
        self.entry_treatments = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_treatments.grid(row=4, column=4, pady=10, sticky="w")

        self.label_vaccines = Label(self.Manage_Frame, text="Vacunas", font=("Arial",15,"bold"))
        self.label_vaccines.grid(row=5, column=3, pady=10, padx=15, sticky="w")
        self.entry_vaccines = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_vaccines.grid(row=5, column=4, pady=10, sticky="w")

        self.label_next_check_up = Label(self.Manage_Frame, text="Próx. revisión", font=("Arial",15,"bold"))
        self.label_next_check_up.grid(row=6, column=3, pady=10, padx=15, sticky="w")
        self.entry_next_check_up = DateEntry(self.Manage_Frame, date_pattern='dd/mm/yyyy', width=18)
        self.entry_next_check_up.grid(row=6, column=4, pady=10, sticky="w")

        self.label_ref_medical_center = Label(self.Manage_Frame, text="Centro médico de ref. ", font=("Arial",10,"bold"))
        self.label_ref_medical_center.grid(row=7, column=3, pady=10, padx=10, sticky="w")
        self.entry_ref_medical_center = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_ref_medical_center.grid(row=7, column=4, pady=10, sticky="w")

        self.label_main_doctor = Label(self.Manage_Frame, text="Médico de cabecera", font=("Arial",10,"bold"))
        self.label_main_doctor.grid(row=8, column=3, pady=10, padx=10, sticky="w")
        self.entry_main_doctor = Entry(self.Manage_Frame, width=10, font=("Courier",15,"bold"), bd=5, relief= GROOVE)
        self.entry_main_doctor.grid(row=8, column=4, pady=10, sticky="w")

        self.Button_Frame = Frame(self.Manage_Frame, bd=4, relief= RIDGE, bg="white")
        self.Button_Frame.place(x=10, y=620, width=575,)

        self.button_add = Button(self.Button_Frame, text= "Añadir", width=10, command=self.add_patient).grid(row=0, column=0, padx=30, pady=20)
        self.button_update = Button(self.Button_Frame, text= "Actualizar", width=10, command=self.update_data).grid(row=0, column=1, padx=30, pady=20)
        self.button_delete = Button(self.Button_Frame, text= "Eliminar", width=10, command=self.delete_data).grid(row=0, column=2, padx=30, pady=20)
        self.button_clear = Button(self.Button_Frame, text= "Vaciar", width=10, command=self.clear).grid(row=0, column=3, padx=30, pady=20)

        self.Detail_Frame=Frame(self.master, bd=4, relief= RIDGE, bg="white")
        self.Detail_Frame.place(x=635, y=100, width=870, height=720)

        self.label_filter = Label(self.Detail_Frame, text ="Filtrar por")
        self.label_filter.grid(row=0, column=0, pady= 0, padx=10, sticky="w")

        self.entry_criteria= ttk.Combobox(self.Detail_Frame, width=10, state="readonly")
        self.entry_criteria["values"] = ("CIPA", "DNI")
        self.entry_criteria.grid(row=0, column=1, pady=0, padx=10)

        self.entry_filter_text= Entry(self.Detail_Frame, width=20, bd=3, relief=GROOVE)
        self.entry_filter_text.grid(row=0, column=2, pady= 0, padx= 20, sticky ="w")

        self.button_filter_by= Button(self.Detail_Frame, text= "Filtrar", width =20, command=self.filter_patients).grid(row=0, column=3, padx=20, pady=10)
        self.button_show_all= Button(self.Detail_Frame, text= "Mostrar todos", width=20, command=self.fetch_data).grid(row=0, column=4, padx=20, pady=10)

        self.Table_Frame= Frame(self.Detail_Frame, bd=4, relief= RIDGE)
        self.Table_Frame.place(x=10, y=60, width=840, height=640)

        self.scroll_x= Scrollbar(self.Table_Frame, orient= HORIZONTAL)
        self.scroll_y= Scrollbar(self.Table_Frame, orient= VERTICAL)
        
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

    def add_patient(self):

        patient_info_status = "Verificado"

        if not self.validate_data():
            return
        
        if self.entry_DNI.get() in self.encrypted_CIPAs.keys():
            messagebox.showerror("Registro de paciente", "El paciente ya está registrado.")
            return
        
        if self.entry_CIPA.get() in self.encrypted_DNIs.keys():
            messagebox.showerror("Registro de paciente", "El paciente ya esta registrado.")
            return

        try:
            connection = pymysql.connect(host=self.decrypted_host, user=self.decrypted_user, password=self.decrypted_password, database=self.decrypted_database)
            cursor = connection.cursor()

            f = Fernet(self.symmetrical_master_key)
            
            cursor.execute("INSERT INTO PATIENTS VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(f.encrypt(patient_info_status.encode()).decode(), f.encrypt(self.entry_CIPA.get().encode()).decode(), f.encrypt(self.entry_DNI.get().encode()).decode(), f.encrypt(self.entry_name.get().encode()).decode(), f.encrypt(self.entry_surnames.get().encode()).decode(), f.encrypt(self.entry_gender.get().encode()).decode(), f.encrypt(self.entry_age.get().encode()).decode(), f.encrypt(self.entry_phone.get().encode()).decode(), f.encrypt(self.entry_email.get().encode()).decode(), f.encrypt(self.entry_address.get().encode()).decode(), f.encrypt(self.entry_blood_type.get().encode()).decode(), f.encrypt(self.entry_health_problems.get().encode()).decode(), f.encrypt(self.entry_medicines.get().encode()).decode(), f.encrypt(self.entry_treatments.get().encode()).decode(), f.encrypt(self.entry_vaccines.get().encode()).decode(), f.encrypt(self.entry_next_check_up.get().encode()).decode(), f.encrypt(self.entry_ref_medical_center.get().encode()).decode(), f.encrypt(self.entry_main_doctor.get().encode()).decode()))

            connection.commit()
            connection.close()

        except:
            messagebox.showerror("Error de registro de paciente", "Las credenciales del nuevo paciente no son consistentes.")
            return

        self.clear()

        self.fetch_data()

        messagebox.showinfo("Registro de paciente", "El paciente ha sido añadido con éxito.")

    def fetch_data(self):
        connection = pymysql.connect(host=self.decrypted_host, user=self.decrypted_user, password=self.decrypted_password, database=self.decrypted_database)
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM PATIENTS")
        rows = cursor.fetchall()

        f = Fernet(self.symmetrical_master_key)

        rows_decrypted = []
        
        self.encrypted_DNIs = {}
        self.encrypted_CIPAs = {}

        for row in rows:
            list_row = list(row)

            row_decrypted = []

            for attribute in row:
                try:
                    decrypted_attribute = f.decrypt(str(attribute).encode()).decode()
                except:
                    decrypted_attribute = "Corrupto"
                row_decrypted.append(decrypted_attribute)

            self.encrypted_DNIs[str(row_decrypted[1])]=list_row[2]
            self.encrypted_CIPAs[str(row_decrypted[2])]=list_row[1]
            
            rows_decrypted.append(row_decrypted)   

        if len(rows_decrypted) >= 0:
            self.treeview_patients.delete(*self.treeview_patients.get_children())
            for row in rows_decrypted:
                self.treeview_patients.insert("",END, value=row)

            connection.commit()

        connection.close()

        self.clear()
        
    def clear(self):
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

    def get_cursor(self, ev):
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

    def update_data(self):
        if not self.validate_data():
            return

        f = Fernet(self.symmetrical_master_key)

        try:
            #Si el CIPA no esta en el diccionario salta error
            current_DNI = self.encrypted_DNIs[self.entry_CIPA.get()]
            #Si el DNI no está en ningun diccionario
            current_CIPA = self.encrypted_CIPAs[self.entry_DNI.get()]
        except:
            messagebox.showerror("Registro de paciente", "El paciente que trata de actualizar no es consistente.\n\nCIPA y DNI no son modificables")
            return
        
        patient_info_status = "Verificado"

        connection = pymysql.connect(host=self.decrypted_host, user=self.decrypted_user, password=self.decrypted_password, database=self.decrypted_database)
        cursor = connection.cursor()

        cursor.execute("UPDATE PATIENTS SET `Estado del reg.`=%s, `CIPA`=%s, `Nombre`=%s, `Apellidos`=%s, `Sexo`=%s, `Edad`=%s, `Teléfono`=%s, `Email`=%s, `Dirección`=%s, `Grupo sanguíneo`=%s, `Patología/s`=%s, `Medicamento/s`=%s, `Tratamiento/s`=%s, `Vacunas`=%s, `Próx. revisión`=%s, `Centro médico de ref.`=%s, `Médico de cabecera`=%s where `DNI`=%s",(f.encrypt(patient_info_status.encode()).decode(), f.encrypt(self.entry_CIPA.get().encode()).decode(), f.encrypt(self.entry_name.get().encode()).decode(), f.encrypt(self.entry_surnames.get().encode()).decode(), f.encrypt(self.entry_gender.get().encode()).decode(), f.encrypt(self.entry_age.get().encode()).decode(), f.encrypt(self.entry_phone.get().encode()).decode(), f.encrypt(self.entry_email.get().encode()).decode(), f.encrypt(self.entry_address.get().encode()).decode(), f.encrypt(self.entry_blood_type.get().encode()).decode(), f.encrypt(self.entry_health_problems.get().encode()).decode(), f.encrypt(self.entry_medicines.get().encode()).decode(), f.encrypt(self.entry_treatments.get().encode()).decode(), f.encrypt(self.entry_vaccines.get().encode()).decode(), f.encrypt(self.entry_next_check_up.get().encode()).decode(), f.encrypt(self.entry_ref_medical_center.get().encode()).decode(), f.encrypt(self.entry_main_doctor.get().encode()).decode(), current_DNI))

        connection.commit()
        
        self.fetch_data()

        self.clear()
            
        connection.close()

        messagebox.showinfo("Registro de paciente", "El paciente ha sido actualizado con éxito.")
            
    
    def delete_data(self):
        current_DNI = self.encrypted_DNIs[self.entry_CIPA.get()]

        connection = pymysql.connect(host=self.decrypted_host, user=self.decrypted_user, password=self.decrypted_password, database=self.decrypted_database)
        cursor = connection.cursor()
        
        cursor.execute("DELETE FROM PATIENTS WHERE `DNI`=%s", current_DNI)

        connection.commit()

        self.fetch_data()

        self.clear()

        connection.close()

        messagebox.showinfo("Registro de paciente", "El paciente ha sido eliminado con éxito.")
    
    def validate_data(self):
        regex_CIPA = r"^\d{11}$"
        regex_DNI = r"^\d{8}[A-HJ-NP-TV-Z]$"
        regex_name = r"^[A-ZÁÉÍÓÚÜ][a-záéíóúü]+(?: [A-ZÁÉÍÓÚÜ][a-záéíóúü]+)?$"
        regex_surnames = r"^[A-ZÁÉÍÓÚÜ][a-záéíóúü]+(?: [A-ZÁÉÍÓÚÜ][a-záéíóúü]+)?$"
        regex_gender = r"^(Masculino|Femenino|Otro)$"
        regex_age = r"^(?:[0-9]|[1-9][0-9]|1[0-4][0-9])$|150$"
        regex_phone = r"^(?:\+34|0034|34)?[6789]\d{8}$"
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
                messagebox.showerror("Registro de paciente", f"El campo, {field_name}, no cumple con la expresión esperada.")
                return False
        
        return True

    def filter_patients(self):
        try:
            if self.entry_criteria.get() == "CIPA":
                column = "DNI"
                value = self.encrypted_DNIs[self.entry_filter_text.get()]
                print(value)

            elif self.entry_criteria.get() == "DNI":
                column = "CIPA"
                value = self.encrypted_CIPAs[self.entry_filter_text.get()]
                print(value)
                print(column)

            else:
                messagebox.showerror("Error de filtrado", "Filtre por un campo válido de los proporcionados.")
                return
        except:
            messagebox.showerror("Error de filtrado", "El " + str(self.entry_criteria.get()) + " introducido no se encuentra registrado.")
            return

        connection = pymysql.connect(host=self.decrypted_host, user=self.decrypted_user, password=self.decrypted_password, database=self.decrypted_database)
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM PATIENTS WHERE {} = %s".format(column), (value,))

        rows = cursor.fetchall()

        f = Fernet(self.symmetrical_master_key)

        rows_decrypted = []

        for row in rows:
            row_decrypted = []

            for attribute in row:
                try:
                    decrypted_attribute = f.decrypt(str(attribute).encode()).decode()
                except:
                    decrypted_attribute = "Corrupto"
                row_decrypted.append(decrypted_attribute)

            rows_decrypted.append(row_decrypted)

        print(rows_decrypted)
        if len(rows_decrypted) >= 0:
            self.treeview_patients.delete(*self.treeview_patients.get_children())
            for row in rows_decrypted:
                self.treeview_patients.insert("", END, value=row)

            connection.commit()

        connection.close()

        self.clear()

        self.entry_criteria.delete(0, END)
        self.entry_filter_text.delete(0, END)