from sql_db import create_connection, execute_query, execute_read_query
from queries import (create_details_table, create_user_table,  # delete_james,
                     insert_table_values, insert_user_pass_value,
                     retrieve_detail_data, select_user_pass_value
                     )

import tkinter as tk
import random
import scrypt
import string
import validators
connection = create_connection("app.db")

# Creat tables if they do not exist
execute_query(connection, create_details_table)
execute_query(connection, create_user_table)
# execute_query(connection, delete_james)

password_string = string.ascii_letters + string.digits + string.punctuation
result = execute_read_query(connection, select_user_pass_value)

user_password = "" if result == [] else result[0][0]


class LoginFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.config(width=400, height=400)
        # self.grid(row=0, column=0, sticky="nsew")
        self.pack(fill=tk.BOTH, )
        self.pack_propagate(0)  # Enables the configured height and widht

        self._create_widgets()

    def _create_widgets(self):
        self.label_error = tk.Label(self, text="", fg="red", font=16)
        self.entry_request = tk.Entry(self, width=65)
        if user_password == "":
            self.label_request = tk.Label(
                self, text="Create an entry password", font=16)
            label_info = tk.Label(self,
                                  text="You will need this to login everytime",
                                  fg="green")
            label_info.pack()
            self.btn_request = tk.Button(
                self, text="Create", command=self._create_user_password)
        else:
            self.label_request = tk.Label(self, text="Password", font=16)
            self.btn_request = tk.Button(
                self, text="Log In", command=self._check_pass)

        self.label_request.pack(fill=tk.X, expand=False, pady=10)
        self.label_error.pack(fill=tk.X, expand=False)
        self.entry_request.pack(padx=10, pady=5)
        self.btn_request.pack(ipadx=10, ipady=5, pady=5)

    def _check_pass(self):
        password = self.entry_request.get()
        if password == user_password:
            self.destroy()
            return
        else:
            self.label_error["text"] = "Invalid password"

    def _create_user_password(self):
        password = self.entry_request.get()
        execute_query(connection, insert_user_pass_value, password)
        connection.commit()
        self.destroy()


class PasswordStorageWindow(tk.Frame):
    """
    Frame for Password Storage
    """

    entry_list = []

    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.grid(row=0, column=1, sticky="nsew")
        self._create_widgets()
        self.columnconfigure(1, weight=1)

    def _create_widgets(self):
        self.labels = [
            "URL", "PassChangeURL",
            "SiteName", "Email/Username", "Password"]
        for index, name in enumerate(self.labels):
            label = tk.Label(self, text=name, fg="green")
            entry = tk.Entry(self, )
            label.grid(row=index, column=0, sticky="e",
                       ipadx=5, padx=7, pady=7)
            entry.grid(row=index, column=1, sticky="we",
                       ipadx=5, ipady=8, padx=7, pady=7)
            PasswordStorageWindow.entry_list.append(entry)

        self.label_error = tk.Label(
            self, text="", fg="red", font=16)
        self.btn_submit = tk.Button(self, text="Submit",
                                    command=self._handle_submit)
        length = len(self.labels)
        self.btn_submit.grid(row=length, column=1, sticky="e",
                             ipadx=8, ipady=5, padx=5, pady=8)
        self.label_error.grid(row=length+1, column=0, padx=5, pady=8)

    def _handle_submit(self):
        values = [entry.get() for entry in PasswordStorageWindow.entry_list]
        if not validators.url(values[0]) or (
                not validators.url(values[1]) and values[1] != ""):
            self.label_error["fg"] = "red"
            self.label_error["text"] = "Not a valid URL"
            return
        values[4] = scrypt.encrypt(values[4], "password", maxtime=0.025)
        execute_query(connection, insert_table_values, values)
        connection.commit()
        self.label_error["text"] = "Saved"
        self.label_error["fg"] = "green"
        for i in PasswordStorageWindow.entry_list:
            i.delete(0, tk.END)

    def _auto_change_password():
        pass

    def manual_change_password():
        pass


class MenuFrame(tk.Menu):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self._create_menu()

    def _create_menu(self):
        filemenu = tk.Menu(self, tearoff=0)
        filemenu.add_command(label="New", )
        filemenu.add_command(label="Retrieve", command=retrieve_data_view)
        filemenu.add_command(label="Store", command=store_data_view)
        filemenu.add_command(label="Generate", command=generate_password_view)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=handle_close)
        self.add_cascade(label="File", menu=filemenu)

        editmenu = tk.Menu(self, tearoff=0)
        editmenu.add_command(label="Change password")
        self.add_cascade(label="Edit", menu=editmenu)


class GeneratePasswordWindow(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.grid(row=0, column=1, sticky="nsew")
        self._create_widgets()
        self.columnconfigure([1], weight=1)

    def _create_widgets(self):
        self.label_pass = tk.Label(self, text="Generated Password")
        self.label_warning = tk.Label(self, text="", font=16, fg="red")
        self.entry_pass = tk.Entry(self,)
        self.btn_pass = tk.Button(self, text="Generate password",
                                  command=self._build_password)

        self.label_pass.grid(row=0, column=0)
        self.label_warning.grid(row=1, column=1, sticky="we")
        self.entry_pass.grid(row=0, column=1, ipady=5, pady=5, sticky="we")
        self.btn_pass.grid(row=0, column=2, ipady=5, padx=5, pady=8)

    def _build_password(self):
        password = "".join((random.choice(password_string))
                           for i in range(16))
        warning = '''
        1. Do not use the same password for multiple important accounts.
        2. Use a password that has at least 16 characters, use at least one 
        number,
        one uppercase letter, one lowercase letter and one special symbol.
        '''
        self.label_warning["text"] = warning
        self.entry_pass.delete(0, tk.END)
        self.entry_pass.insert(0, password)


class RetrieveDataWindow(tk.Frame):
    """
    Frame for the retrieving all the data stored
    """

    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.grid(row=0, column=1, sticky="nsew")
        self._create_widgets()
        self.columnconfigure([0, 1], weight=1)

    def _create_widgets(self):
        # For now, retrieve all the data in the db
        # TODO: eliminate gathering of all data, just specifics
        result = execute_read_query(connection, retrieve_detail_data)
        label_sitename = tk.Label(self, text="SITE NAME")
        label_username = tk.Label(self, text="USERNAME")

        label_sitename.grid(row=0, column=0, pady=7)
        label_username.grid(row=0, column=1, pady=7)

        for indx, passUrl, url, sitename, email, password in result:
            entry_one = tk.Entry(self)
            entry_one.insert(0, sitename)

            entry_two = tk.Entry(self)
            entry_two.insert(0, email)

            btn_check = tk.Button(self, text="Check",
                                  command=self.check_password)

            entry_one.grid(row=indx, column=0, sticky="we",
                           padx=5, pady=10, ipady=5)
            entry_two.grid(row=indx, column=1, sticky="we",
                           padx=5, pady=10, ipady=5)
            btn_check.grid(row=indx, column=2, sticky="we",
                           padx=5, pady=10, ipady=5)

    def _check_details_widgets(self):
        self.labels = [
            "URL", "PassChangeURL",
            "SiteName", "Email/Username", "Password"]

    def check_password(self):
        # TODO: Use scrypt to hash password before storing
        pass


class SideOptions(tk.Frame):
    """
    Frame for the side buttons
    """

    def __init__(self, master=None):
        super().__init__(master)
        self.configure(bg="black")
        self.master = master
        self.grid(row=0, column=0, sticky="ns")
        self._create_widgets()
        self.columnconfigure(0, weight=1)

    def _create_widgets(self):
        self.btn_store_new = tk.Button(
            self, text="Store New", command=store_data_view)
        self.btn_close = tk.Button(
            self, text="Close App", fg="red", command=handle_close)
        self.btn_retrieve = tk.Button(
            self, text="Retrieve Pass", command=retrieve_data_view)
        self.btn_generate = tk.Button(
            self, text="Generate Pass", command=generate_password_view)

        self.btn_store_new.grid(row=0, column=0, sticky="ew",
                                ipadx=5, padx=5, pady=5)
        self.btn_retrieve.grid(row=1, column=0, sticky="ew",
                               ipadx=5, padx=5, pady=5)
        self.btn_close.grid(row=3, column=0, sticky="ew",
                            ipadx=5, padx=5, pady=5)
        self.btn_generate.grid(row=2, column=0, sticky="ew",
                               ipadx=5, padx=5, pady=5)


# HANDLERS FOR WINDOW VIEW
def handle_close():
    connection.close()
    window.destroy()


def store_data_view():
    retrieve_data.grid_forget()
    generate_pass.grid_forget()
    storage_frame.grid(row=0, column=1, sticky="nsew")


def retrieve_data_view():
    storage_frame.grid_forget()
    generate_pass.grid_forget()
    retrieve_data.grid(row=0, column=1, sticky="nsew")


def generate_password_view():
    """
    Switch view from existing to generate password view
    """
    storage_frame.grid_forget()
    retrieve_data.grid_forget()
    generate_pass.grid(row=0, column=1, sticky="nsew")


window = tk.Tk()
window.title("Window")

window.rowconfigure(0, weight=1, minsize=600)
window.columnconfigure(1, weight=1, minsize=600)

window.protocol("WM_DELETE_WINDOW", handle_close)


# remove frame frame.grid_forget() or .pack_forget()
menu_bar = MenuFrame(window)
window.config(menu=menu_bar)


login = LoginFrame(window)
try:
    login.wait_window(login)

    storage_frame = PasswordStorageWindow(window)
    side_frame = SideOptions(window)
    generate_pass = GeneratePasswordWindow(window)
    retrieve_data = RetrieveDataWindow(window)
    generate_pass.grid_forget()
    retrieve_data.grid_forget()
except Exception:
    pass


window.mainloop()
