import flet as ft
import file_encryption
import time

# functions
def clear_fields():
    t_key_output.value = ""
    t_IV_output.value = ""
    t_key_input.value = ""
    t_IV_input.value = ""
    t_selected_encrypt.value = ""
    t_selected_decrypt.value = ""

def get_page(page):
    global page_var
    page_var = page
    page_var.overlay.append(dlg_pick_file_encrypt)
    page_var.overlay.append(dlg_pick_file_decrypt)
    page_var.overlay.append(dlg_encrypt_load)
    page_var.overlay.append(dlg_decrypt_load)
    page_var.overlay.append(dlg_export_key)
    page_var.overlay.append(dlg_import_key)
    page_var.overlay.append(dlg_errors_encryption)
    page_var.overlay.append(dlg_errors_decryption)

def get_file(e: ft.FilePickerResultEvent, action):
    if e.files:
        if action == "encryption":
            global file_path
            file_path = e.files[0].path
            t_selected_encrypt.value = file_path
            t_selected_encrypt.update()
        elif action == "decryption":
            file_path = e.files[0].path
            t_selected_decrypt.value = file_path
            t_selected_decrypt.update()
        elif action == "import_key":
            with open(e.files[0].path, "r") as file:
                t_key_input.value = file.read(64)
                t_IV_input.value = file.read(32)
            page_var.update()
    else:
        "Cancelled"

def encrypt():
    if file_path is not None:
        open_dlg_encrypt_load()
        time.sleep(0.5)
        page_var.update()
        file_encryption.encrypt_file(file_path)
        t_key_output.value = file_encryption.key_val
        t_IV_output.value = file_encryption.IV_val
        dlg_encrypt_load.open = False
        page_var.update()
    else:
        open_errors_encryption()

def decrypt():
    if file_path is not None and len(t_key_input.value) == 64 and len(t_IV_input.value) == 32:
        open_dlg_decrypt_load()
        time.sleep(0.5)
        page_var.update()
        file_encryption.decrypt_file(file_path, t_key_input.value, t_IV_input.value)
        dlg_decrypt_load.open = False
        page_var.update()
    else:
        open_errors_decryption()

def open_dlg_encrypt_load(e=None):
    page_var.dialogue = dlg_encrypt_load
    dlg_encrypt_load.open = True
    page_var.update()

def open_dlg_decrypt_load(e=None):
    page_var.dialogue = dlg_decrypt_load
    dlg_decrypt_load.open = True
    page_var.update()

def export_key(e: ft.FilePickerResultEvent):
    save_location = e.path
    if save_location:
        try:
            with open(save_location, "w") as file:
                file.write(f"{t_key_output.value}{t_IV_output.value}")
        except Exception as e:
            print("Error", e)
    page_var.update()

def open_errors_encryption(e=None):
    dlg_errors_encryption.content = ft.Text("No file is selected.")
    page_var.dialog = dlg_errors_encryption
    dlg_errors_encryption.open = True
    page_var.update()

def open_errors_decryption(e=None):
    if file_path is None:
        dlg_errors_encryption.content = ft.Text("No file is selected.")
    elif len(t_key_input.value) != 64:
        dlg_errors_encryption.content = ft.Text("Invalid decryption key.")
    elif len(t_IV_input.value) != 32:
        dlg_errors_encryption.content = ft.Text("Invalid IV.")
    page_var.dialog = dlg_errors_encryption
    dlg_errors_encryption.open = True
    page_var.update()

# variables
file_path = None
page_var = None

# buttons
b_select_files_encrypt = ft.ElevatedButton(
    "Select File",
    on_click=lambda _: dlg_pick_file_encrypt.pick_files()
)
b_select_files_decrypt = ft.ElevatedButton(
    "Select File",
    on_click=lambda _: dlg_pick_file_decrypt.pick_files()
)
b_encrypt_files = ft.ElevatedButton(
    "Encrypt File",
    on_click=lambda _: encrypt()
)
b_decrypt_files = ft.ElevatedButton(
    "Decrypt File",
    on_click=lambda _: decrypt()
)
b_export_key = ft.ElevatedButton(
    "Export Key",
    on_click=lambda _: dlg_export_key.save_file()
)
b_import_key = ft.ElevatedButton(
    "Import Key",
    on_click=lambda _: dlg_import_key.pick_files()
)

# text fields
t_key_output = ft.TextField(
    label="Encryption Key", read_only=True
)
t_IV_output = ft.TextField(
    label="IV", read_only=True
)
t_key_input = ft.TextField(
    label="Encryption Key"
)
t_IV_input = ft.TextField(
    label="IV"
)
t_selected_encrypt = ft.Text("")
t_selected_decrypt = ft.Text("")

# dialogue
dlg_pick_file_encrypt = ft.FilePicker(on_result=lambda e: get_file(e, "encryption"))
dlg_pick_file_decrypt = ft.FilePicker(on_result=lambda e: get_file(e, "decryption"))
dlg_export_key = ft.FilePicker(on_result=export_key)
dlg_import_key = ft.FilePicker(on_result=lambda e: get_file(e, "import_key"))
dlg_encrypt_load = ft.AlertDialog(
    title=ft.Text("Encrypting"),
    content=ft.ProgressRing(width=16, height=16, stroke_width=2)
)
dlg_decrypt_load = ft.AlertDialog(
    title=ft.Text("Decrypting"),
    content=ft.ProgressRing(width=16, height=16, stroke_width=2)
)
dlg_errors_encryption = ft.AlertDialog(
    title=ft.Text("Error")
)
dlg_errors_decryption = ft.AlertDialog(
    title=ft.Text("Error")
)


def file_page(router):
    content = ft.Column([
        ft.Row([
            ft.Text("Encryption", size=40)
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            b_select_files_encrypt, t_selected_encrypt, b_encrypt_files,
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            t_key_output, t_IV_output, b_export_key
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Container(padding=40),
        ft.Row([
            ft.Text("Decryption", size=40)
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            b_select_files_decrypt, t_selected_decrypt, b_decrypt_files
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            t_key_input, t_IV_input, b_import_key
        ], alignment=ft.MainAxisAlignment.CENTER)
    ])

    return content