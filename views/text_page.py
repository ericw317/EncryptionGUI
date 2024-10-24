import flet as ft
import text_encryption
import time

# functions
def clear_fields():
    t_key_output.value = ""
    t_IV_output.value = ""
    t_key_input.value = ""
    t_IV_input.value = ""
    t_plaintext_encrypt.value = ""
    t_ciphertext_encrypt.value = ""
    t_plaintext_decrypt.value = ""
    t_ciphertext_decrypt.value = ""

def get_page(page):
    global page_var
    page_var = page
    page.overlay.append(dlg_export_key)
    page.overlay.append(dlg_import_key)

def encrypt():
    if t_plaintext_encrypt.value != "":
        text_encryption.encrypt(t_plaintext_encrypt.value)
        t_ciphertext_encrypt.value = text_encryption.ciphertext_encrypt_val
        t_key_output.value = text_encryption.key_val
        t_IV_output.value = text_encryption.IV_val
        t_ciphertext_encrypt.update()
        page_var.update()

def decrypt():
    if t_ciphertext_decrypt.value is not None:
        text_encryption.decrypt(t_ciphertext_decrypt.value, t_key_input.value, t_IV_input.value)
        t_plaintext_decrypt.value = text_encryption.plaintext_val
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

def import_key(e: ft.FilePickerResultEvent):
    if e.files:
        with open(e.files[0].path, "r") as file:
            t_key_input.value = file.read(64)
            t_IV_input.value = file.read(32)
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
b_encrypt_text = ft.ElevatedButton(
    "Encrypt Text",
    on_click=lambda _: encrypt()
)
b_decrypt_text = ft.ElevatedButton(
    "Decrypt Text",
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
t_plaintext_encrypt = ft.TextField(
    label="Plaintext"
)
t_ciphertext_encrypt = ft.TextField(
    label="Ciphertext", read_only=True
)
t_plaintext_decrypt = ft.TextField(
    label="Plaintext", read_only=True
)
t_ciphertext_decrypt = ft.TextField(
    label="Ciphertext"
)

# dialogue
dlg_export_key = ft.FilePicker(on_result=export_key)
dlg_import_key = ft.FilePicker(on_result=import_key)
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


def text_page(router):
    content = ft.Column([
        ft.Row([
            ft.Text("Encryption", size=40)
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            b_encrypt_text
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            t_plaintext_encrypt, t_ciphertext_encrypt
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            ft.Text(" " * 29), t_key_output, t_IV_output, b_export_key
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Container(padding=40),
        ft.Row([
            ft.Text("Decryption", size=40)
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            b_decrypt_text
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            t_ciphertext_decrypt, t_plaintext_decrypt
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            ft.Text(" " * 29), t_key_input, t_IV_input, b_import_key
        ], alignment=ft.MainAxisAlignment.CENTER),
    ])

    return content