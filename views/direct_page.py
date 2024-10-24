import flet as ft
import directory_encryption
import os
import time

# functions
def clear_fields():
    t_key.value = ""
    t_IV.value = ""
    t_selected_dir.value = ""
    t_selected_file.value = ""
    t_key_input.value = ""
    t_IV_input.value = ""
    page_var.update()

def get_dir(e: ft.FilePickerResultEvent):
    if e.path:
        global dir_path
        dir_path = e.path
        t_selected_dir.value = e.path
        t_selected_dir.update()
    else:
        "Cancelled"

def get_file(e: ft.FilePickerResultEvent):
    if e.files:
        global dir_path
        dir_path = e.files[0].path
        t_selected_file.value = e.files[0].path
        t_selected_file.update()
    else:
        "Cancelled"

def save_file(e: ft.FilePickerResultEvent):
    save_location = e.path
    if save_location:
        try:
            with open(save_location, "w") as file:
                file.write(f"{t_key.value}{t_IV.value}")
        except Exception as e:
            print("Error", e)
    page_var.update()

def get_import(e: ft.FilePickerResultEvent):
    if e.files:
        with open(e.files[0].path, "r") as file:
            key = file.read(64)
            iv = file.read(32)
        t_key_input.value = key
        t_IV_input.value = iv
        page_var.update()

def get_page(page):
    global page_var
    page_var = page
    page_var.overlay.append(dlg_pick_dir)
    page_var.overlay.append(dlg_pick_dir_file)
    page_var.overlay.append(dlg_save_file)
    page_var.overlay.append(dlg_get_import)
    page_var.overlay.append(dlg_errors)
    page_var.overlay.append(dlg_errors_decrypt)

def decrypt():
    if dir_path != None and len(t_key_input.value) == 64 and len(t_IV_input.value) == 32:
        open_decrypt_dlg()
        directory_encryption.decrypt_dir(dir_path, t_key_input.value, t_IV_input.value)
        dlg_decrypt.open = False
        page_var.update()
    else:
        open_dlg_errors_decrypt()

def export_key():
    dlg_save_file.save_file()

def import_key():
    dlg_get_import.pick_files()

def open_confirmation_dlg(e):
    if dir_path is not None:
        page_var.dialog = dlg_confirm_encrypt
        page_var.dialog.content = ft.Text(f"Would you like to encrypt {os.path.basename(dir_path)}?")
        dlg_confirm_encrypt.open = True
        page_var.update()
    else:
        open_dlg_errors()

def open_decrypt_dlg(e=None):
    page_var.dialog = dlg_decrypt
    dlg_decrypt.open = True
    page_var.update()

def close_confirmation_dlg(e, execute):
    dlg_confirm_encrypt.title = ft.Text("Encrypting")
    dlg_confirm_encrypt.content = ft.ProgressRing(width=16, height=16, stroke_width=2)
    page_var.update()
    if execute:
        directory_encryption.encrypt_dir(dir_path)
        t_key.value = directory_encryption.key_val
        t_IV.value = directory_encryption.IV_val
        t_key.update()
        t_IV.update()
    dlg_confirm_encrypt.open = False
    page_var.update()

def open_dlg_errors(e=None):
    if dir_path is None:
        dlg_errors.content = ft.Text("No file is selected.")
    page_var.dialog = dlg_errors
    dlg_errors.open = True
    page_var.update()

def open_dlg_errors_decrypt(e=None):
    if dir_path is None:
        dlg_errors_decrypt.content = ft.Text("No file is selected.")
    elif len(t_key_input.value) != 64:
        dlg_errors_decrypt.content = ft.Text("Invalid decryption key.")
    elif len(t_IV_input.value) != 32:
        dlg_errors_decrypt.content = ft.Text("Invalid IV.")
    page_var.dialog = dlg_errors_decrypt
    dlg_errors_decrypt.open = True
    page_var.update()


# global variables
dir_path = None
page_var = None

# dialogues
dlg_pick_dir = ft.FilePicker(on_result=get_dir)
dlg_pick_dir_file = ft.FilePicker(on_result=get_file)
dlg_save_file = ft.FilePicker(on_result=save_file)
dlg_get_import = ft.FilePicker(on_result=get_import)
dlg_confirm_encrypt = ft.AlertDialog(
    modal=True,
    title=ft.Text("Encryption Confirmation"),
    content=ft.Text(f"Would you like to encrypt {dir_path}?"),
    actions=[
        ft.TextButton("Yes", on_click=lambda e: close_confirmation_dlg(e, True)),
        ft.TextButton("No", on_click=lambda e: close_confirmation_dlg(e, False)),
    ],
    actions_alignment=ft.MainAxisAlignment.CENTER
)
dlg_decrypt = ft.AlertDialog(
    title=ft.Text("Decrypting"),
    content=ft.ProgressRing(width=16, height=16, stroke_width=2),
    modal=True
)
dlg_errors = ft.AlertDialog(
    title=ft.Text("Error")
)
dlg_errors_decrypt = ft.AlertDialog(
    title=ft.Text("Error")
)

# buttons
b_select_dir = ft.ElevatedButton(
    "Select Directory",
    on_click=lambda _: dlg_pick_dir.get_directory_path()
)

b_select_file = ft.ElevatedButton(
    "Select File",
    on_click=lambda _: dlg_pick_dir_file.pick_files()
)

b_encrypt_dir = ft.ElevatedButton(
    "Encrypt Directory",
    on_click=open_confirmation_dlg
)

b_decrypt_dir = ft.ElevatedButton(
    "Decrypt Directory",
    on_click=lambda _: decrypt()
)

b_export_key = ft.ElevatedButton(
    "Export Key",
    on_click=lambda _: export_key()
)

b_import_key = ft.ElevatedButton(
    "Import Key",
    on_click=lambda _: import_key()
)

# text fields
t_key = ft.TextField(label="Encryption Key", read_only=True)
t_IV = ft.TextField(label="IV", read_only=True)
t_selected_dir = ft.Text("")
t_selected_file = ft.Text("")
t_key_input = ft.TextField(label="Encryption Key")
t_IV_input = ft.TextField(label="IV")

def directory_page(router):
    content = ft.Column([
        ft.Row([
            ft.Text("Encryption", size=40)
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            b_select_dir,
            t_selected_dir,
            b_encrypt_dir,
        ],
            alignment=ft.MainAxisAlignment.CENTER
        ),
        ft.Row([
            t_key, t_IV, b_export_key
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Container(padding=40),
        ft.Row([
            ft.Text("Decryption", size=40)
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            b_select_file, t_selected_file, b_decrypt_dir
        ], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            t_key_input, t_IV_input, b_import_key
        ], alignment=ft.MainAxisAlignment.CENTER)

    ])

    return content