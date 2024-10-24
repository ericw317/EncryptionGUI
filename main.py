import flet as ft
from user_controls.routes import router
from user_controls.app_bar import NavBar
import views.direct_page as direct_page
import views.file_page as file_page
import views.text_page as text_page

def main(page: ft.Page):
    page.title = "AES-256 Encryptor"
    page.window_width = 1350
    page.window_height = 800
    page.theme_mode = "dark"
    page.appbar = NavBar(page)
    page.on_route_change = router.route_change
    router.page = page
    page.add(
        ft.Column([
            router.body
        ],
            expand=True,
            alignment=ft.MainAxisAlignment.CENTER,
        ), ft.Container(padding=50.5)
    )

    direct_page.get_page(page)
    file_page.get_page(page)
    text_page.get_page(page)
    page.go('/')

ft.app(target=main)