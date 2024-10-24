import flet as ft
import views.direct_page as directory_page


def NavBar(page):
    NavBar = ft.Dropdown(
        label="Files",
        width=150,
        value="home",
        on_change=lambda _: change(),
        options=[
            ft.dropdown.Option("Files"),
            ft.dropdown.Option("Directory"),
            ft.dropdown.Option("Text")
        ]
    )

    def change():
        directory_page.clear_fields()
        if NavBar.value == "Files":
            navigation = "/"
        elif NavBar.value == "Directory":
            navigation = "/directory_page"
        elif NavBar.value == "Text":
            navigation = "/text_page"
        page.go(navigation)

    return NavBar