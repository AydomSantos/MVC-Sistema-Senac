from tkinter import Tk, Canvas, Entry, Button, PhotoImage, Label, Toplevel, StringVar, OptionMenu
import pathlib
from pathlib import Path
class View:
    def __init__(self, controller):
        self.controller = controller
        self.window = Tk()
        self.window.geometry("800x800")
        self.window.configure(bg="#F39421")
        self.button_images = {}  # Dicionário para manter a referência das imagens
        self.login_window()

    def relative_to_assets(self, path: str) -> str:
        script_dir = Path(__file__).parent
        assets_path = script_dir.parent / "assets" / "img"
        full_path = assets_path / path
        print(full_path)  # Adicione este print para depuração
        return str(full_path)

    def login_window(self):
        canvas = Canvas(
            self.window,
            bg="#F39421",
            height=800,
            width=800,
            bd=0,
            highlightthickness=0,
            relief="ridge"
        )
        canvas.place(x=0, y=0)

        # Add title text
        canvas.create_text(
            50.0,
            20.0,
            anchor="nw",
            text="Convertion Cash",
            fill="#FFFDFD",
            font=("MontserratItalic Medium", 48 * -1)
        )

        # Create entry fields
        self.entry_email = Entry(
            bd=0,
            bg="#FFFDFD",
            fg="#000716",
            highlightthickness=0,
            font=("Helvetica", 16)
        )
        self.entry_email.place(
            x=35.0,
            y=280.0,
            width=730.0,
            height=50.0
        )

        self.entry_senha = Entry(
            bd=0,
            bg="#FFFFFF",
            fg="#000716",
            highlightthickness=0,
            font=("Helvetica", 16),
            show="*"
        )
        self.entry_senha.place(
            x=35.0,
            y=380.0,
            width=730.0,
            height=50.0
        )

        # Add labels
        canvas.create_text(
            45.0,
            250.0,
            anchor="nw",
            text="Digite o seu email",
            fill="#FFFDFD",
            font=("Lato Medium", 24 * -1)
        )

        canvas.create_text(
            45.0,
            350.0,
            anchor="nw",
            text="Digite a sua senha",
            fill="#FFFDFD",
            font=("Lato Medium", 24 * -1)
        )

        # Add buttons
        button_img_login_path = self.relative_to_assets("button_img_login.png")
        button_img_login = PhotoImage(file=button_img_login_path)
        self.button_images["login"] = button_img_login  # Mantenha a referência da imagem

        button_login = Button(
            self.window,
            image=button_img_login,
            borderwidth=0,
            highlightthickness=0,
            command=self.controller.valida_login
        )
        button_login.place(
            x=250.8,
            y=460.0,
            width=278.0,
            height=78.0
        )

        button_img_register_path = self.relative_to_assets("register_button.png")
        button_img_register = PhotoImage(file=button_img_register_path)
        self.button_images["register"] = button_img_register  # Mantenha a referência da imagem

        button_register = Button(
            self.window,
            image=button_img_register,
            borderwidth=0,
            highlightthickness=0,
            command=self.controller.open_registration_window
        )
        button_register.place(
            x=250.0,
            y=600.0,
            width=278.0,
            height=78.0
        )

        # Add error label
        self.error_label = Label(
            self.window,
            text="",
            bg="#F39421",
            font=("Helvetica", 14)
        )
        self.error_label.place(
            x=35.0,
            y=700.0,
            width=730.0,
            height=50.0
        )

    def open_registration_window(self):
        register_window = Toplevel(self.window)
        register_window.geometry("800x800")
        register_window.configure(bg="#F39421")
        register_window.title("Cadastro")

        register_canvas = Canvas(
            register_window,
            bg="#F39421",
            height=800,
            width=800,
            bd=0,
            highlightthickness=0,
            relief="ridge"
        )
        register_canvas.place(x=0, y=0)

        register_canvas.create_text(
            50.0,
            20.0,
            anchor="nw",
            text="Cadastro",
            fill="#FFFDFD",
            font=("Montserrat Medium", 48)
        )

        fields = ["Nome", "Email", "Telefone", "Senha", "Confirme a Senha"]
        entry_fields = []
        for i, field in enumerate(fields):
            entry = Entry(
                register_window,
                bd=0,
                bg="#FFFDFD",
                fg="#000716",
                font=("Helvetica", 16),
                show="*" if "Senha" in field else ""
            )
            entry_fields.append(entry)

            register_canvas.create_text(
                45.0,
                110.0 + i * 100,
                anchor="nw",
                text=field,
                fill="#FFFFFF",
                font=("Lato Medium", 18)
            )
            entry.place(
                x=45.0,
                y=140.0 + i * 100,
                width=710.0,
                height=30.0
            )

        def register():
            values = [entry.get() for entry in entry_fields]
            error_message = self.controller.model.validate_register_inputs(*values)

            if error_message:
                register_error_label.config(text=error_message, fg="red")
            else:
                register_error_label.config(text="Cadastro realizado com sucesso!", fg="green")
                self.controller.model.register_user(values[0], values[1], values[2], values[3])
                print("Cadastro realizado")

        register_button = Button(
            register_window,
            text="Register",
            font=("Helvetica", 16),
            bg="#4CAF50",
            fg="white",
            borderwidth=0,
            highlightthickness=0,
            command=register
        )
        register_button.place(
            x=250.0,
            y=620.0,
            width=278.0,
            height=78.0
        )

        register_error_label = Label(
            register_window,
            text="",
            bg="#F39421",
            font=("Helvetica", 14)
        )
        register_error_label.place(
            x=35.0,
            y=710.0,
            width=730.0,
            height=50.0
        )

    def open_conversor_window(self):
        conversor_window = Toplevel(self.window)
        conversor_window.geometry("776x654")
        conversor_window.configure(bg="#FFFFFF")
        conversor_window.title("Conversor")

        moeda = ['USD', 'BRL', 'EUR', 'CAD', 'AUD', 'CHF', 'JPY', 'RUB', 'INR', 'AOA']
        self.dict_moedas = {
            'USD': '$',
            'BRL': 'R$',
            'EUR': '€',
            'CAD': 'C$',
            'AUD': 'A$',
            'CHF': 'Fr',
            'JPY': '¥',
            'RUB': 'RUB',
            'INR': '₹',
            'AOA': 'Kz'
        }

        canvas = Canvas(
            conversor_window,
            bg="#FFFFFF",
            height=654,
            width=776,
            bd=0,
            highlightthickness=0,
            relief="ridge"
        )
        canvas.place(x=0, y=0)

        image_image_1 = PhotoImage(file=(self.relative_to_assets("tela.png")))
        canvas.create_image(388.0, 327.0, image=image_image_1)

        canvas.create_text(
            33.0,
            241.0,
            anchor="nw",
            text="Digite o valor em",
            fill="#000000",
            font=("Inter Medium", 16 * -1)
        )

        self.app_resultado = Label(
            conversor_window,
            text='',
            width=16,
            height=2,
            anchor='center',
            font=('Ivy 15 bold'),
            bg='#FFFFFF',
            fg='#333333'
        )
        self.app_resultado.place(x=430, y=335, width=315, height=80)

        self.entrada_valor = Entry(
            conversor_window,
            width=22,
            justify='center',
            font=('Ivy 12 bold'),
            relief='solid',
            bg='#FFFFFF',
            fg='#000000'
        )
        self.entrada_valor.place(x=40, y=335, width=310, height=80)

        self.moeda_de = StringVar()
        self.moeda_de.set(moeda[0])
        dropdown_de = OptionMenu(
            conversor_window,
            self.moeda_de,
            *moeda
        )
        dropdown_de.config(
            width=8,
            font=('Ivy 12 bold'),
            bg='#FFFFFF',
            fg='#333333',
            relief='solid'
        )
        dropdown_de.place(x=200, y=235)

        self.moeda_para = StringVar()
        self.moeda_para.set(moeda[1])
        dropdown_para = OptionMenu(
            conversor_window,
            self.moeda_para,
            *moeda
        )
        dropdown_para.config(
            width=8,
            font=('Ivy 12 bold'),
            bg='#FFFFFF',
            fg='#333333',
            relief='solid'
        )
        dropdown_para.place(x=578, y=233, width=180, height=32)

        canvas.create_text(
            429.0,
            237.0,
            anchor="nw",
            text="Esse é o valor em",
            fill="#000000",
            font=("Inter Medium", 16 * -1)
        )

        button_image_1 = PhotoImage(file=self.relative_to_assets("conversor_button.png"))
        button_1 = Button(
            conversor_window,
            image=button_image_1,
            highlightthickness=0,
            command=self.controller.converter,
            relief="flat",
            bg="white" 
        )
        button_1.place(x=100, y=480, width=278, height=78)

        conversor_window.mainloop()

    def start(self):
        self.window.resizable(False, False)
        self.window.mainloop()
