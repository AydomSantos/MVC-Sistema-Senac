from models.model import Model
from views.view import View
from tkinter import messagebox

class Controller:
    def __init__(self, model):
        self.model = model
        self.view = View(self)
        self.usuario = None

    def valida_login(self):
        email = self.view.entry_email.get()
        senha = self.view.entry_senha.get()
        error_message = self.model.validate_login_inputs(email, senha)
        if error_message:
            self.view.error_label.config(text=error_message, fg="red")
        else:
            result = self.model.authenticate_user(email, senha)
            self.usuario = result
            if isinstance(result, str):
                self.view.error_label.config(text=result, fg="red")
            else:
                self.view.error_label.config(text="")
                self.view.open_conversor_window()
        return result

    def open_registration_window(self):
        self.view.open_registration_window()

    def register(self, name, email, phone, password, confirm_password):
        error_message = self.model.validate_register_inputs(name, email, phone, password, confirm_password)
        if error_message:
            return error_message
        return self.model.register_user(name, email, phone, password) 
    
    def converter(self):
        valor = self.view.entrada_valor.get()
        moeda_de = self.view.moeda_de.get()
        moeda_para = self.view.moeda_para.get()
        try:
            valor = float(valor)
            resultado = self.model.converter_moeda(valor, moeda_de, moeda_para, self.usuario[0])
            self.view.app_resultado.config(text=f'{resultado:.2f}')
        except ValueError:
            self.view.app_resultado.config(text="Entrada de valor inválida")
        except Exception as e:
            self.view.app_resultado.config(text=str(e))

    def mostrar_historico_conversoes(self):
        historico = self.model.historico_conversao(self.usuario[0])
        return historico
        # if isinstance(historico, str):
        #     print(historico)
        # else:
        #     print("Histórico de conversões:")
        #     for conversao in historico:
        #         print(f"ID: {conversao[0]}, Valor Entrada: {conversao[1]}, Moeda de Valor: {conversao[2]}, Moeda para Valor: {conversao[3]}, Valor Convertido: {conversao[4]}, Data e Hora: {conversao[5]}")

    def start(self):
        self.view.start()
