import re
import requests
import mysql.connector
from mysql.connector import Error

class Model:
    def __init__(self):
        self.base_url = 'https://economia.awesomeapi.com.br/last/'
        self.db_config = {
            'host': 'localhost',
            'port': '3306',
            'database': 'banco_de_dados',  # Nome do banco de dados
            'user': 'root',
            'password': 'aydon1234512345'
        }

    # Conectar ao banco de dados
    def conn_db(self):
        try:
            conn = mysql.connector.connect(**self.db_config)
            if conn.is_connected():
                return conn
        except Error as e:
            print("Erro ao conectar ao MySQL", e)
        return None
    
    # Desconectar do banco de dados
    def disconnect_db(self, conn):
        if conn.is_connected():
            conn.close()

    # Validação de email
    def is_valid_email(self, email):
        return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

    # Validação de telefone
    def is_valid_phone(self, phone):
        return re.match(r"^\d{10,15}$", phone) is not None

    # Verificar se as senhas correspondem
    def passwords_match(self, password, confirm_password):
        return password == confirm_password

    # Validar todos os campos de entrada de registro
    def validate_register_inputs(self, name, email, phone, password, confirm_password):
        error_message = ""

        if not name:
            error_message += "Nome não pode estar vazio.\n"
        if not email or not self.is_valid_email(email):
            error_message += "Email inválido.\n"
        if not phone or not self.is_valid_phone(phone):
            error_message += "Telefone inválido. Deve conter apenas números e ter entre 10 e 15 dígitos.\n"
        if not password:
            error_message += "Senha não pode estar vazia.\n"
        if not confirm_password:
            error_message += "Confirme a senha não pode estar vazio.\n"
        if password and confirm_password and not self.passwords_match(password, confirm_password):
            error_message += "As senhas não correspondem.\n"

        return error_message

    # Registrar usuário no banco de dados
    def register_user(self, name, email, phone, password):
        conn = self.conn_db()
        if not conn:
            return "Erro ao conectar ao banco de dados."

        try:
            cursor = conn.cursor()
            cursor.execute(
            "INSERT INTO usuarios(nome, email, telefone, senha) VALUES (%s, %s, %s, %s)",
            (name, email, phone, password)
)
            conn.commit()
            return "Usuário registrado com sucesso."
        except Error as e:
            return f"Erro ao registrar usuário: {e}"
        finally:
            self.disconnect_db(conn)

    # Autenticar usuário
    def authenticate_user(self, email, password):
        conn = self.conn_db()
        if not conn:
            return "Erro ao conectar ao banco de dados."

        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM usuarios WHERE email = %s AND senha = %s",
                (email, password)
            )
            user = cursor.fetchone()
            return user if user else "Email ou senha incorretos."
        except Error as e:
            return f"Erro ao autenticar usuário: {e}"
        finally:
            self.disconnect_db(conn)

    # Validar campos de entrada do login
    def validate_login_inputs(self, email, password):
        error_message = ""

        if not email or not self.is_valid_email(email):
            error_message += "Email inválido.\n"
        if not password:
            error_message += "Senha não pode estar vazia.\n"

        return error_message

    # Converter moeda
    def converter_moeda(self, valor_entrada, moeda_de_valor, moeda_para_valor):
        url = f'{self.base_url}{moeda_de_valor}-{moeda_para_valor}'
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            taxa_cambio = float(data[f'{moeda_de_valor}{moeda_para_valor}']['bid'])
            valor_convertido = valor_entrada * taxa_cambio
            return valor_convertido
        else:
            raise Exception('Falha ao obter as taxas de câmbio. Tente novamente mais tarde.')

# Testando a função de registro
"""
if __name__ == "__main__":
    model = Model()
    result = model.register_user("Testateste", "joojoãoteste@gmail.com", "1234567890", "123")
    print(result)
"""

