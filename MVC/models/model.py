import re
import requests
import sqlite3
from datetime import datetime

class Model:
    def __init__(self):
        self.base_url = 'https://economia.awesomeapi.com.br/last/'

    # Conectar ao banco de dados
    def conn_db(self):
        try:
            conn = sqlite3.connect("conversor.db")
            # Criar tabela de usuários se não existir
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS usuario (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                nome_usuario TEXT NOT NULL,
                                email_usuario TEXT NOT NULL UNIQUE,
                                telefone_usuario TEXT NOT NULL,
                                senha_usuario TEXT NOT NULL)''')
            # Criar tabela de conversões se não existir
            cursor.execute('''CREATE TABLE IF NOT EXISTS conversao (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                valor_entrada REAL NOT NULL,
                                moeda_de_valor TEXT NOT NULL,
                                moeda_para_valor TEXT NOT NULL,
                                valor_convertido REAL NOT NULL,
                                data_hora TEXT NOT NULL)''')
            conn.commit()
            return conn
        except sqlite3.Error as e:
            print(f"Erro ao conectar ao SQLite: {e}")
        return None

    # Desconectar do banco de dados
    def disconnect_db(self, conn):
        if conn:
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
                "INSERT INTO usuario(nome_usuario, email_usuario, telefone_usuario, senha_usuario) VALUES (?, ?, ?, ?)",
                (name, email, phone, password)
            )
            conn.commit()
            return "Usuário registrado com sucesso."
        except sqlite3.IntegrityError:
            return "Erro: Email já cadastrado."
        except sqlite3.Error as e:
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
                "SELECT * FROM usuario WHERE email_usuario = ? AND senha_usuario = ?",
                (email, password)
            )
            user = cursor.fetchone()
            return user if user else "Email ou senha incorretos."
        except sqlite3.Error as e:
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

    # Registrar conversão no banco de dados
    def register_conversao(self, valor_entrada, moeda_de_valor, moeda_para_valor, valor_convertido):
        conn = self.conn_db()
        if not conn:
            return "Erro ao conectar ao banco de dados."

        try:
            cursor = conn.cursor()
            data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO conversao (valor_entrada, moeda_de_valor, moeda_para_valor, valor_convertido, data_hora) VALUES (?, ?, ?, ?, ?)",
                (valor_entrada, moeda_de_valor, moeda_para_valor, valor_convertido, data_hora)
            )
            conn.commit()
            return "Conversão registrada com sucesso."
        except sqlite3.Error as e:
            return f"Erro ao registrar conversão: {e}"
        finally:
            self.disconnect_db(conn)

    # Converter moeda
    def converter_moeda(self, valor_entrada, moeda_de_valor, moeda_para_valor):
        url = f'{self.base_url}{moeda_de_valor}-{moeda_para_valor}'
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            taxa_cambio = float(data[f'{moeda_de_valor}{moeda_para_valor}']['bid'])
            valor_convertido = valor_entrada * taxa_cambio
            self.register_conversao(valor_entrada, moeda_de_valor, moeda_para_valor, valor_convertido)
            return valor_convertido
        else:
            raise Exception('Falha ao obter as taxas de câmbio. Tente novamente mais tarde.')

    # Obter histórico de conversões
    def historico_conversao(self):
        conn = self.conn_db()
        if not conn:
            return "Erro ao conectar ao banco de dados."

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM conversao")
            conversoes = cursor.fetchall()
            return conversoes
        except sqlite3.Error as e:
            return f"Erro ao obter histórico de conversões: {e}"
        finally:
            self.disconnect_db(conn)

# Testando a função de registro e a conversão

if __name__ == "__main__":
    model = Model()
    result = model.register_user("Aydom", "aydomaparecido@gmail.com", "1234567890", "123")
    print(result)

    valor_convertido = model.converter_moeda(100, 'USD', 'BRL')
    print(f"Valor convertido: {valor_convertido}")

    historico = model.historico_conversao()
    print("Histórico de conversões:")
    for conversao in historico:
        print(conversao)
