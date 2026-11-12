import os
import getpass
import string
import secrets

VAULT_FILE = "vault.enc"
SALT_SIZE = 16

# Importa as funções do arquivo crypto.py
from crypto import encrypt_data, decrypt_data

def initialize_vault():
    """Configura a senha mestra pela primeira vez."""
    print("=== Configuração Inicial do Gerenciador ===")
    password = getpass.getpass("Defina sua Senha Mestra: ")
    confirm = getpass.getpass("Confirme a Senha Mestra: ")
    
    if password != confirm:
        print("As senhas não conferem. Tente novamente.")
        return False
    
    salt = os.urandom(SALT_SIZE)
    empty_vault = {}
    encrypted_data = encrypt_data(empty_vault, password, salt)
    
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + encrypted_data)
        
    print("\n[Sucesso] Cofre criado com segurança!")
    return True

def load_vault():
    """Carrega o cofre pedindo a senha mestra."""
    if not os.path.exists(VAULT_FILE):
        print("Cofre não encontrado. Faça a configuração inicial.")
        return None, None
        
    password = getpass.getpass("Digite sua Senha Mestra: ")
    
    try:
        with open(VAULT_FILE, "rb") as f:
            content = f.read()
            
        salt = content[:SALT_SIZE]
        encrypted_blob = content[SALT_SIZE:]
        
        vault_data = decrypt_data(encrypted_blob, password, salt)
        return vault_data, password
    except ValueError:
        print("\n[Erro] Senha Mestra incorreta!")
        return None, None

def save_vault(vault_data: dict, password: str):
    """Salva o cofre atualizado de volta no disco."""
    with open(VAULT_FILE, "rb") as f:
        salt = f.read(SALT_SIZE)
        
    encrypted_blob = encrypt_data(vault_data, password, salt)
    
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + encrypted_blob)

def generate_strong_password(length=16) -> str:
    """Gera uma senha forte usando caracteres aleatórios seguros."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in string.punctuation for c in pwd)):
            return pwd

def add_password(vault_data: dict, password: str):
    site = input("Nome do site/serviço (ex: github.com): ").strip()
    if not site:
        print("O nome do site não pode estar vazio.")
        return
        
    user = input("Usuário / E-mail: ").strip()
    
    print("\nComo deseja definir a senha?")
    print("1. Digitar manualmente")
    print("2. Gerar uma senha forte automática")
    choice = input("Escolha (1 ou 2): ").strip()
    
    if choice == "2":
        try:
            length_input = input("Tamanho da senha [padrão 16]: ").strip()
            length = int(length_input) if length_input else 16
        except ValueError:
            length = 16
            
        pwd = generate_strong_password(length)
        print(f"\n[Gerada] Sua nova senha é: {pwd}")
    else:
        pwd = getpass.getpass("Senha a ser salva: ")
    
    vault_data[site] = {
        "usuario": user,
        "senha": pwd
    }
    
    save_vault(vault_data, password)
    print(f"\n[Sucesso] Credenciais para '{site}' salvas com sucesso!")

def list_passwords(vault_data: dict):
    if not vault_data:
        print("\nO cofre está vazio.")
        return
        
    print("\n--- Senhas Armazenadas ---")
    for site, creds in vault_data.items():
        print(f"Site: {site}")
        print(f"  Usuário: {creds['usuario']}")
        print(f"  Senha:   {creds['senha']}")
        print("-" * 25)

def search_password(vault_data: dict):
    if not vault_data:
        print("\nO cofre está vazio.")
        return
        
    query = input("Digite o nome (ou parte do nome) do site que procura: ").strip().lower()
    found = False
    
    print(f"\n--- Resultados para '{query}' ---")
    for site, creds in vault_data.items():
        if query in site.lower():
            print(f"Site: {site}")
            print(f"  Usuário: {creds['usuario']}")
            print(f"  Senha:   {creds['senha']}")
            print("-" * 25)
            found = True
            
    if not found:
        print("Nenhum registro encontrado com esse termo.")

def edit_password(vault_data: dict, password: str):
    if not vault_data:
        print("\nO cofre está vazio.")
        return
        
    site = input("Digite o nome exato do site que deseja editar: ").strip()
    if site not in vault_data:
        print(f"\n[Erro] O site '{site}' não foi encontrado no cofre.")
        return
        
    print(f"\nEditando credenciais para: {site}")
    print(f"Usuário atual: {vault_data[site]['usuario']}")
    
    novo_user = input("Novo usuário / e-mail (deixe em branco para manter): ").strip()
    if novo_user:
        vault_data[site]['usuario'] = novo_user
        
    print("\nComo deseja atualizar a senha?")
    print("1. Digitar nova senha manualmente")
    print("2. Gerar uma nova senha forte automática")
    print("3. Manter a senha atual")
    choice = input("Escolha (1, 2 ou 3): ").strip()
    
    if choice == "1":
        nova_pwd = getpass.getpass("Nova senha: ")
        vault_data[site]['senha'] = nova_pwd
    elif choice == "2":
        try:
            length_input = input("Tamanho da senha [padrão 16]: ").strip()
            length = int(length_input) if length_input else 16
        except ValueError:
            length = 16
        nova_pwd = generate_strong_password(length)
        vault_data[site]['senha'] = nova_pwd
        print(f"\n[Gerada] Nova senha: {nova_pwd}")
    elif choice == "3":
        pass
    else:
        print("Opção inválida. Nenhuma alteração de senha feita.")
        return
        
    save_vault(vault_data, password)
    print(f"\n[Sucesso] Credenciais de '{site}' atualizadas com sucesso!")

def delete_password(vault_data: dict, password: str):
    if not vault_data:
        print("\nO cofre está vazio.")
        return
        
    site = input("Digite o nome exato do site que deseja remover: ").strip()
    if site not in vault_data:
        print(f"\n[Erro] O site '{site}' não foi encontrado no cofre.")
        return
        
    confirm = input(f"Tem certeza que deseja apagar os dados de '{site}'? (s/n): ").strip().lower()
    if confirm == 's':
        del vault_data[site]
        save_vault(vault_data, password)
        print(f"\n[Sucesso] Registro de '{site}' removido do cofre.")
    else:
        print("Operação cancelada.")

def main():
    if not os.path.exists(VAULT_FILE):
        if not initialize_vault():
            return

    vault_data, master_password = load_vault()
    if vault_data is None:
        return

    while True:
        print("\n=== GERENCIADOR DE SENHAS ===")
        print("1. Listar todas as senhas")
        print("2. Buscar senha por site")
        print("3. Adicionar nova senha")
        print("4. Editar senha existente")
        print("5. Deletar senha")
        print("6. Sair")
        
        choice = input("Escolha uma opção: ").strip()
        
        if choice == "1":
            list_passwords(vault_data)
        elif choice == "2":
            search_password(vault_data)
        elif choice == "3":
            add_password(vault_data, master_password)
        elif choice == "4":
            edit_password(vault_data, master_password)
        elif choice == "5":
            delete_password(vault_data, master_password)
        elif choice == "6":
            print("Saindo... Seus dados estão seguros.")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "X": # Evita warning padrão se executado direto
    pass

if __name__ == "__main__":
    main()