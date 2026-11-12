import os
import string
import secrets
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from crypto import encrypt_data, decrypt_data

# Importa o gerador de PDF da ReportLab
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

VAULT_FILE = "vault.enc"
SALT_SIZE = 16
IDLE_TIME_LIMIT = 300000  # Tempo limite de inatividade (5 minutos)
CLIPBOARD_CLEAR_TIME = 15000  # Tempo para limpar o clipboard (15 segundos)

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gerenciador de Senhas Seguro")
        self.root.geometry("660x680")
        self.root.minsize(600, 600)
        
        self.vault_data = None
        self.master_password = None
        self.idle_timer_id = None
        self.clipboard_timer_id = None
        
        # Estilo visual moderno
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Monitora eventos globais para o Auto-Lock
        self.root.bind_all("<Any-KeyPress>", self.reset_idle_timer)
        self.root.bind_all("<Any-ButtonPress>", self.reset_idle_timer)
        self.root.bind_all("<Motion>", self.reset_idle_timer)
        
        if not os.path.exists(VAULT_FILE):
            self.show_setup_screen()
        else:
            self.show_login_screen()

    def clear_window(self):
        """Limpa todos os widgets da janela atual."""
        for widget in self.root.winfo_children():
            widget.destroy()

    # ==================== CONTROLE DE INATIVIDADE (AUTO-LOCK) ====================
    def start_idle_timer(self):
        self.cancel_idle_timer()
        if self.vault_data is not None:
            self.idle_timer_id = self.root.after(IDLE_TIME_LIMIT, self.auto_lock)

    def cancel_idle_timer(self):
        if self.idle_timer_id is not None:
            self.root.after_cancel(self.idle_timer_id)
            self.idle_timer_id = None

    def reset_idle_timer(self, event=None):
        self.start_idle_timer()

    def auto_lock(self):
        self.vault_data = None
        self.master_password = None
        self.cancel_idle_timer()
        messagebox.showwarning("Bloqueado", "Aplicativo bloqueado automaticamente por inatividade.")
        self.show_login_screen()

    # ==================== CLIPBOARD COM LIMPEZA AUTOMÁTICA ====================
    def copy_to_clipboard(self, text_to_copy, site_name):
        self.start_idle_timer()
        if self.clipboard_timer_id is not None:
            self.root.after_cancel(self.clipboard_timer_id)
            
        self.root.clipboard_clear()
        self.root.clipboard_append(text_to_copy)
        
        messagebox.showinfo("Copiado!", f"A senha de '{site_name}' foi copiada para a área de transferência.\n\nEla será limpa automaticamente em 15 segundos.")
        self.clipboard_timer_id = self.root.after(CLIPBOARD_CLEAR_TIME, self.clear_clipboard)

    def clear_clipboard(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append("")
        except Exception:
            pass
        self.clipboard_timer_id = None

    # ==================== CÁLCULO E VALIDAÇÃO DE FORÇA ====================
    def calculate_password_strength(self, password: str) -> int:
        if not password:
            return 0
        score = 0
        length = len(password)
        if length >= 8: score += 25
        if length >= 12: score += 15
        if length >= 16: score += 10
        if any(c.islower() for c in password): score += 15
        if any(c.isupper() for c in password): score += 15
        if any(c.isdigit() for c in password): score += 10
        if any(c in string.punctuation for c in password): score += 10
        return min(score, 100)

    def update_strength_indicator(self, password, progress_bar, label_widget):
        score = self.calculate_password_strength(password)
        progress_bar["value"] = score
        if score == 0:
            label_widget.config(text="Insira uma senha", foreground="gray")
        elif score < 40:
            label_widget.config(text="Força: Fraca ❌", foreground="red")
        elif score < 75:
            label_widget.config(text="Força: Média ⚠️", foreground="orange")
        else:
            label_widget.config(text="Força: Forte ✅", foreground="green")

    def check_master_password_strength(self, password: str) -> tuple[bool, str]:
        if len(password) < 10:
            return False, "A Senha Mestra deve ter pelo menos 10 caracteres."
        if not any(c.islower() for c in password):
            return False, "A Senha Mestra precisa conter pelo menos uma letra minúscula."
        if not any(c.isupper() for c in password):
            return False, "A Senha Mestra precisa conter pelo menos uma letra maiúscula."
        if not any(c.isdigit() for c in password):
            return False, "A Senha Mestra precisa conter pelo menos um número."
        if not any(c in string.punctuation for c in password):
            return False, "A Senha Mestra precisa conter pelo menos um caractere especial (!@#$%^&*...)."
        return True, ""

    # ==================== EXPORTAR RELATÓRIO PARA PDF ====================
    def export_pdf_report(self):
        self.start_idle_timer()
        if not self.vault_data:
            messagebox.showerror("Erro", "O cofre está vazio. Nada para exportar.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("Arquivo PDF", "*.pdf"), ("Todos os arquivos", "*.*")],
            title="Exportar Relatório de Senhas para PDF"
        )

        if file_path:
            try:
                doc = SimpleDocTemplate(file_path, pagesize=letter)
                elements = []
                styles = getSampleStyleSheet()

                title_style = ParagraphStyle(
                    'TitleStyle',
                    parent=styles['Heading1'],
                    fontSize=18,
                    textColor=colors.HexColor('#D9534F'),
                    spaceAfter=15,
                    alignment=1
                )

                elements.append(Paragraph("Relatório de Credenciais - Cofre Seguro", title_style))
                elements.append(Spacer(1, 10))

                table_data = [["Site / Serviço", "Usuário", "Senha", "Observações"]]
                for site, creds in self.vault_data.items():
                    obs = creds.get("observacao", "")
                    table_data.append([site, creds["usuario"], creds["senha"], obs])

                t = Table(table_data, colWidths=[150, 95, 95, 150])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#D9534F')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F9F9F9')),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('TOPPADDING', (0, 1), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                ]))

                elements.append(t)
                doc.build(elements)
                messagebox.showinfo("Sucesso", "Relatório PDF gerado com sucesso!")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao gerar PDF: {e}")

    # ==================== EXPORTAR / IMPORTAR BACKUP (.ENC) ====================
    def export_backup(self):
        self.start_idle_timer()
        if not os.path.exists(VAULT_FILE):
            messagebox.showerror("Erro", "Nenhum cofre encontrado para exportar.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Cofre Criptografado", "*.enc"), ("Todos os arquivos", "*.*")],
            title="Salvar Backup do Cofre"
        )
        if file_path:
            try:
                with open(VAULT_FILE, "rb") as src:
                    content = src.read()
                with open(file_path, "wb") as dst:
                    dst.write(content)
                messagebox.showinfo("Sucesso", "Backup criptografado exportado com sucesso!")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao exportar backup: {e}")

    def import_backup(self):
        self.start_idle_timer()
        file_path = filedialog.askopenfilename(
            filetypes=[("Cofre Criptografado", "*.enc"), ("Todos os arquivos", "*.*")],
            title="Selecionar Backup para Importar"
        )
        if file_path:
            confirm = messagebox.askyesno("Atenção", "Importar um backup substituirá o cofre atual. Deseja continuar?")
            if confirm:
                try:
                    with open(file_path, "rb") as src:
                        content = src.read()
                    with open(VAULT_FILE, "wb") as dst:
                        dst.write(content)
                    messagebox.showinfo("Sucesso", "Backup importado com sucesso!")
                    self.show_login_screen()
                except Exception as e:
                    messagebox.showerror("Erro", f"Falha ao importar backup: {e}")

    # ==================== TELA DE SETUP ====================
    def show_setup_screen(self):
        self.cancel_idle_timer()
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text="Configuração Inicial", font=("Arial", 16, "bold")).pack(pady=5)
        ttk.Label(frame, text="Defina uma Senha Mestra forte para proteger seu cofre:", font=("Arial", 9)).pack(pady=2)
        
        rules_text = "Requisitos Mínimos:\n• 10+ caracteres | Maiúsculas e minúsculas\n• Números e caracteres especiais"
        ttk.Label(frame, text=rules_text, font=("Arial", 8, "italic"), foreground="#555555").pack(pady=2)
        
        ttk.Label(frame, text="Nova Senha Mestra:").pack(anchor="w", pady=(5, 0))
        pass_var = tk.StringVar()
        pass_entry = ttk.Entry(frame, textvariable=pass_var, show="*", width=35, font=("Arial", 11))
        pass_entry.pack(pady=3)
        
        strength_frame = ttk.Frame(frame)
        strength_frame.pack(fill="x", pady=2)
        lbl_strength = ttk.Label(strength_frame, text="Insira uma senha", font=("Arial", 9, "bold"))
        lbl_strength.pack(anchor="w")
        progress_bar = ttk.Progressbar(strength_frame, orient="horizontal", length=300, mode="determinate", maximum=100)
        progress_bar.pack(fill="x", pady=2)
        pass_var.trace_add("write", lambda *args: self.update_strength_indicator(pass_var.get(), progress_bar, lbl_strength))
        
        ttk.Label(frame, text="Confirme a Senha Mestra:").pack(anchor="w", pady=(5, 0))
        confirm_entry = ttk.Entry(frame, show="*", width=35, font=("Arial", 11))
        confirm_entry.pack(pady=3)
        
        def handle_setup():
            p1 = pass_entry.get()
            p2 = confirm_entry.get()
            if not p1 or p1 != p2:
                messagebox.showerror("Erro", "As senhas não conferem ou estão vazias!")
                return
            is_strong, error_msg = self.check_master_password_strength(p1)
            if not is_strong:
                messagebox.showerror("Senha Fraca", error_msg)
                return
            
            salt = os.urandom(SALT_SIZE)
            encrypted = encrypt_data({}, p1, salt)
            with open(VAULT_FILE, "wb") as f:
                f.write(salt + encrypted)
                
            messagebox.showinfo("Sucesso", "Cofre criado com segurança máxima!")
            self.master_password = p1
            self.vault_data = {}
            self.show_main_menu()

        ttk.Button(frame, text="Criar Cofre", command=handle_setup).pack(pady=10)
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=10)
        ttk.Button(frame, text="📥 Já tenho um Backup (.enc)", command=self.import_backup).pack(pady=2)

    # ==================== TELA DE LOGIN ====================
    def show_login_screen(self):
        self.cancel_idle_timer()
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=30)
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text="🔓 Desbloquear Cofre", font=("Arial", 18, "bold")).pack(pady=15)
        ttk.Label(frame, text="Digite sua Senha Mestra:", font=("Arial", 11)).pack(pady=5)
        
        pass_entry = ttk.Entry(frame, show="*", width=35, font=("Arial", 12))
        pass_entry.pack(pady=10)
        pass_entry.focus()
        
        def handle_login():
            password = pass_entry.get()
            try:
                with open(VAULT_FILE, "rb") as f:
                    content = f.read()
                salt = content[:SALT_SIZE]
                encrypted = content[SALT_SIZE:]
                
                data = decrypt_data(encrypted, password, salt)
                self.vault_data = data
                self.master_password = password
                self.show_main_menu()
            except ValueError:
                messagebox.showerror("Erro", "Senha Mestra incorreta!")
                pass_entry.delete(0, tk.END)

        pass_entry.bind("<Return>", lambda event: handle_login())
        ttk.Button(frame, text="Entrar", command=handle_login).pack(pady=10)
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=15)
        ttk.Button(frame, text="📥 Importar Outro Backup", command=self.import_backup).pack(pady=2)

    # ==================== MENU PRINCIPAL ====================
    def show_main_menu(self):
        self.start_idle_timer()
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text="Gerenciador de Senhas", font=("Arial", 16, "bold")).pack(pady=5)
        
        btn_width = 28
        ttk.Button(frame, text="Listar / Buscar Senhas", width=btn_width, command=self.show_list_screen).pack(pady=5)
        ttk.Button(frame, text="Adicionar Nova Senha", width=btn_width, command=self.show_add_screen).pack(pady=5)
        ttk.Button(frame, text="Editar / Deletar Senha", width=btn_width, command=self.show_manage_screen).pack(pady=5)
        
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=10)
        ttk.Button(frame, text="💾 Exportar Backup (.enc)", width=btn_width, command=self.export_backup).pack(pady=4)
        ttk.Button(frame, text="📥 Importar Backup (.enc)", width=btn_width, command=self.import_backup).pack(pady=4)
        
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=10)
        ttk.Button(frame, text="Bloquear / Sair", width=btn_width, command=self.show_login_screen).pack(pady=4)

    def save_current_vault(self):
        self.start_idle_timer()
        with open(VAULT_FILE, "rb") as f:
            salt = f.read(SALT_SIZE)
        encrypted = encrypt_data(self.vault_data, self.master_password, salt)
        with open(VAULT_FILE, "wb") as f:
            f.write(salt + encrypted)

    # ==================== TELA DE LISTAGEM E BUSCA ====================
    def show_list_screen(self):
        self.start_idle_timer()
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=15)
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text="Suas Senhas Armazenadas", font=("Arial", 16, "bold")).pack(pady=3)
        ttk.Label(frame, text="Dica: Selecione um item na lista e use os botões abaixo.", font=("Arial", 10, "italic")).pack(pady=3)
        
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill="x", pady=8)
        ttk.Label(search_frame, text="Buscar:", font=("Arial", 11)).pack(side="left", padx=5)
        
        search_entry = ttk.Entry(search_frame, width=30, font=("Arial", 11))
        search_entry.pack(side="left", padx=5)
        
        self.style.configure("Treeview.Heading", font=("Arial", 11, "bold"))
        self.style.configure("Treeview", font=("Arial", 11), rowheight=30)
        
        tree = ttk.Treeview(frame, columns=("site", "usuario", "senha", "observacao"), show="headings", height=8, style="Treeview")
        self.style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
        
        tree.heading("site", text="Site / Serviço")
        tree.heading("usuario", text="Usuário")
        tree.heading("senha", text="Senha")
        tree.heading("observacao", text="Observações")
        
        tree.column("site", width=150, anchor="w")
        tree.column("usuario", width=110, anchor="w")
        tree.column("senha", width=110, anchor="w")
        tree.column("observacao", width=150, anchor="w")
        
        tree.pack(fill="both", expand=True, pady=5)
        
        tree.tag_configure('par', background='#FFFFFF')
        tree.tag_configure('impar', background='#F2F5F8')

        self.revealed_items = set()

        def populate_tree(filter_text=""):
            self.start_idle_timer()
            for item in tree.get_children():
                tree.delete(item)
                
            index = 0
            for site, creds in self.vault_data.items():
                if filter_text.lower() in site.lower():
                    if site in self.revealed_items:
                        display_password = creds["senha"]
                    else:
                        display_password = "•" * len(creds["senha"])
                    
                    obs = creds.get("observacao", "")
                    tag = 'par' if index % 2 == 0 else 'impar'
                    tree.insert("", "end", values=(site, creds["usuario"], display_password, obs), iid=site, tags=(tag,))
                    index += 1

        populate_tree()
        search_entry.bind("<KeyRelease>", lambda event: populate_tree(search_entry.get()))
        
        def handle_toggle_reveal():
            self.start_idle_timer()
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Aviso", "Selecione um item da lista para mostrar/ocultar a senha.")
                return
            
            site_name = selected_item[0]
            if site_name in self.revealed_items:
                self.revealed_items.remove(site_name)
            else:
                self.revealed_items.add(site_name)
            
            populate_tree(search_entry.get())

        def handle_copy_selected():
            self.start_idle_timer()
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Aviso", "Selecione um item da lista para copiar a senha.")
                return
            site_name = selected_item[0]
            real_password = self.vault_data[site_name]["senha"]
            self.copy_to_clipboard(real_password, site_name)

        btn_action_frame = ttk.Frame(frame)
        btn_action_frame.pack(fill="x", pady=6)

        btn_reveal = tk.Button(btn_action_frame, text="👁️ Mostrar / Ocultar Senha", font=("Arial", 10, "bold"), command=handle_toggle_reveal)
        btn_reveal.pack(side="left", expand=True, fill="x", padx=3, ipady=3)
        
        btn_copy = tk.Button(btn_action_frame, text="📋 Copiar Senha", font=("Arial", 10, "bold"), command=handle_copy_selected)
        btn_copy.pack(side="left", expand=True, fill="x", padx=3, ipady=3)
        
        btn_pdf = tk.Button(
            frame, 
            text="📄 Exportar Relatório em PDF", 
            bg="#D9534F", 
            fg="white", 
            font=("Arial", 11, "bold"), 
            activebackground="#C9302C", 
            activeforeground="white",
            relief="raised",
            bd=2,
            cursor="hand2",
            command=self.export_pdf_report
        )
        btn_pdf.pack(fill="x", pady=6, ipady=3)

        btn_back = tk.Button(frame, text="Voltar ao Menu", font=("Arial", 10), command=self.show_main_menu)
        btn_back.pack(fill="x", pady=2, ipady=2)

    # ==================== TELA DE ADICIONAR ====================
    def show_add_screen(self):
        self.start_idle_timer()
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text="Adicionar Nova Senha", font=("Arial", 14, "bold")).pack(pady=5)
        
        ttk.Label(frame, text="Site / Serviço (ex: github.com):").pack(anchor="w")
        site_entry = ttk.Entry(frame, width=40, font=("Arial", 10))
        site_entry.pack(pady=3)
        
        ttk.Label(frame, text="Usuário / E-mail:").pack(anchor="w")
        user_entry = ttk.Entry(frame, width=40, font=("Arial", 10))
        user_entry.pack(pady=3)
        
        ttk.Label(frame, text="Senha:").pack(anchor="w")
        pwd_var = tk.StringVar()
        pwd_entry = ttk.Entry(frame, textvariable=pwd_var, width=40, font=("Arial", 10))
        pwd_entry.pack(pady=3)
        
        strength_frame = ttk.Frame(frame)
        strength_frame.pack(fill="x", pady=2)
        lbl_strength = ttk.Label(strength_frame, text="Insira uma senha", font=("Arial", 9, "bold"))
        lbl_strength.pack(anchor="w")
        progress_bar = ttk.Progressbar(strength_frame, orient="horizontal", length=300, mode="determinate", maximum=100)
        progress_bar.pack(fill="x", pady=2)
        pwd_var.trace_add("write", lambda *args: self.update_strength_indicator(pwd_var.get(), progress_bar, lbl_strength))
        
        def generate_pwd():
            self.start_idle_timer()
            alphabet = string.ascii_letters + string.digits + string.punctuation
            while True:
                pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
                if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                        and any(c.isdigit() for c in pwd) and any(c in string.punctuation for c in pwd)):
                    pwd_var.set(pwd)
                    break

        ttk.Button(frame, text="Gerar Senha Forte", command=generate_pwd).pack(pady=3)
        
        ttk.Label(frame, text="Observações (opcional):").pack(anchor="w", pady=(3, 0))
        obs_entry = ttk.Entry(frame, width=40, font=("Arial", 10))
        obs_entry.pack(pady=3)
        
        def save_new():
            self.start_idle_timer()
            site = site_entry.get().strip()
            user = user_entry.get().strip()
            pwd = pwd_var.get().strip()
            obs = obs_entry.get().strip()
            
            if not site or not pwd:
                messagebox.showerror("Erro", "Preencha o site e a senha!")
                return
            self.vault_data[site] = {"usuario": user, "senha": pwd, "observacao": obs}
            self.save_current_vault()
            messagebox.showinfo("Sucesso", f"Credenciais de '{site}' salvas!")
            self.show_main_menu()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="Salvar", command=save_new).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancelar", command=self.show_main_menu).pack(side="left", padx=5)

    # ==================== TELA DE EDITAR / DELETAR ====================
    def show_manage_screen(self):
        self.start_idle_timer()
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text="Gerenciar Registros Existentes", font=("Arial", 14, "bold")).pack(pady=10)
        
        if not self.vault_data:
            ttk.Label(frame, text="O cofre está vazio.").pack(pady=20)
            ttk.Button(frame, text="Voltar", command=self.show_main_menu).pack(pady=10)
            return
            
        ttk.Label(frame, text="Selecione o site:").pack(anchor="w")
        sites_list = list(self.vault_data.keys())
        site_combo = ttk.Combobox(frame, values=sites_list, width=37, state="readonly")
        site_combo.pack(pady=5)
        if sites_list:
            site_combo.current(0)
            
        def delete_selected():
            self.start_idle_timer()
            selected = site_combo.get()
            if not selected:
                return
            if messagebox.askyesno("Confirmação", f"Deseja realmente apagar '{selected}'?"):
                del self.vault_data[selected]
                self.save_current_vault()
                messagebox.showinfo("Sucesso", "Registro removido.")
                self.show_main_menu()

        def edit_selected():
            self.start_idle_timer()
            selected = site_combo.get()
            if not selected:
                return
            
            edit_win = tk.Toplevel(self.root)
            edit_win.title(f"Editar: {selected}")
            edit_win.geometry("400x420")
            
            ef = ttk.Frame(edit_win, padding=15)
            ef.pack(expand=True, fill="both")
            
            ttk.Label(ef, text=f"Editando: {selected}", font=("Arial", 11, "bold")).pack(pady=5)
            
            ttk.Label(ef, text="Novo Usuário:").pack(anchor="w")
            u_entry = ttk.Entry(ef, width=35)
            u_entry.pack(pady=3)
            u_entry.insert(0, self.vault_data[selected]["usuario"])
            
            ttk.Label(ef, text="Nova Senha:").pack(anchor="w")
            edit_pwd_var = tk.StringVar(value=self.vault_data[selected]["senha"])
            p_entry = ttk.Entry(ef, textvariable=edit_pwd_var, width=35)
            p_entry.pack(pady=3)
            
            edit_strength_frame = ttk.Frame(ef)
            edit_strength_frame.pack(fill="x", pady=2)
            edit_lbl_strength = ttk.Label(edit_strength_frame, text="", font=("Arial", 9, "bold"))
            edit_lbl_strength.pack(anchor="w")
            progress_bar = ttk.Progressbar(edit_strength_frame, orient="horizontal", length=250, mode="determinate", maximum=100)
            progress_bar.pack(fill="x", pady=2)
            
            edit_pwd_var.trace_add("write", lambda *args: self.update_strength_indicator(edit_pwd_var.get(), progress_bar, edit_lbl_strength))
            self.update_strength_indicator(edit_pwd_var.get(), progress_bar, edit_lbl_strength)

            ttk.Label(ef, text="Nova Observação:").pack(anchor="w", pady=(3, 0))
            obs_entry = ttk.Entry(ef, width=35)
            obs_entry.pack(pady=3)
            obs_entry.insert(0, self.vault_data[selected].get("observacao", ""))

            def save_edits():
                self.start_idle_timer()
                self.vault_data[selected]["usuario"] = u_entry.get().strip()
                self.vault_data[selected]["senha"] = edit_pwd_var.get().strip()
                self.vault_data[selected]["observacao"] = obs_entry.get().strip()
                self.save_current_vault()
                messagebox.showinfo("Sucesso", "Atualizado com sucesso!")
                edit_win.destroy()
                self.show_manage_screen()

            ttk.Button(ef, text="Salvar Alterações", command=save_edits).pack(pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="Editar Selecionado", command=edit_selected).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Deletar Selecionado", command=delete_selected).pack(side="left", padx=5)
        ttk.Button(frame, text="Voltar ao Menu", command=self.show_main_menu).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()