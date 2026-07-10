#!/usr/bin/env python3
"""
Interface Gráfica para Gerenciamento de Computadores
Utiliza Tkinter para criar a interface
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
from datetime import datetime

class InterfaceGerenciamento:
    def __init__(self, root):
        self.root = root
        self.root.title("Painel de Gerenciamento de Computadores")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        
        # Simular dados de clientes conectados
        self.clientes = {}
        
        self.criar_interface()
        
    def criar_interface(self):
        """Cria a interface gráfica principal"""
        
        # Frame superior com informações
        frame_superior = ttk.Frame(self.root)
        frame_superior.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(frame_superior, text="Status do Servidor", font=("Arial", 14, "bold")).pack(side=tk.LEFT)
        self.label_status = ttk.Label(frame_superior, text="● Offline", foreground="red", font=("Arial", 12))
        self.label_status.pack(side=tk.LEFT, padx=10)
        
        self.label_clientes = ttk.Label(frame_superior, text="Clientes: 0", font=("Arial", 12))
        self.label_clientes.pack(side=tk.LEFT, padx=10)
        
        # Frame para a tabela de clientes
        frame_tabela = ttk.LabelFrame(self.root, text="Clientes Conectados", padding=10)
        frame_tabela.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Criar treeview
        self.tree = ttk.Treeview(
            frame_tabela,
            columns=("ID", "IP", "PC", "SO", "Status", "Último Contato"),
            height=15,
            show="headings"
        )
        
        # Definir colunas
        self.tree.column("ID", width=30, anchor=tk.W)
        self.tree.column("IP", width=120, anchor=tk.W)
        self.tree.column("PC", width=120, anchor=tk.W)
        self.tree.column("SO", width=100, anchor=tk.W)
        self.tree.column("Status", width=80, anchor=tk.CENTER)
        self.tree.column("Último Contato", width=150, anchor=tk.W)
        
        self.tree.heading("ID", text="ID")
        self.tree.heading("IP", text="IP do Cliente")
        self.tree.heading("PC", text="Nome do PC")
        self.tree.heading("SO", text="Sistema Operacional")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Último Contato", text="Último Contato")
        
        scrollbar = ttk.Scrollbar(frame_tabela, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Frame para botões de controle
        frame_botoes = ttk.LabelFrame(self.root, text="Controles", padding=10)
        frame_botoes.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            frame_botoes,
            text="🔒 Bloquear PC",
            command=lambda: self.enviar_comando("bloquear")
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            frame_botoes,
            text="🔄 Reiniciar",
            command=lambda: self.enviar_comando("reiniciar")
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            frame_botoes,
            text="⏻ Desligar",
            command=lambda: self.enviar_comando("desligar")
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            frame_botoes,
            text="🔄 Atualizar",
            command=self.atualizar_lista
        ).pack(side=tk.LEFT, padx=5)
        
        # Frame para informações detalhadas
        frame_detalhes = ttk.LabelFrame(self.root, text="Informações do Cliente Selecionado", padding=10)
        frame_detalhes.pack(fill=tk.X, padx=10, pady=10)
        
        self.label_detalhes = ttk.Label(frame_detalhes, text="Selecione um cliente para ver detalhes", justify=tk.LEFT)
        self.label_detalhes.pack(fill=tk.X)
        
        # Vincular seleção na tabela
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        
        # Adicionar alguns clientes de exemplo
        self.adicionar_cliente_exemplo()
    
    def adicionar_cliente_exemplo(self):
        """Adiciona clientes de exemplo para demonstração"""
        exemplos = [
            ("1", "192.168.1.10", "PC-SALA-01", "Windows 10", "Online", "2024-01-15 10:30:45"),
            ("2", "192.168.1.11", "PC-SALA-02", "Windows 10", "Online", "2024-01-15 10:30:42"),
            ("3", "192.168.1.12", "PC-LAB-01", "Ubuntu 22.04", "Online", "2024-01-15 10:30:40"),
            ("4", "192.168.1.13", "PC-GERENCIA", "Windows 11", "Offline", "2024-01-15 09:45:20"),
        ]
        
        for exemplo in exemplos:
            self.tree.insert("", tk.END, values=exemplo)
        
        self.label_clientes.config(text=f"Clientes: {len(exemplos)}")
    
    def on_select(self, event):
        """Chamado quando um cliente é selecionado"""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            valores = self.tree.item(item)['values']
            
            detalhes = f"""
ID: {valores[0]}
IP: {valores[1]}
Nome do PC: {valores[2]}
Sistema Operacional: {valores[3]}
Status: {valores[4]}
Último Contato: {valores[5]}
Processador: Intel Core i5
Memória RAM: 8 GB
Armazenamento: 500 GB SSD
            """
            self.label_detalhes.config(text=detalhes)
    
    def enviar_comando(self, comando):
        """Envia comando para o cliente selecionado"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um cliente para enviar comando")
            return
        
        item = selection[0]
        valores = self.tree.item(item)['values']
        cliente_id = valores[0]
        cliente_nome = valores[2]
        
        # Confirmar ação
        mensagens = {
            "bloquear": f"Deseja bloquear o PC {cliente_nome}?",
            "reiniciar": f"Deseja reiniciar o PC {cliente_nome}?",
            "desligar": f"Deseja desligar o PC {cliente_nome}?"
        }
        
        if messagebox.askyesno("Confirmar", mensagens[comando]):
            messagebox.showinfo("Sucesso", f"Comando '{comando}' enviado para {cliente_nome}")
    
    def atualizar_lista(self):
        """Atualiza a lista de clientes"""
        messagebox.showinfo("Atualizado", "Lista de clientes atualizada")


if __name__ == "__main__":
    root = tk.Tk()
    app = InterfaceGerenciamento(root)
    root.mainloop()
