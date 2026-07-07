"""
Módulo de banco de dados - Gerenciamento do SQLite
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple


class DatabaseManager:
    """Gerenciador de banco de dados SQLite"""
    
    def __init__(self, db_path: str = 'database/panel_management.db'):
        """
        Inicializar o gerenciador de banco de dados
        
        Args:
            db_path: Caminho do arquivo SQLite
        """
        self.db_path = db_path
        self.connection = None
        self.initialize()
    
    def initialize(self):
        """Inicializar o banco de dados e criar tabelas"""
        # Criar diretório se não existir
        Path(os.path.dirname(self.db_path)).mkdir(parents=True, exist_ok=True)
        
        # Conectar ao banco
        self.connect()
        
        # Criar tabelas
        self.create_tables()
    
    def connect(self):
        """Conectar ao banco de dados"""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            print(f"✓ Banco de dados conectado: {self.db_path}")
        except sqlite3.Error as e:
            print(f"✗ Erro ao conectar: {e}")
            raise
    
    def disconnect(self):
        """Desconectar do banco de dados"""
        if self.connection:
            self.connection.close()
            print("✓ Banco de dados desconectado")
    
    def create_tables(self):
        """Criar todas as tabelas do sistema"""
        cursor = self.connection.cursor()
        
        try:
            # Tabela de Administradores
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS administrators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    full_name TEXT,
                    role TEXT DEFAULT 'admin',
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Tabela de Computadores
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS computers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    computer_name TEXT UNIQUE NOT NULL,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    processor TEXT,
                    ram_gb INTEGER,
                    disk_gb INTEGER,
                    status TEXT DEFAULT 'offline',
                    last_seen TIMESTAMP,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    location TEXT,
                    lab_name TEXT
                )
            ''')
            
            # Tabela de Status Online/Offline
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS computer_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    computer_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT,
                    FOREIGN KEY (computer_id) REFERENCES computers(id)
                )
            ''')
            
            # Tabela de Métricas de Sistema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    computer_id INTEGER NOT NULL,
                    cpu_usage REAL,
                    memory_usage REAL,
                    disk_usage REAL,
                    network_sent INTEGER,
                    network_received INTEGER,
                    temperature REAL,
                    uptime_seconds INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (computer_id) REFERENCES computers(id)
                )
            ''')
            
            # Tabela de Aplicativos em Execução
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS running_processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    computer_id INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    process_id INTEGER,
                    cpu_usage REAL,
                    memory_usage REAL,
                    memory_percent REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (computer_id) REFERENCES computers(id)
                )
            ''')
            
            # Tabela de Mensagens
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id INTEGER NOT NULL,
                    computer_id INTEGER,
                    message_text TEXT NOT NULL,
                    message_type TEXT DEFAULT 'info',
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delivered_at TIMESTAMP,
                    read_at TIMESTAMP,
                    FOREIGN KEY (admin_id) REFERENCES administrators(id),
                    FOREIGN KEY (computer_id) REFERENCES computers(id)
                )
            ''')
            
            # Tabela de Comandos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id INTEGER NOT NULL,
                    computer_id INTEGER,
                    command_type TEXT NOT NULL,
                    command_data TEXT,
                    status TEXT DEFAULT 'pending',
                    result TEXT,
                    executed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (admin_id) REFERENCES administrators(id),
                    FOREIGN KEY (computer_id) REFERENCES computers(id)
                )
            ''')
            
            # Tabela de Logs de Ação
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS action_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id INTEGER,
                    computer_id INTEGER,
                    action_type TEXT NOT NULL,
                    action_description TEXT,
                    status TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (admin_id) REFERENCES administrators(id),
                    FOREIGN KEY (computer_id) REFERENCES computers(id)
                )
            ''')
            
            # Tabela de Sessões de Login
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id INTEGER NOT NULL,
                    token TEXT UNIQUE,
                    ip_address TEXT,
                    user_agent TEXT,
                    login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    logout_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (admin_id) REFERENCES administrators(id)
                )
            ''')
            
            # Tabela de Configurações
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_key TEXT UNIQUE NOT NULL,
                    setting_value TEXT,
                    data_type TEXT DEFAULT 'text',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.connection.commit()
            print("✓ Tabelas criadas com sucesso!")
            
        except sqlite3.Error as e:
            print(f"✗ Erro ao criar tabelas: {e}")
            raise
    
    def execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """
        Executar uma query
        
        Args:
            query: Query SQL
            params: Parâmetros da query
            
        Returns:
            sqlite3.Cursor: Cursor com os resultados
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            return cursor
        except sqlite3.Error as e:
            print(f"✗ Erro ao executar query: {e}")
            raise
    
    def fetch_one(self, query: str, params: tuple = ()) -> Dict[str, Any]:
        """
        Obter um registro
        
        Args:
            query: Query SQL
            params: Parâmetros
            
        Returns:
            Dict: Registro como dicionário
        """
        cursor = self.execute_query(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """
        Obter múltiplos registros
        
        Args:
            query: Query SQL
            params: Parâmetros
            
        Returns:
            List[Dict]: Lista de registros
        """
        cursor = self.execute_query(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    # ===== OPERAÇÕES COM ADMINISTRADORES =====
    
    def add_administrator(self, username: str, password_hash: str, email: str = '', full_name: str = '') -> int:
        """Adicionar um novo administrador"""
        query = '''
            INSERT INTO administrators (username, password_hash, email, full_name)
            VALUES (?, ?, ?, ?)
        '''
        cursor = self.execute_query(query, (username, password_hash, email, full_name))
        return cursor.lastrowid
    
    def get_administrator(self, username: str) -> Dict[str, Any]:
        """Obter administrador por username"""
        query = 'SELECT * FROM administrators WHERE username = ? AND is_active = 1'
        return self.fetch_one(query, (username,))
    
    def update_last_login(self, admin_id: int):
        """Atualizar último login"""
        query = 'UPDATE administrators SET last_login = CURRENT_TIMESTAMP WHERE id = ?'
        self.execute_query(query, (admin_id,))
    
    # ===== OPERAÇÕES COM COMPUTADORES =====
    
    def add_computer(self, computer_name: str, ip_address: str, mac_address: str = '',
                    os_name: str = '', os_version: str = '', processor: str = '',
                    ram_gb: int = 0, disk_gb: int = 0, location: str = '', lab_name: str = '') -> int:
        """Adicionar um novo computador"""
        query = '''
            INSERT INTO computers (computer_name, ip_address, mac_address, os_name, 
                                  os_version, processor, ram_gb, disk_gb, location, lab_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        cursor = self.execute_query(query, (computer_name, ip_address, mac_address, os_name,
                                           os_version, processor, ram_gb, disk_gb, location, lab_name))
        return cursor.lastrowid
    
    def get_computer(self, computer_name: str) -> Dict[str, Any]:
        """Obter computador por nome"""
        query = 'SELECT * FROM computers WHERE computer_name = ? AND is_active = 1'
        return self.fetch_one(query, (computer_name,))
    
    def get_all_computers(self) -> List[Dict[str, Any]]:
        """Obter todos os computadores"""
        query = 'SELECT * FROM computers WHERE is_active = 1'
        return self.fetch_all(query)
    
    def update_computer_status(self, computer_id: int, status: str):
        """Atualizar status do computador"""
        query = '''
            UPDATE computers SET status = ?, last_seen = CURRENT_TIMESTAMP 
            WHERE id = ?
        '''
        self.execute_query(query, (status, computer_id))
        
        # Registrar no histórico de status
        query_history = '''
            INSERT INTO computer_status (computer_id, status)
            VALUES (?, ?)
        '''
        self.execute_query(query_history, (computer_id, status))
    
    # ===== OPERAÇÕES COM MÉTRICAS =====
    
    def add_system_metrics(self, computer_id: int, cpu_usage: float, memory_usage: float,
                          disk_usage: float, network_sent: int = 0, network_received: int = 0,
                          temperature: float = None, uptime_seconds: int = 0):
        """Adicionar métricas do sistema"""
        query = '''
            INSERT INTO system_metrics (computer_id, cpu_usage, memory_usage, disk_usage,
                                       network_sent, network_received, temperature, uptime_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        self.execute_query(query, (computer_id, cpu_usage, memory_usage, disk_usage,
                                  network_sent, network_received, temperature, uptime_seconds))
    
    def get_latest_metrics(self, computer_id: int) -> Dict[str, Any]:
        """Obter últimas métricas de um computador"""
        query = '''
            SELECT * FROM system_metrics 
            WHERE computer_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
        '''
        return self.fetch_one(query, (computer_id,))
    
    def get_metrics_history(self, computer_id: int, hours: int = 24) -> List[Dict[str, Any]]:
        """Obter histórico de métricas"""
        query = '''
            SELECT * FROM system_metrics
            WHERE computer_id = ? AND timestamp > datetime('now', '-' || ? || ' hours')
            ORDER BY timestamp DESC
        '''
        return self.fetch_all(query, (computer_id, hours))
    
    # ===== OPERAÇÕES COM PROCESSOS =====
    
    def add_process(self, computer_id: int, process_name: str, process_id: int,
                   cpu_usage: float, memory_usage: float, memory_percent: float):
        """Adicionar processo em execução"""
        query = '''
            INSERT INTO running_processes (computer_id, process_name, process_id,
                                          cpu_usage, memory_usage, memory_percent)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        self.execute_query(query, (computer_id, process_name, process_id,
                                  cpu_usage, memory_usage, memory_percent))
    
    def get_computer_processes(self, computer_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        """Obter processos de um computador"""
        query = '''
            SELECT * FROM running_processes
            WHERE computer_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        '''
        return self.fetch_all(query, (computer_id, limit))
    
    # ===== OPERAÇÕES COM MENSAGENS =====
    
    def add_message(self, admin_id: int, message_text: str, computer_id: int = None,
                   message_type: str = 'info') -> int:
        """Adicionar nova mensagem"""
        query = '''
            INSERT INTO messages (admin_id, computer_id, message_text, message_type)
            VALUES (?, ?, ?, ?)
        '''
        cursor = self.execute_query(query, (admin_id, computer_id, message_text, message_type))
        return cursor.lastrowid
    
    def get_pending_messages(self, computer_id: int) -> List[Dict[str, Any]]:
        """Obter mensagens pendentes para um computador"""
        query = '''
            SELECT * FROM messages
            WHERE computer_id = ? AND status = 'pending'
            ORDER BY created_at ASC
        '''
        return self.fetch_all(query, (computer_id,))
    
    def update_message_status(self, message_id: int, status: str):
        """Atualizar status da mensagem"""
        query = 'UPDATE messages SET status = ?, delivered_at = CURRENT_TIMESTAMP WHERE id = ?'
        self.execute_query(query, (status, message_id))
    
    # ===== OPERAÇÕES COM COMANDOS =====
    
    def add_command(self, admin_id: int, command_type: str, computer_id: int = None,
                   command_data: str = '') -> int:
        """Adicionar novo comando"""
        query = '''
            INSERT INTO commands (admin_id, computer_id, command_type, command_data)
            VALUES (?, ?, ?, ?)
        '''
        cursor = self.execute_query(query, (admin_id, computer_id, command_type, command_data))
        return cursor.lastrowid
    
    def get_pending_commands(self, computer_id: int) -> List[Dict[str, Any]]:
        """Obter comandos pendentes para um computador"""
        query = '''
            SELECT * FROM commands
            WHERE computer_id = ? AND status = 'pending'
            ORDER BY created_at ASC
        '''
        return self.fetch_all(query, (computer_id,))
    
    def update_command_status(self, command_id: int, status: str, result: str = ''):
        """Atualizar status do comando"""
        query = '''
            UPDATE commands 
            SET status = ?, result = ?, executed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        '''
        self.execute_query(query, (status, result, command_id))
    
    # ===== OPERAÇÕES COM LOGS =====
    
    def log_action(self, action_type: str, action_description: str = '', admin_id: int = None,
                  computer_id: int = None, status: str = 'success', ip_address: str = ''):
        """Registrar uma ação"""
        query = '''
            INSERT INTO action_logs (admin_id, computer_id, action_type, action_description, status, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        self.execute_query(query, (admin_id, computer_id, action_type, action_description, status, ip_address))
    
    def get_action_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Obter logs de ações"""
        query = '''
            SELECT * FROM action_logs
            ORDER BY timestamp DESC
            LIMIT ?
        '''
        return self.fetch_all(query, (limit,))
    
    def get_computer_logs(self, computer_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Obter logs de um computador"""
        query = '''
            SELECT * FROM action_logs
            WHERE computer_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        '''
        return self.fetch_all(query, (computer_id, limit))
    
    # ===== OPERAÇÕES COM SESSÕES =====
    
    def create_session(self, admin_id: int, token: str, ip_address: str = '', user_agent: str = '') -> int:
        """Criar nova sessão"""
        query = '''
            INSERT INTO sessions (admin_id, token, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
        '''
        cursor = self.execute_query(query, (admin_id, token, ip_address, user_agent))
        return cursor.lastrowid
    
    def get_session(self, token: str) -> Dict[str, Any]:
        """Obter sessão por token"""
        query = 'SELECT * FROM sessions WHERE token = ? AND is_active = 1'
        return self.fetch_one(query, (token,))
    
    def close_session(self, token: str):
        """Encerrar sessão"""
        query = 'UPDATE sessions SET is_active = 0, logout_at = CURRENT_TIMESTAMP WHERE token = ?'
        self.execute_query(query, (token,))


# Instância global
db_manager = DatabaseManager()
