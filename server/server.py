"""
Servidor Central - Painel de Gerenciamento de Laboratórios
Gerencia comunicação com clientes e coordena operações
"""

import socket
import threading
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import sys
import os

# Adicionar diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db_manager import db_manager
from utils.logger import Logger
from utils.crypto import CryptoManager, crypto_manager
from utils.validators import Validator
from utils.constants import *


class Server:
    """Servidor central de gerenciamento"""
    
    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """
        Inicializar servidor
        
        Args:
            host: Host de escuta
            port: Porta de escuta
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.clients: Dict[str, socket.socket] = {}
        self.client_info: Dict[str, Dict] = {}
        self.logger = Logger.get_logger('server')
        self.lock = threading.Lock()
    
    def start(self):
        """Iniciar o servidor"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"\n{'='*60}")
            print(f"🖥️  PAINEL DE GERENCIAMENTO DE LABORATÓRIOS")
            print(f"{'='*60}")
            print(f"✓ Servidor iniciado em {self.host}:{self.port}")
            print(f"✓ Aguardando conexões de clientes...")
            print(f"{'='*60}\n")
            
            Logger.log_system_event('SERVER_START', f'Servidor iniciado em {self.host}:{self.port}')
            
            # Thread para aceitar conexões
            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
            
            # Manter servidor rodando
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()
        
        except Exception as e:
            self.logger.error(f"Erro ao iniciar servidor: {e}")
            print(f"✗ Erro ao iniciar servidor: {e}")
    
    def stop(self):
        """Parar o servidor"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Desconectar todos os clientes
        for client_socket in self.clients.values():
            try:
                client_socket.close()
            except:
                pass
        
        print(f"\n✓ Servidor parado")
        Logger.log_system_event('SERVER_STOP', 'Servidor parado')
    
    def _accept_connections(self):
        """Aceitar conexões de clientes"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"\n📡 Nova conexão de {client_address[0]}:{client_address[1]}")
                
                # Thread para lidar com cliente
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
            
            except Exception as e:
                if self.running:
                    self.logger.error(f"Erro ao aceitar conexão: {e}")
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """
        Lidar com cliente conectado
        
        Args:
            client_socket: Socket do cliente
            client_address: Endereço do cliente
        """
        client_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            while self.running:
                # Receber dados
                data = client_socket.recv(CLIENT_BUFFER_SIZE).decode('utf-8')
                
                if not data:
                    break
                
                # Processar mensagem
                self._process_message(client_socket, client_id, data, client_address[0])
        
        except Exception as e:
            self.logger.error(f"Erro ao lidar com cliente {client_id}: {e}")
        
        finally:
            self._disconnect_client(client_socket, client_id)
    
    def _process_message(self, client_socket: socket.socket, client_id: str, data: str, ip: str):
        """
        Processar mensagem do cliente
        
        Args:
            client_socket: Socket do cliente
            client_id: ID do cliente
            data: Dados recebidos
            ip: IP do cliente
        """
        try:
            message = json.loads(data)
            command = message.get('command', '').lower()
            
            print(f"\n📨 Mensagem de {client_id}: {command}")
            
            if command == 'register':
                self._handle_register(client_socket, client_id, message, ip)
            
            elif command == 'system_info':
                self._handle_system_info(client_socket, client_id, message)
            
            elif command == 'heartbeat':
                self._handle_heartbeat(client_socket, client_id, message)
            
            elif command == 'authenticate':
                self._handle_authenticate(client_socket, client_id, message)
            
            else:
                self._send_response(client_socket, {
                    'status': 'error',
                    'message': f'Comando desconhecido: {command}'
                })
        
        except json.JSONDecodeError:
            self.logger.error(f"Erro ao decodificar JSON de {client_id}")
            self._send_response(client_socket, {
                'status': 'error',
                'message': 'JSON inválido'
            })
        
        except Exception as e:
            self.logger.error(f"Erro ao processar mensagem de {client_id}: {e}")
    
    def _handle_register(self, client_socket: socket.socket, client_id: str, message: Dict, ip: str):
        """
        Lidar com registro de computador
        
        Args:
            client_socket: Socket do cliente
            client_id: ID do cliente
            message: Mensagem do cliente
            ip: IP do cliente
        """
        try:
            computer_name = message.get('computer_name', '')
            mac_address = message.get('mac_address', '')
            os_name = message.get('os_name', '')
            os_version = message.get('os_version', '')
            processor = message.get('processor', '')
            ram_gb = message.get('ram_gb', 0)
            disk_gb = message.get('disk_gb', 0)
            lab_name = message.get('lab_name', 'Laboratório')
            
            if not computer_name:
                self._send_response(client_socket, {
                    'status': 'error',
                    'message': 'Nome do computador não fornecido'
                })
                return
            
            # Verificar se computador já existe
            existing = db_manager.get_computer(computer_name)
            
            if existing:
                computer_id = existing['id']
                print(f"✓ Computador {computer_name} já registrado")
            else:
                # Adicionar novo computador
                computer_id = db_manager.add_computer(
                    computer_name=computer_name,
                    ip_address=ip,
                    mac_address=mac_address,
                    os_name=os_name,
                    os_version=os_version,
                    processor=processor,
                    ram_gb=ram_gb,
                    disk_gb=disk_gb,
                    lab_name=lab_name
                )
                print(f"✓ Computador {computer_name} registrado com sucesso!")
            
            # Atualizar status
            db_manager.update_computer_status(computer_id, COMPUTER_STATUS_ONLINE)
            
            # Guardar informações do cliente
            with self.lock:
                self.clients[client_id] = client_socket
                self.client_info[client_id] = {
                    'computer_id': computer_id,
                    'computer_name': computer_name,
                    'ip_address': ip,
                    'connected_at': datetime.now().isoformat()
                }
            
            Logger.log_connection(computer_name, ip, 'connected')
            
            self._send_response(client_socket, {
                'status': 'success',
                'message': 'Computador registrado com sucesso',
                'computer_id': computer_id
            })
        
        except Exception as e:
            self.logger.error(f"Erro ao registrar computador: {e}")
            self._send_response(client_socket, {
                'status': 'error',
                'message': f'Erro ao registrar: {str(e)}'
            })
    
    def _handle_system_info(self, client_socket: socket.socket, client_id: str, message: Dict):
        """
        Lidar com informações de sistema
        
        Args:
            client_socket: Socket do cliente
            client_id: ID do cliente
            message: Mensagem do cliente
        """
        try:
            if client_id not in self.client_info:
                self._send_response(client_socket, {
                    'status': 'error',
                    'message': 'Cliente não registrado'
                })
                return
            
            computer_id = self.client_info[client_id]['computer_id']
            
            # Extrair métricas
            cpu_usage = message.get('cpu_usage', 0)
            memory_usage = message.get('memory_usage', 0)
            disk_usage = message.get('disk_usage', 0)
            network_sent = message.get('network_sent', 0)
            network_received = message.get('network_received', 0)
            temperature = message.get('temperature')
            uptime_seconds = message.get('uptime_seconds', 0)
            processes = message.get('processes', [])
            
            # Salvar métricas
            db_manager.add_system_metrics(
                computer_id=computer_id,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                disk_usage=disk_usage,
                network_sent=network_sent,
                network_received=network_received,
                temperature=temperature,
                uptime_seconds=uptime_seconds
            )
            
            # Salvar processos
            for process in processes[:20]:  # Limitar a 20 processos
                db_manager.add_process(
                    computer_id=computer_id,
                    process_name=process.get('name', ''),
                    process_id=process.get('pid', 0),
                    cpu_usage=process.get('cpu', 0),
                    memory_usage=process.get('memory', 0),
                    memory_percent=process.get('memory_percent', 0)
                )
            
            # Verificar alertas
            alerts = []
            if cpu_usage > CPU_ALERT_THRESHOLD:
                alerts.append(f'CPU acima de {CPU_ALERT_THRESHOLD}%')
            if memory_usage > MEMORY_ALERT_THRESHOLD:
                alerts.append(f'Memória acima de {MEMORY_ALERT_THRESHOLD}%')
            if disk_usage > DISK_ALERT_THRESHOLD:
                alerts.append(f'Disco acima de {DISK_ALERT_THRESHOLD}%')
            
            self._send_response(client_socket, {
                'status': 'success',
                'message': 'Métricas recebidas com sucesso',
                'alerts': alerts
            })
        
        except Exception as e:
            self.logger.error(f"Erro ao processar system_info: {e}")
            self._send_response(client_socket, {
                'status': 'error',
                'message': f'Erro ao processar métricas: {str(e)}'
            })
    
    def _handle_heartbeat(self, client_socket: socket.socket, client_id: str, message: Dict):
        """
        Lidar com heartbeat do cliente
        
        Args:
            client_socket: Socket do cliente
            client_id: ID do cliente
            message: Mensagem do cliente
        """
        try:
            if client_id in self.client_info:
                computer_id = self.client_info[client_id]['computer_id']
                db_manager.update_computer_status(computer_id, COMPUTER_STATUS_ONLINE)
            
            # Verificar se há comandos pendentes
            if client_id in self.client_info:
                computer_id = self.client_info[client_id]['computer_id']
                
                # Obter comandos pendentes
                pending_commands = db_manager.get_pending_commands(computer_id)
                
                # Obter mensagens pendentes
                pending_messages = db_manager.get_pending_messages(computer_id)
                
                response = {
                    'status': 'success',
                    'commands': [dict(cmd) for cmd in pending_commands],
                    'messages': [dict(msg) for msg in pending_messages]
                }
            else:
                response = {'status': 'success'}
            
            self._send_response(client_socket, response)
        
        except Exception as e:
            self.logger.error(f"Erro ao processar heartbeat: {e}")
    
    def _handle_authenticate(self, client_socket: socket.socket, client_id: str, message: Dict):
        """
        Lidar com autenticação
        
        Args:
            client_socket: Socket do cliente
            client_id: ID do cliente
            message: Mensagem do cliente
        """
        try:
            token = message.get('token', '')
            
            # Verificar token
            session = db_manager.get_session(token)
            
            if session and session['is_active']:
                self._send_response(client_socket, {
                    'status': 'success',
                    'message': 'Autenticação bem-sucedida'
                })
            else:
                self._send_response(client_socket, {
                    'status': 'error',
                    'message': 'Token inválido ou expirado'
                })
        
        except Exception as e:
            self.logger.error(f"Erro ao autenticar: {e}")
            self._send_response(client_socket, {
                'status': 'error',
                'message': 'Erro na autenticação'
            })
    
    def _disconnect_client(self, client_socket: socket.socket, client_id: str):
        """
        Desconectar cliente
        
        Args:
            client_socket: Socket do cliente
            client_id: ID do cliente
        """
        try:
            client_socket.close()
        except:
            pass
        
        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]
            
            if client_id in self.client_info:
                info = self.client_info[client_id]
                computer_id = info['computer_id']
                computer_name = info['computer_name']
                ip_address = info['ip_address']
                
                # Atualizar status
                db_manager.update_computer_status(computer_id, COMPUTER_STATUS_OFFLINE)
                
                Logger.log_connection(computer_name, ip_address, 'disconnected')
                print(f"📡 {computer_name} desconectado")
                
                del self.client_info[client_id]
    
    def _send_response(self, client_socket: socket.socket, response: Dict):
        """
        Enviar resposta ao cliente
        
        Args:
            client_socket: Socket do cliente
            response: Dicionário de resposta
        """
        try:
            data = json.dumps(response)
            client_socket.sendall(data.encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Erro ao enviar resposta: {e}")
    
    def send_command_to_computer(self, computer_id: int, command_type: str, command_data: str = ''):
        """
        Enviar comando para computador
        
        Args:
            computer_id: ID do computador
            command_type: Tipo de comando
            command_data: Dados do comando
        """
        # Encontrar cliente correspondente
        for client_id, info in self.client_info.items():
            if info['computer_id'] == computer_id:
                client_socket = self.clients.get(client_id)
                if client_socket:
                    command = {
                        'command': command_type,
                        'data': command_data
                    }
                    self._send_response(client_socket, command)
                    return True
        
        return False
    
    def broadcast_message(self, message: str, computer_ids: List[int] = None):
        """
        Enviar mensagem para computador(es)
        
        Args:
            message: Mensagem a enviar
            computer_ids: Lista de IDs de computadores (None = todos)
        """
        count = 0
        for client_id, info in self.client_info.items():
            if computer_ids is None or info['computer_id'] in computer_ids:
                client_socket = self.clients.get(client_id)
                if client_socket:
                    msg = {
                        'command': 'message',
                        'message': message
                    }
                    self._send_response(client_socket, msg)
                    count += 1
        
        return count
    
    def get_connected_clients(self) -> List[Dict]:
        """Obter lista de clientes conectados"""
        clients_list = []
        for client_id, info in self.client_info.items():
            clients_list.append({
                'client_id': client_id,
                'computer_name': info['computer_name'],
                'ip_address': info['ip_address'],
                'connected_at': info['connected_at']
            })
        return clients_list
    
    def get_statistics(self) -> Dict:
        """Obter estatísticas do servidor"""
        computers = db_manager.get_all_computers()
        online_count = sum(1 for c in computers if c['status'] == COMPUTER_STATUS_ONLINE)
        offline_count = len(computers) - online_count
        
        # Calcular médias
        total_cpu = 0
        total_memory = 0
        count = 0
        
        for computer in computers:
            if computer['status'] == COMPUTER_STATUS_ONLINE:
                metrics = db_manager.get_latest_metrics(computer['id'])
                if metrics:
                    total_cpu += metrics['cpu_usage']
                    total_memory += metrics['memory_usage']
                    count += 1
        
        avg_cpu = total_cpu / count if count > 0 else 0
        avg_memory = total_memory / count if count > 0 else 0
        
        return {
            'total_computers': len(computers),
            'online_computers': online_count,
            'offline_computers': offline_count,
            'average_cpu': avg_cpu,
            'average_memory': avg_memory,
            'connected_clients': len(self.clients)
        }


if __name__ == '__main__':
    server = Server()
    server.start()
