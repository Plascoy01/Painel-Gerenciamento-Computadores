"""
Módulo de validadores - Validação de dados e entrada
"""

import re
import socket
from ipaddress import ip_address, AddressValueError


class Validator:
    """Classe para validação de dados"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validar formato de email
        
        Args:
            email: Email a validar
            
        Returns:
            bool: True se válido
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """
        Validar endereço IP
        
        Args:
            ip: Endereço IP a validar
            
        Returns:
            bool: True se válido
        """
        try:
            ip_address(ip)
            return True
        except AddressValueError:
            return False
    
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """
        Validar nome de host
        
        Args:
            hostname: Nome de host a validar
            
        Returns:
            bool: True se válido
        """
        if len(hostname) > 255:
            return False
        
        # Remover o ponto final se existir
        if hostname.endswith("."):
            hostname = hostname[:-1]
        
        # Permitir nomes simples e FQDN
        allowed = re.compile(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$")
        return allowed.match(hostname) is not None
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """
        Validar número de porta
        
        Args:
            port: Número da porta
            
        Returns:
            bool: True se válido
        """
        return 0 < port < 65536
    
    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> dict:
        """
        Validar força da senha
        
        Args:
            password: Senha a validar
            min_length: Comprimento mínimo
            
        Returns:
            dict: Resultado da validação
        """
        result = {
            'valid': True,
            'errors': [],
            'strength': 'weak'
        }
        
        if len(password) < min_length:
            result['valid'] = False
            result['errors'].append(f'Senha deve ter no mínimo {min_length} caracteres')
        
        if not re.search(r'[a-z]', password):
            result['errors'].append('Senha deve conter letras minúsculas')
        
        if not re.search(r'[A-Z]', password):
            result['errors'].append('Senha deve conter letras maiúsculas')
        
        if not re.search(r'[0-9]', password):
            result['errors'].append('Senha deve conter números')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            result['errors'].append('Senha deve conter caracteres especiais')
        
        # Calcular força
        score = 0
        if len(password) >= min_length:
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        
        if score == 5:
            result['strength'] = 'strong'
        elif score >= 3:
            result['strength'] = 'medium'
        else:
            result['strength'] = 'weak'
        
        return result
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """
        Validar nome de usuário
        
        Args:
            username: Nome de usuário
            
        Returns:
            bool: True se válido
        """
        # 3-20 caracteres, apenas alfanuméricos, underscore e hífen
        pattern = r'^[a-zA-Z0-9_-]{3,20}$'
        return re.match(pattern, username) is not None
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: int = 2) -> bool:
        """
        Verificar se uma porta está aberta
        
        Args:
            host: Host a verificar
            port: Porta a verificar
            timeout: Timeout em segundos
            
        Returns:
            bool: True se porta está aberta
        """
        try:
            socket.settimeout(timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = 255) -> str:
        """
        Sanitizar string removendo caracteres perigosos
        
        Args:
            text: Texto a sanitizar
            max_length: Comprimento máximo
            
        Returns:
            str: Texto sanitizado
        """
        # Remover caracteres nulos
        text = text.replace('\x00', '')
        
        # Limitar comprimento
        text = text[:max_length]
        
        return text.strip()
    
    @staticmethod
    def validate_command(command: str) -> bool:
        """
        Validar um comando
        
        Args:
            command: Comando a validar
            
        Returns:
            bool: True se válido
        """
        # Comandos válidos
        valid_commands = [
            'ping', 'pong', 'register', 'system_info',
            'shutdown', 'restart', 'message', 'get_apps',
            'authenticate', 'heartbeat'
        ]
        return command.lower() in valid_commands
