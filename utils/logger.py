"""
Módulo de logging - Sistema de registros de operações
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler


class Logger:
    """Gerenciador centralizado de logs"""
    
    _loggers = {}
    LOGS_DIR = 'logs'
    
    @classmethod
    def setup_logging(cls, name: str = 'system', level=logging.INFO) -> logging.Logger:
        """
        Configurar um logger
        
        Args:
            name: Nome do logger
            level: Nível de logging
            
        Returns:
            logging.Logger: Logger configurado
        """
        if name in cls._loggers:
            return cls._loggers[name]
        
        # Criar diretório de logs se não existir
        Path(cls.LOGS_DIR).mkdir(exist_ok=True)
        
        # Criar logger
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Formato de log
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%d/%m/%Y %H:%M:%S'
        )
        
        # Handler para arquivo
        log_file = os.path.join(cls.LOGS_DIR, f'{name}_{datetime.now().strftime("%Y%m%d")}.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(log_format)
        
        # Handler para console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(log_format)
        
        # Adicionar handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        cls._loggers[name] = logger
        return logger
    
    @classmethod
    def get_logger(cls, name: str = 'system') -> logging.Logger:
        """
        Obter um logger já configurado
        
        Args:
            name: Nome do logger
            
        Returns:
            logging.Logger: Logger
        """
        if name not in cls._loggers:
            return cls.setup_logging(name)
        return cls._loggers[name]
    
    @classmethod
    def log_action(cls, action: str, user: str = 'system', status: str = 'success', details: str = ''):
        """
        Registrar uma ação do administrador
        
        Args:
            action: Descrição da ação
            user: Usuário que realizou a ação
            status: Status da ação (success, failed, warning)
            details: Detalhes adicionais
        """
        logger = cls.get_logger('actions')
        message = f"[{user}] {action}"
        if details:
            message += f" - {details}"
        
        if status == 'success':
            logger.info(message)
        elif status == 'failed':
            logger.error(message)
        elif status == 'warning':
            logger.warning(message)
    
    @classmethod
    def log_system_event(cls, event_type: str, message: str, details: dict = None):
        """
        Registrar um evento do sistema
        
        Args:
            event_type: Tipo de evento
            message: Mensagem
            details: Detalhes adicionais
        """
        logger = cls.get_logger('system')
        log_message = f"[{event_type}] {message}"
        if details:
            log_message += f" - {details}"
        
        logger.info(log_message)
    
    @classmethod
    def log_connection(cls, computer_name: str, ip_address: str, event: str):
        """
        Registrar evento de conexão
        
        Args:
            computer_name: Nome do computador
            ip_address: Endereço IP
            event: Tipo de evento (connected, disconnected, reconnected)
        """
        logger = cls.get_logger('connections')
        logger.info(f"{computer_name} ({ip_address}) - {event}")
    
    @classmethod
    def log_error(cls, logger_name: str, error: Exception, context: str = ''):
        """
        Registrar um erro
        
        Args:
            logger_name: Nome do logger
            error: Exception
            context: Contexto do erro
        """
        logger = cls.get_logger(logger_name)
        logger.error(f"{context} - {str(error)}", exc_info=True)


# Configurar loggers padrão
Logger.setup_logging('system')
Logger.setup_logging('actions')
Logger.setup_logging('connections')
Logger.setup_logging('server')
Logger.setup_logging('client')
