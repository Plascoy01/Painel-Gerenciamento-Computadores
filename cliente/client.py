#!/usr/bin/env python3
"""
Cliente de Computador Gerenciado
Conecta ao servidor para receber comandos
"""

import socket
import json
import threading
import time
from datetime import datetime
import os
import subprocess
import platform

class ClientePC:
    def __init__(self, servidor_host='localhost', servidor_porta=5000):
        self.servidor_host = servidor_host
        self.servidor_porta = servidor_porta
        self.socket_cliente = None
        self.conectado = False
        self.rodando = True
        
    def conectar(self):
        """Conecta ao servidor de gerenciamento"""
        try:
            self.socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_cliente.connect((self.servidor_host, self.servidor_porta))
            self.conectado = True
            print(f"[CLIENTE] Conectado ao servidor {self.servidor_host}:{self.servidor_porta}")
            
            # Thread para enviar informações
            thread_enviar = threading.Thread(target=self.enviar_info, daemon=True)
            thread_enviar.start()
            
            # Thread para receber comandos
            thread_receber = threading.Thread(target=self.receber_comandos, daemon=True)
            thread_receber.start()
            
        except Exception as e:
            print(f"[ERRO] Falha ao conectar: {e}")
            self.conectado = False
    
    def obter_info_sistema(self):
        """Obtém informações do sistema"""
        try:
            info = {
                'nome_pc': platform.node(),
                'sistema': platform.system(),
                'versao': platform.version(),
                'processador': platform.processor(),
                'timestamp': datetime.now().isoformat()
            }
            return info
        except Exception as e:
            print(f"[ERRO] Obtendo info: {e}")
            return {}
    
    def enviar_info(self):
        """Envia informações do PC para o servidor periodicamente"""
        while self.rodando and self.conectado:
            try:
                info = self.obter_info_sistema()
                mensagem = json.dumps({
                    'tipo': 'info',
                    'dados': info
                })
                self.socket_cliente.send(mensagem.encode('utf-8'))
                time.sleep(10)  # Enviar a cada 10 segundos
                
            except Exception as e:
                print(f"[ERRO] Enviando info: {e}")
                self.conectado = False
                break
    
    def receber_comandos(self):
        """Recebe e processa comandos do servidor"""
        while self.rodando and self.conectado:
            try:
                dados = self.socket_cliente.recv(4096).decode('utf-8')
                
                if not dados:
                    break
                
                try:
                    mensagem = json.loads(dados)
                    self.processar_comando(mensagem)
                except json.JSONDecodeError:
                    print(f"[ERRO] Formato JSON inválido")
                    
            except Exception as e:
                print(f"[ERRO] Recebendo comandos: {e}")
                self.conectado = False
                break
    
    def processar_comando(self, mensagem):
        """Processa comandos recebidos do servidor"""
        comando = mensagem.get('comando')
        
        if comando == 'desligar':
            print("[COMANDO] Desligando PC em 60 segundos...")
            threading.Thread(target=self.desligar_pc, daemon=True).start()
            
        elif comando == 'reiniciar':
            print("[COMANDO] Reiniciando PC em 60 segundos...")
            threading.Thread(target=self.reiniciar_pc, daemon=True).start()
            
        elif comando == 'bloquear':
            print("[COMANDO] Bloqueando PC...")
            self.bloquear_pc()
            
        else:
            print(f"[COMANDO DESCONHECIDO] {comando}")
    
    def desligar_pc(self):
        """Desliga o PC"""
        try:
            time.sleep(60)  # Aguardar 60 segundos
            if platform.system() == 'Windows':
                os.system('shutdown /s /t 0')
            else:
                os.system('shutdown -h now')
        except Exception as e:
            print(f"[ERRO] Desligando: {e}")
    
    def reiniciar_pc(self):
        """Reinicia o PC"""
        try:
            time.sleep(60)  # Aguardar 60 segundos
            if platform.system() == 'Windows':
                os.system('shutdown /r /t 0')
            else:
                os.system('shutdown -r now')
        except Exception as e:
            print(f"[ERRO] Reiniciando: {e}")
    
    def bloquear_pc(self):
        """Bloqueia a tela do PC"""
        try:
            if platform.system() == 'Windows':
                os.system('rundll32.exe user32.dll,LockWorkStation')
            else:
                os.system('gnome-screensaver-command -l')
        except Exception as e:
            print(f"[ERRO] Bloqueando: {e}")
    
    def manter_conexao(self):
        """Mantém o cliente rodando"""
        while self.rodando:
            if not self.conectado:
                print("[CLIENTE] Tentando reconectar...")
                time.sleep(5)
                self.conectar()
            time.sleep(1)
    
    def fechar(self):
        """Fecha a conexão do cliente"""
        print("\n[CLIENTE] Encerrando...")
        self.rodando = False
        if self.socket_cliente:
            try:
                self.socket_cliente.close()
            except:
                pass
        print("[CLIENTE] Encerrado")


if __name__ == "__main__":
    # Configurar IP do servidor (alterar conforme necessário)
    servidor_ip = '192.168.1.100'  # Alterar para o IP do servidor
    
    cliente = ClientePC(servidor_host=servidor_ip, servidor_porta=5000)
    cliente.conectar()
    
    try:
        cliente.manter_conexao()
    except KeyboardInterrupt:
        cliente.rodando = False
        print("\n[CLIENTE] Interrompido pelo usuário")
    finally:
        cliente.fechar()
