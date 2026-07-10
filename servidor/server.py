#!/usr/bin/env python3
"""
Servidor de Gerenciamento de Computadores
Controla múltiplos PCs conectados na mesma rede
"""

import socket
import json
import threading
import time
from datetime import datetime
import os
import sys

class ServidorGerenciamento:
    def __init__(self, host='0.0.0.0', porta=5000):
        self.host = host
        self.porta = porta
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clientes_conectados = {}
        self.lock = threading.Lock()
        self.rodando = True
        
    def iniciar(self):
        """Inicia o servidor de gerenciamento"""
        try:
            self.servidor.bind((self.host, self.porta))
            self.servidor.listen(5)
            print(f"[SERVIDOR] Iniciado em {self.host}:{self.porta}")
            print(f"[SERVIDOR] Aguardando conexões de clientes...\n")
            
            # Thread para aceitar conexões
            thread_aceitar = threading.Thread(target=self.aceitar_conexoes, daemon=True)
            thread_aceitar.start()
            
            # Thread para monitorar clientes
            thread_monitor = threading.Thread(target=self.monitorar_clientes, daemon=True)
            thread_monitor.start()
            
            # Manter servidor rodando
            while self.rodando:
                time.sleep(1)
                
        except Exception as e:
            print(f"[ERRO] Falha ao iniciar servidor: {e}")
        finally:
            self.fechar()
    
    def aceitar_conexoes(self):
        """Aceita conexões de novos clientes"""
        while self.rodando:
            try:
                cliente_socket, endereco = self.servidor.accept()
                cliente_id = f"{endereco[0]}:{endereco[1]}"
                
                with self.lock:
                    self.clientes_conectados[cliente_id] = {
                        'socket': cliente_socket,
                        'endereco': endereco,
                        'conectado_em': datetime.now(),
                        'ultima_atividade': datetime.now(),
                        'info': {}
                    }
                
                print(f"[CONECTADO] Cliente {cliente_id} conectado")
                
                # Thread para gerenciar este cliente
                thread_cliente = threading.Thread(
                    target=self.gerenciar_cliente,
                    args=(cliente_id,),
                    daemon=True
                )
                thread_cliente.start()
                
            except Exception as e:
                if self.rodando:
                    print(f"[ERRO] Ao aceitar conexão: {e}")
    
    def gerenciar_cliente(self, cliente_id):
        """Gerencia comunicação com um cliente específico"""
        try:
            while self.rodando and cliente_id in self.clientes_conectados:
                cliente_info = self.clientes_conectados[cliente_id]
                socket_cliente = cliente_info['socket']
                
                # Receber dados do cliente
                dados = socket_cliente.recv(4096).decode('utf-8')
                
                if not dados:
                    break
                
                try:
                    mensagem = json.loads(dados)
                    cliente_info['ultima_atividade'] = datetime.now()
                    
                    if mensagem.get('tipo') == 'info':
                        cliente_info['info'] = mensagem.get('dados', {})
                        print(f"[INFO] {cliente_id}: {mensagem.get('dados')}")
                        
                        # Responder ao cliente
                        resposta = {'status': 'ok', 'mensagem': 'Info recebida'}
                        socket_cliente.send(json.dumps(resposta).encode('utf-8'))
                    
                    elif mensagem.get('tipo') == 'comando':
                        resposta = self.processar_comando(cliente_id, mensagem)
                        socket_cliente.send(json.dumps(resposta).encode('utf-8'))
                        
                except json.JSONDecodeError:
                    print(f"[ERRO] Formato JSON inválido de {cliente_id}")
                    
        except Exception as e:
            print(f"[ERRO] Gerenciando cliente {cliente_id}: {e}")
        finally:
            self.desconectar_cliente(cliente_id)
    
    def processar_comando(self, cliente_id, mensagem):
        """Processa comandos enviados ao cliente"""
        comando = mensagem.get('comando')
        
        if comando == 'desligar':
            return {'status': 'ok', 'mensagem': 'PC será desligado em 60 segundos'}
        elif comando == 'reiniciar':
            return {'status': 'ok', 'mensagem': 'PC será reiniciado em 60 segundos'}
        elif comando == 'bloquear':
            return {'status': 'ok', 'mensagem': 'Tela bloqueada'}
        else:
            return {'status': 'erro', 'mensagem': 'Comando desconhecido'}
    
    def monitorar_clientes(self):
        """Monitora status dos clientes conectados"""
        while self.rodando:
            time.sleep(5)
            
            with self.lock:
                print(f"\n[STATUS] Clientes conectados: {len(self.clientes_conectados)}")
                for cliente_id, info in self.clientes_conectados.items():
                    tempo_conectado = (datetime.now() - info['conectado_em']).total_seconds()
                    print(f"  - {cliente_id}: {tempo_conectado:.0f}s | Info: {info['info']}")
                print()
    
    def desconectar_cliente(self, cliente_id):
        """Desconecta um cliente"""
        with self.lock:
            if cliente_id in self.clientes_conectados:
                try:
                    self.clientes_conectados[cliente_id]['socket'].close()
                except:
                    pass
                del self.clientes_conectados[cliente_id]
                print(f"[DESCONECTADO] {cliente_id}")
    
    def enviar_comando_para_cliente(self, cliente_id, comando):
        """Envia comando para um cliente específico"""
        with self.lock:
            if cliente_id in self.clientes_conectados:
                try:
                    socket_cliente = self.clientes_conectados[cliente_id]['socket']
                    mensagem = json.dumps({
                        'tipo': 'comando',
                        'comando': comando,
                        'timestamp': datetime.now().isoformat()
                    })
                    socket_cliente.send(mensagem.encode('utf-8'))
                    return True
                except Exception as e:
                    print(f"[ERRO] Enviando comando: {e}")
                    return False
            return False
    
    def fechar(self):
        """Fecha o servidor"""
        print("\n[SERVIDOR] Encerrando...")
        self.rodando = False
        
        with self.lock:
            for cliente_id in list(self.clientes_conectados.keys()):
                self.desconectar_cliente(cliente_id)
        
        self.servidor.close()
        print("[SERVIDOR] Encerrado")


if __name__ == "__main__":
    servidor = ServidorGerenciamento()
    try:
        servidor.iniciar()
    except KeyboardInterrupt:
        servidor.rodando = False
        print("\n[SERVIDOR] Interrompido pelo usuário")
