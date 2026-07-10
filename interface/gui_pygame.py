#!/usr/bin/env python3
"""
Interface Gráfica Avançada com Pygame para Gerenciamento de Computadores
Interface moderna, responsiva e com múltiplas funcionalidades
"""

import pygame
import json
from datetime import datetime
import threading
import socket
import math

class Botao:
    """Classe para criar botões interativos"""
    def __init__(self, x, y, largura, altura, texto, cor, cor_hover, funcao=None, icone=""):
        self.rect = pygame.Rect(x, y, largura, altura)
        self.texto = texto
        self.icone = icone
        self.cor = cor
        self.cor_hover = cor_hover
        self.cor_original = cor
        self.funcao = funcao
        self.hover = False
        self.ativo = False
        
    def desenhar(self, tela, fonte):
        """Desenha o botão"""
        cor = self.cor_hover if self.hover else self.cor
        
        # Sombra
        pygame.draw.rect(tela, (0, 0, 0, 50), (self.rect.x + 3, self.rect.y + 3, self.rect.width, self.rect.height))
        
        # Botão com borda arredondada
        pygame.draw.rect(tela, cor, self.rect, border_radius=8)
        pygame.draw.rect(tela, (255, 255, 255) if self.hover else (200, 200, 200), self.rect, 2, border_radius=8)
        
        # Texto
        texto_surface = fonte.render(self.texto, True, (255, 255, 255))
        texto_rect = texto_surface.get_rect(center=self.rect.center)
        tela.blit(texto_surface, texto_rect)
    
    def atualizar_mouse(self, mouse_pos):
        """Atualiza estado do hover"""
        self.hover = self.rect.collidepoint(mouse_pos)
    
    def clicou(self, mouse_pos):
        """Verifica se foi clicado"""
        return self.rect.collidepoint(mouse_pos)


class GraficoSistema:
    """Classe para desenhar gráficos de sistema"""
    def __init__(self, x, y, largura, altura, titulo, valor_max=100):
        self.rect = pygame.Rect(x, y, largura, altura)
        self.titulo = titulo
        self.valor_max = valor_max
        self.valor_atual = 0
        self.historico = [0] * 20
        
    def atualizar(self, valor):
        """Atualiza o valor do gráfico"""
        self.valor_atual = min(valor, self.valor_max)
        self.historico.append(self.valor_atual)
        if len(self.historico) > 20:
            self.historico.pop(0)
    
    def desenhar(self, tela, fonte_pequena):
        """Desenha o gráfico"""
        # Fundo
        pygame.draw.rect(tela, (240, 240, 240), self.rect)
        pygame.draw.rect(tela, (200, 200, 200), self.rect, 2)
        
        # Título
        titulo = fonte_pequena.render(self.titulo, True, (0, 0, 0))
        tela.blit(titulo, (self.rect.x + 10, self.rect.y + 5))
        
        # Valor percentual
        percentual = int((self.valor_atual / self.valor_max) * 100)
        valor_texto = fonte_pequena.render(f"{percentual}%", True, (0, 100, 200))
        tela.blit(valor_texto, (self.rect.x + self.rect.width - 60, self.rect.y + 5))
        
        # Barra de progresso
        altura_barra = 15
        y_barra = self.rect.y + self.rect.height - altura_barra - 10
        largura_barra = self.rect.width - 20
        
        # Fundo da barra
        pygame.draw.rect(tela, (200, 200, 200), (self.rect.x + 10, y_barra, largura_barra, altura_barra))
        
        # Barra preenchida
        largura_preenchida = (largura_barra * percentual) // 100
        cor_barra = (0, 200, 0) if percentual < 70 else (255, 200, 0) if percentual < 85 else (255, 0, 0)
        pygame.draw.rect(tela, cor_barra, (self.rect.x + 10, y_barra, largura_preenchida, altura_barra))
        pygame.draw.rect(tela, (0, 0, 0), (self.rect.x + 10, y_barra, largura_barra, altura_barra), 1)
        
        # Linha do gráfico
        if len(self.historico) > 1:
            largura_linha = (largura_barra - 10) / 19
            y_grafico = self.rect.y + 40
            altura_grafico = self.rect.height - 70
            
            for i in range(len(self.historico) - 1):
                x1 = self.rect.x + 15 + (i * largura_linha)
                y1 = y_grafico + altura_grafico - (self.historico[i] / self.valor_max * altura_grafico)
                x2 = self.rect.x + 15 + ((i + 1) * largura_linha)
                y2 = y_grafico + altura_grafico - (self.historico[i + 1] / self.valor_max * altura_grafico)
                
                pygame.draw.line(tela, (0, 150, 255), (x1, y1), (x2, y2), 2)


class PainelDetalhesCliente:
    """Classe para exibir detalhes do cliente"""
    def __init__(self, x, y, largura, altura):
        self.rect = pygame.Rect(x, y, largura, altura)
        self.cliente = None
        self.graficos = []
        self.criar_graficos()
    
    def criar_graficos(self):
        """Cria os gráficos do painel"""
        y_inicio = self.rect.y + 50
        self.graficos = [
            GraficoSistema(self.rect.x + 10, y_inicio, (self.rect.width - 30) // 3, 120, "CPU", 100),
            GraficoSistema(self.rect.x + 10 + (self.rect.width - 30) // 3 + 5, y_inicio, (self.rect.width - 30) // 3, 120, "RAM", 100),
            GraficoSistema(self.rect.x + 10 + (2 * ((self.rect.width - 30) // 3 + 5)), y_inicio, (self.rect.width - 30) // 3, 120, "DISCO", 100),
        ]
    
    def definir_cliente(self, cliente):
        """Define o cliente a ser exibido"""
        self.cliente = cliente
    
    def desenhar(self, tela, fonte_titulo, fonte_normal, fonte_pequena):
        """Desenha o painel de detalhes"""
        # Fundo
        pygame.draw.rect(tela, (245, 245, 245), self.rect)
        pygame.draw.rect(tela, (100, 150, 255), self.rect, 3)
        
        if self.cliente:
            # Título
            titulo = fonte_titulo.render(f"Detalhes: {self.cliente['nome']}", True, (0, 50, 150))
            tela.blit(titulo, (self.rect.x + 15, self.rect.y + 10))
            
            # Gráficos
            for grafico in self.graficos:
                grafico.desenhar(tela, fonte_pequena)
            
            # Informações adicionais
            y_info = self.rect.y + self.rect.height - 100
            infos = [
                f"IP: {self.cliente['ip']}",
                f"SO: {self.cliente['so']}",
                f"Processador: Intel Core i5",
                f"RAM Total: 16 GB",
                f"Disco: 1 TB SSD",
                f"Status: {self.cliente['status']}",
            ]
            
            for idx, info in enumerate(infos):
                col = idx % 3
                row = idx // 3
                x = self.rect.x + 15 + (col * (self.rect.width - 30) // 3)
                y = y_info + (row * 20)
                
                cor = (0, 150, 0) if "Online" in info else (150, 0, 0)
                texto = fonte_pequena.render(info, True, cor)
                tela.blit(texto, (x, y))
        else:
            texto = fonte_normal.render("Selecione um cliente para ver detalhes", True, (150, 150, 150))
            texto_rect = texto.get_rect(center=self.rect.center)
            tela.blit(texto, texto_rect)


class InterfaceGerenciamentoPygame:
    """Interface gráfica principal com Pygame"""
    def __init__(self, largura=1400, altura=900):
        pygame.init()
        self.largura = largura
        self.altura = altura
        self.tela = pygame.display.set_mode((largura, altura))
        pygame.display.set_caption("🖥️ Painel Avançado de Gerenciamento de Computadores")
        
        self.clock = pygame.time.Clock()
        self.rodando = True
        self.fonte_titulo = pygame.font.Font(None, 40)
        self.fonte_normal = pygame.font.Font(None, 22)
        self.fonte_pequena = pygame.font.Font(None, 16)
        
        # Cores modernas
        self.COR_FUNDO = (20, 25, 40)
        self.COR_PAINEL = (30, 35, 50)
        self.COR_DESTAQUE = (100, 150, 255)
        self.COR_SUCESSO = (50, 200, 100)
        self.COR_AVISO = (255, 180, 0)
        self.COR_ERRO = (255, 80, 80)
        self.COR_TEXTO = (255, 255, 255)
        
        # Dados dos clientes com mais informações
        self.clientes = [
            {
                'id': 1, 'ip': '192.168.1.10', 'nome': 'PC-SALA-01', 'so': 'Windows 10', 
                'status': 'Online', 'cpu': 35, 'ram': 60, 'disco': 45, 'ultimo_contato': '10:30:45',
                'processador': 'Intel Core i7', 'ram_total': '16 GB', 'disco_total': '512 GB'
            },
            {
                'id': 2, 'ip': '192.168.1.11', 'nome': 'PC-SALA-02', 'so': 'Windows 10', 
                'status': 'Online', 'cpu': 45, 'ram': 75, 'disco': 55, 'ultimo_contato': '10:30:42',
                'processador': 'Intel Core i5', 'ram_total': '8 GB', 'disco_total': '256 GB'
            },
            {
                'id': 3, 'ip': '192.168.1.12', 'nome': 'PC-LAB-01', 'so': 'Ubuntu 22.04', 
                'status': 'Online', 'cpu': 20, 'ram': 40, 'disco': 30, 'ultimo_contato': '10:30:40',
                'processador': 'AMD Ryzen 5', 'ram_total': '32 GB', 'disco_total': '1 TB'
            },
            {
                'id': 4, 'ip': '192.168.1.13', 'nome': 'PC-GERENCIA', 'so': 'Windows 11', 
                'status': 'Offline', 'cpu': 0, 'ram': 0, 'disco': 65, 'ultimo_contato': '09:45:20',
                'processador': 'Intel Core i9', 'ram_total': '64 GB', 'disco_total': '2 TB'
            },
        ]
        
        self.cliente_selecionado = None
        self.botoes = []
        self.scroll_offset = 0
        self.filtro_status = "Todos"
        self.modo_escuro = True
        
        self.criar_botoes()
        self.painel_detalhes = PainelDetalhesCliente(15, 450, self.largura - 30, 420)
        
    def criar_botoes(self):
        """Cria os botões de controle"""
        self.botoes = [
            Botao(50, 70, 150, 45, "🔒 Bloquear", self.COR_ERRO, (255, 100, 100), "bloquear"),
            Botao(210, 70, 150, 45, "🔄 Reiniciar", self.COR_AVISO, (255, 200, 100), "reiniciar"),
            Botao(370, 70, 150, 45, "⏹ Desligar", (180, 0, 0), (220, 50, 50), "desligar"),
            Botao(530, 70, 150, 45, "📊 Monitorar", self.COR_DESTAQUE, (150, 180, 255), "monitorar"),
            Botao(690, 70, 150, 45, "🔍 Conectar", self.COR_SUCESSO, (100, 230, 150), "conectar"),
            Botao(850, 70, 120, 45, "🗑 Limpar", (100, 100, 100), (150, 150, 150), "limpar"),
            Botao(990, 70, 120, 45, "⚙ Config", self.COR_DESTAQUE, (150, 180, 255), "config"),
            Botao(1140, 70, 230, 45, "🔄 Atualizar Lista", self.COR_SUCESSO, (100, 230, 150), "atualizar"),
        ]
    
    def desenhar_cabecalho(self):
        """Desenha o cabeçalho da interface"""
        # Fundo do cabeçalho
        pygame.draw.rect(self.tela, self.COR_PAINEL, (0, 0, self.largura, 35))
        pygame.draw.line(self.tela, self.COR_DESTAQUE, (0, 35), (self.largura, 35), 3)
        
        # Título
        titulo = self.fonte_titulo.render("🖥️ Painel de Gerenciamento de Computadores em Rede", True, self.COR_DESTAQUE)
        self.tela.blit(titulo, (50, 5))
        
        # Status do servidor
        clientes_online = sum(1 for c in self.clientes if c['status'] == 'Online')
        status_texto = self.fonte_pequena.render(f"✓ Servidor Online | {clientes_online}/{len(self.clientes)} PCs", True, self.COR_SUCESSO)
        self.tela.blit(status_texto, (self.largura - 350, 10))
    
    def desenhar_botoes_controle(self):
        """Desenha os botões de controle"""
        # Título
        titulo = self.fonte_normal.render("Controles", True, self.COR_DESTAQUE)
        self.tela.blit(titulo, (50, 45))
        
        # Desenhar botões
        mouse_pos = pygame.mouse.get_pos()
        for botao in self.botoes:
            botao.atualizar_mouse(mouse_pos)
            botao.desenhar(self.tela, self.fonte_pequena)
    
    def desenhar_filtros(self):
        """Desenha os filtros de visualização"""
        y = 140
        titulo = self.fonte_normal.render("Filtros:", True, self.COR_DESTAQUE)
        self.tela.blit(titulo, (50, y))
        
        filtros = ["Todos", "Online", "Offline"]
        x = 150
        for filtro in filtros:
            cor = self.COR_SUCESSO if filtro == self.filtro_status else (100, 100, 100)
            texto = self.fonte_pequena.render(f"● {filtro}", True, cor)
            self.tela.blit(texto, (x, y + 3))
            x += 150
    
    def desenhar_tabela_clientes(self):
        """Desenha a tabela de clientes com estilo moderno"""
        titulo = self.fonte_normal.render("Clientes Conectados", True, self.COR_DESTAQUE)
        self.tela.blit(titulo, (50, 180))
        
        # Cabeçalho da tabela
        cabecalho_y = 210
        colunas = [
            ('ID', 40, 50),
            ('IP', 120, 100),
            ('Nome PC', 140, 230),
            ('Sistema', 130, 380),
            ('CPU', 60, 520),
            ('RAM', 60, 590),
            ('Status', 80, 660),
            ('Último Contato', 130, 750),
        ]
        
        # Desenhar cabeçalho
        pygame.draw.rect(self.tela, self.COR_DESTAQUE, (50, cabecalho_y, self.largura - 100, 30))
        
        for nome, largura, x in colunas:
            texto = self.fonte_pequena.render(nome, True, (255, 255, 255))
            self.tela.blit(texto, (x, cabecalho_y + 7))
        
        # Desenhar linhas de clientes
        linha_altura = 45
        max_linhas = 7
        y_inicio = cabecalho_y + 35
        
        for idx, cliente in enumerate(self.clientes):
            y = y_inicio + (idx * linha_altura)
            
            if y > self.altura - 50:
                break
            
            # Cor de fundo alternada
            cor_fundo = (40, 45, 60) if idx % 2 == 0 else (50, 55, 70)
            pygame.draw.rect(self.tela, cor_fundo, (50, y - 5, self.largura - 100, linha_altura))
            
            # Borda de seleção
            if self.cliente_selecionado == cliente['id']:
                pygame.draw.rect(self.tela, self.COR_SUCESSO, (50, y - 5, self.largura - 100, linha_altura), 3)
            else:
                pygame.draw.rect(self.tela, (80, 80, 100), (50, y - 5, self.largura - 100, linha_altura), 1)
            
            # Dados
            dados = [
                (str(cliente['id']), 50),
                (cliente['ip'], 100),
                (cliente['nome'], 230),
                (cliente['so'][:15], 380),
                (f"{cliente['cpu']}%", 520),
                (f"{cliente['ram']}%", 590),
                (cliente['status'], 660),
                (cliente['ultimo_contato'], 750),
            ]
            
            for texto_val, x_pos in dados:
                if "Online" in texto_val:
                    cor_texto = self.COR_SUCESSO
                elif "Offline" in texto_val:
                    cor_texto = self.COR_ERRO
                elif "%" in texto_val:
                    val = int(texto_val.replace("%", ""))
                    cor_texto = self.COR_SUCESSO if val < 70 else self.COR_AVISO if val < 85 else self.COR_ERRO
                else:
                    cor_texto = self.COR_TEXTO
                
                texto = self.fonte_pequena.render(texto_val, True, cor_texto)
                self.tela.blit(texto, (x_pos, y))
            
            # Armazenar rect para clique
            cliente['rect'] = pygame.Rect(50, y - 5, self.largura - 100, linha_altura)
        
        # Linha final
        pygame.draw.line(self.tela, (80, 80, 100), (50, y_inicio + (idx + 1) * linha_altura), 
                        (self.largura - 50, y_inicio + (idx + 1) * linha_altura), 1)
    
    def processar_eventos(self):
        """Processa eventos do pygame"""
        for evento in pygame.event.get():
            if evento.type == pygame.QUIT:
                self.rodando = False
            
            elif evento.type == pygame.MOUSEBUTTONDOWN:
                mouse_pos = evento.pos
                
                # Verificar clique nos botões
                for botao in self.botoes:
                    if botao.clicou(mouse_pos):
                        self.executar_comando(botao.texto)
                
                # Verificar clique na tabela
                for cliente in self.clientes:
                    if 'rect' in cliente and cliente['rect'].collidepoint(mouse_pos):
                        self.cliente_selecionado = cliente['id']
                        self.painel_detalhes.definir_cliente(cliente)
                        # Atualizar valores dos gráficos
                        self.painel_detalhes.graficos[0].atualizar(cliente['cpu'])
                        self.painel_detalhes.graficos[1].atualizar(cliente['ram'])
                        self.painel_detalhes.graficos[2].atualizar(cliente['disco'])
            
            elif evento.type == pygame.KEYDOWN:
                if evento.key == pygame.K_ESCAPE:
                    self.rodando = False
    
    def executar_comando(self, botao_texto):
        """Executa o comando do botão"""
        if not self.cliente_selecionado and "Atualizar" not in botao_texto:
            print("⚠️ [GUI] Selecione um cliente para executar comando!")
            return
        
        if "Bloquear" in botao_texto:
            print(f"✓ [GUI] Bloqueando PC {self.cliente_selecionado}...")
        elif "Reiniciar" in botao_texto:
            print(f"✓ [GUI] Reiniciando PC {self.cliente_selecionado}...")
        elif "Desligar" in botao_texto:
            print(f"✓ [GUI] Desligando PC {self.cliente_selecionado}...")
        elif "Monitorar" in botao_texto:
            print(f"📊 [GUI] Monitorando PC {self.cliente_selecionado}...")
        elif "Conectar" in botao_texto:
            print(f"🔌 [GUI] Conectando a PC {self.cliente_selecionado}...")
        elif "Atualizar" in botao_texto:
            print("🔄 [GUI] Atualizando lista de clientes...")
    
    def executar(self):
        """Loop principal da interface"""
        while self.rodando:
            self.tela.fill(self.COR_FUNDO)
            
            # Desenhar componentes
            self.desenhar_cabecalho()
            self.desenhar_botoes_controle()
            self.desenhar_filtros()
            self.desenhar_tabela_clientes()
            self.painel_detalhes.desenhar(self.tela, self.fonte_titulo, self.fonte_normal, self.fonte_pequena)
            
            # Processar eventos
            self.processar_eventos()
            
            # Atualizar tela
            pygame.display.flip()
            self.clock.tick(60)
        
        pygame.quit()


if __name__ == "__main__":
    interface = InterfaceGerenciamentoPygame()
    interface.executar()
