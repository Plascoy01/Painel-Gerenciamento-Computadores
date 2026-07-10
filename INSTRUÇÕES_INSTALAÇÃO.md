# Instruções de Instalação - Painel de Gerenciamento de Computadores

## 🚀 Guia Rápido

### Opção 1: Instalação Simples (Sem Criptografia)

#### Máquina Servidor

1. **Abrir terminal/prompt de comando**

2. **Navegar até a pasta do projeto:**
   ```bash
   cd Painel-Gerenciamento-Computadores
   ```

3. **Instalar dependências:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Encontrar seu IP local:**
   
   **Windows:**
   ```bash
   ipconfig
   ```
   Procure por: `Endereço IPv4: 192.168.x.x`
   
   **Linux/Mac:**
   ```bash
   ifconfig
   ```
   Procure por: `inet 192.168.x.x`

5. **Iniciar o servidor:**
   ```bash
   python servidor/server.py
   ```
   
   Você verá:
   ```
   [SERVIDOR] Iniciado em 0.0.0.0:5000
   [SERVIDOR] Aguardando conexões de clientes...
   ```

#### Máquina Cliente

1. **Copiar o arquivo `cliente/client.py` para o PC**

2. **Editar o arquivo e alterar o IP do servidor:**
   
   Abrir `client.py` e localizar:
   ```python
   servidor_ip = 'localhost'  # ← Alterar aqui!
   ```
   
   Trocar para:
   ```python
   servidor_ip = '192.168.1.X'  # Use o IP encontrado no passo 4 do servidor
   ```

3. **Instalar dependências:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Executar o cliente:**
   ```bash
   python client.py
   ```
   
   Você verá:
   ```
   [CLIENTE] Conectado ao servidor 192.168.1.X:5000
   ```

#### Interface Gráfica (GUI)

1. **Abrir outro terminal na pasta do projeto**

2. **Executar:**
   ```bash
   python interface/gui.py
   ```

3. **Uma janela gráfica abrirá mostrando os PCs conectados**

---

## 🔧 Configuração Avançada

### Usando arquivo de configuração

Editar `config.json` para customizar:

```json
{
  "servidor": {
    "host": "0.0.0.0",
    "porta": 5000
  },
  "cliente": {
    "servidor_host": "SEU_IP_AQUI",
    "servidor_porta": 5000
  }
}
```

### Configurar para iniciar automaticamente (Windows)

1. **Criar arquivo `.bat`:**
   
   Criar arquivo `iniciar_cliente.bat`:
   ```batch
   @echo off
   cd C:\caminho\para\Painel-Gerenciamento-Computadores
   python cliente/client.py
   pause
   ```

2. **Adicionar ao inicialização do Windows:**
   - Pressionar `Win + R`
   - Digitar `shell:startup`
   - Copiar o arquivo `.bat` para a pasta

### Configurar para iniciar automaticamente (Linux)

1. **Criar arquivo de serviço:**
   ```bash
   sudo nano /etc/systemd/system/pc-client.service
   ```

2. **Adicionar conteúdo:**
   ```ini
   [Unit]
   Description=PC Client Control
   After=network.target

   [Service]
   Type=simple
   User=seu_usuario
   WorkingDirectory=/caminho/para/projeto
   ExecStart=/usr/bin/python3 /caminho/para/projeto/cliente/client.py
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

3. **Habilitar e iniciar:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable pc-client
   sudo systemctl start pc-client
   ```

---

## 🔐 Permitir Firewall

### Windows

```bash
netsh advfirewall firewall add rule name="PC Control" dir=in action=allow protocol=tcp localport=5000
```

### Linux (UFW)

```bash
sudo ufw allow 5000/tcp
```

### Linux (FirewallD)

```bash
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

---

## 📋 Checklist de Instalação

- [ ] Python 3.7+ instalado
- [ ] Dependências instaladas (`pip install -r requirements.txt`)
- [ ] IP do servidor identificado
- [ ] Servidor iniciado e aguardando conexões
- [ ] Cliente configurado com o IP correto do servidor
- [ ] Cliente iniciado e conectado
- [ ] Interface gráfica aberta e mostrando clientes
- [ ] Firewall configurado para porta 5000
- [ ] Testou enviar um comando (bloquear, reiniciar, desligar)

---

## 🆘 Resolução de Problemas

### "Conexão recusada"

**Solução:**
- Verificar se servidor está rodando
- Verificar se IP está correto
- Verificar firewall
- Testar: `ping 192.168.1.X`

### "Módulo não encontrado"

**Solução:**
```bash
pip install -r requirements.txt
```

### "Permissão negada" (Linux)

**Solução:**
```bash
chmod +x servidor/server.py
chmod +x cliente/client.py
```

### Cliente não aparece na interface

**Solução:**
- Aguardar 15 segundos
- Clicar em "Atualizar"
- Verificar logs do servidor

---

## 📞 Suporte

Se tiver dúvidas:

1. Verificar os logs na tela
2. Ler a seção de Troubleshooting no README.md
3. Abrir uma issue no repositório
