# Painel de Gerenciamento de Computadores em Rede

## Descrição

Sistema Python para controle e gerenciamento de múltiplos computadores conectados na mesma rede local. O projeto consiste em três componentes principais:

1. **Servidor** - Gerencia as conexões e coordena comandos
2. **Cliente** - Instalado em cada PC a ser controlado
3. **Interface Gráfica** - Painel para visualizar e controlar os PCs

## Arquitetura

```
┌─────────────────────────────────────────────────┐
│         Interface Gráfica (Tkinter)             │
│      (usuario controla os computadores)         │
└────────────────┬────────────────────────────────┘
                 │
        ┌────────▼────────┐
        │   Servidor      │
        │  (porta 5000)   │
        └────────┬────────┘
                 │
        ┌────────┴─────────┐
        │                  │
   ┌────▼────┐      ┌─────▼────┐
   │ Cliente  │      │ Cliente   │
   │   PC 1   │      │   PC 2    │
   └──────────┘      └───────────┘
```

## Componentes

### 1. Servidor (`servidor/server.py`)

- Aceita conexões de múltiplos clientes
- Monitora status dos PCs conectados
- Processa e envia comandos aos clientes
- Registra comunicações

**Funcionalidades:**
- Monitoramento em tempo real
- Gerenciamento de múltiplas conexões
- Processamento de comandos

### 2. Cliente (`cliente/client.py`)

- Conecta ao servidor automaticamente
- Envia informações do sistema periodicamente
- Recebe e executa comandos
- Reconecta automaticamente se desconectar

**Comandos suportados:**
- Desligar PC
- Reiniciar PC
- Bloquear tela

### 3. Interface Gráfica (`interface/gui.py`)

- Visualiza PCs conectados em tempo real
- Tabela com status de cada cliente
- Botões para enviar comandos
- Informações detalhadas do PC selecionado

## Instalação

### Pré-requisitos

- Python 3.7+
- Tkinter (geralmente incluído com Python)

### Passo a passo

1. **Clonar o repositório:**
```bash
git clone https://github.com/Plascoy01/Painel-Gerenciamento-Computadores.git
cd Painel-Gerenciamento-Computadores
```

2. **Instalar dependências:**
```bash
pip install -r requirements.txt
```

3. **Iniciar o servidor:**
```bash
python servidor/server.py
```
O servidor iniciará na porta 5000

4. **Instalar em cada PC cliente:**

   a. Editar `cliente/client.py` e alterar o IP do servidor:
   ```python
   servidor_ip = '192.168.1.X'  # Alterar para o IP da máquina servidor
   ```
   
   b. Executar o cliente:
   ```bash
   python cliente/client.py
   ```

5. **Iniciar a interface gráfica:**
```bash
python interface/gui.py
```

## Configuração

### Encontrar o IP do servidor

**Windows:**
```bash
ipconfig
```
Procure por "Endereço IPv4"

**Linux/Mac:**
```bash
ifconfig
# ou
ip addr
```
Procure pelo IP da rede local (geralmente 192.168.x.x ou 10.x.x.x)

### Configuração de firewall

Certifique-se de que a porta 5000 está aberta no firewall do servidor:

**Windows:**
```bash
netsh advfirewall firewall add rule name="PC Control Server" dir=in action=allow protocol=tcp localport=5000
```

**Linux:**
```bash
sudo ufw allow 5000/tcp
```

## Uso

1. **Iniciar o servidor** em uma máquina central
2. **Executar o cliente** em cada PC que deseja controlar
3. **Abrir a interface gráfica** para visualizar e gerenciar
4. **Selecionar um PC** na lista
5. **Clicar no botão** do comando desejado (Bloquear, Reiniciar ou Desligar)

## Protocolos de Comunicação

O sistema utiliza **sockets TCP** com mensagens em **JSON**:

### Formato de mensagem - Cliente para Servidor:
```json
{
  "tipo": "info",
  "dados": {
    "nome_pc": "PC-SALA-01",
    "sistema": "Windows",
    "versao": "10",
    "processador": "Intel Core i5",
    "timestamp": "2024-01-15T10:30:45"
  }
}
```

### Formato de mensagem - Servidor para Cliente:
```json
{
  "tipo": "comando",
  "comando": "desligar",
  "timestamp": "2024-01-15T10:30:45"
}
```

## Troubleshooting

### Clientes não conseguem conectar
- Verificar se o servidor está rodando
- Verificar o IP configurado no cliente
- Verificar firewall
- Testar ping para o servidor

### Interface não mostra clientes
- Aguardar 10-15 segundos (tempo de primeira sincronização)
- Clicar em "Atualizar"
- Verificar logs do servidor

### Comandos não executam
- Verificar se o cliente está Online
- Verificar conexão de rede
- Revisar logs do cliente

## Segurança

⚠️ **Importante:** Este é um projeto educacional. Para uso em produção:
- Implementar autenticação (usuário/senha ou certificados)
- Usar SSL/TLS para criptografar comunicações
- Implementar controle de acesso (permissões)
- Limitar comandos permitidos
- Validar todas as entradas
- Manter logs de auditoria

## Melhorias Futuras

- [ ] Autenticação de usuários
- [ ] Encriptação de comunicação (SSL/TLS)
- [ ] Suporte a múltiplos servidores
- [ ] Agendamento de comandos
- [ ] Histórico de comandos
- [ ] Monitoramento de recursos (CPU, RAM, Disco)
- [ ] Captura de tela remota
- [ ] Gerenciamento de processos
- [ ] Sincronização de arquivos
- [ ] Interface web

## Contribuindo

Contribuições são bem-vindas! Por favor:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Adiciona MinhaFeature'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

## Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

## Autor

Plascoy01

## Suporte

Para reportar bugs ou solicitar features, abra uma issue no repositório.
