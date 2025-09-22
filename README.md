```markdown
# PC Optimizer Pro

Um otimizador e antivírus completo para Windows, construído com Python. Este script permite limpar o sistema, escanear ameaças, otimizar a performance e analisar a saúde geral do seu computador.

## ✨ Características

- **Interface amigável**: Menu interativo em português
- **Limpeza profunda do sistema**:
  - Arquivos temporários
  - Cache de navegadores
  - Arquivos de log
  - Lixeira
  - Arquivos duplicados
- **Antivírus integrado**:
  - Detecção por assinatura (hash e padrões)
  - Sistema de quarentena
  - Escaneamento rápido, completo e personalizado
- **Otimização de performance**:
  - Análise de programas de inicialização
  - Análise de serviços do sistema
  - Otimizações automáticas de registro
- **Análise completa do sistema**: Relatórios detalhados de estado e recomendações
- **Ferramentas avançadas**: Gerenciamento de quarentena, verificação de integridade, análise de disco
- **Auto-instalação**: Instala automaticamente as dependências necessárias
- **Funciona offline**: Não requer conexão com a internet para operações principais

## 🚀 Como usar

### Pré-requisitos

- **Windows 10/11**
- **Python 3.7+** instalado no sistema
  - Download: [python.org](https://python.org)
  - Ou instale pela Microsoft Store

### Instalação e Execução

1. **Baixe o script** `pc_optimizer_pro.py` e salve em uma pasta conhecida (ex: `C:\pc_optimizer`).

2. **Execute o script**:
   - **Recomendado**: Execute o Prompt de Comando ou PowerShell **como Administrador**.
   - Navegue até a pasta onde o script está:
     ```cmd
     cd "C:\caminho\para\a\pasta\do\script"
     ```
   - Execute o script:
     ```cmd
     python pc_optimizer_pro.py
     ```
     Ou, se `python` não funcionar:
     ```cmd
     py pc_optimizer_pro.py
     ```

3. **Siga as instruções na tela**:
   - Use o menu para selecionar a ação desejada
   - O script guiará você pelos processos

## 🧰 Menu Principal

```
📋 MENU PRINCIPAL:
1️⃣  🧹 Limpeza Completa do Sistema
2️⃣  🛡️  Escaneamento Antivírus
3️⃣  ⚡ Otimização de Performance
4️⃣  📊 Análise Completa do Sistema
5️⃣  🔧 Ferramentas Avançadas
6️⃣  ⚙️  Configurações
7️⃣  📈 Relatórios e Estatísticas
8️⃣  ❓ Ajuda e Sobre
0️⃣  🚪 Sair
```

## 🎯 Recursos Detalhados

### 1. Limpeza Completa do Sistema
- Remove arquivos temporários, cache, logs e itens da lixeira
- Identifica e remove arquivos duplicados
- Mostra espaço total a ser liberado antes da limpeza

### 2. Escaneamento Antivírus
- **Rápido**: Escaneia pastas críticas
- **Completo**: Escaneia todo o sistema (pode levar horas)
- **Personalizado**: Permite escolher pasta ou arquivo específico
- Detecta ameaças por hash, padrões e extensões suspeitas
- Coloca ameaças em quarentena ou remove permanentemente

### 3. Otimização de Performance
- Analisa programas que iniciam com o Windows
- Analisa serviços em execução
- Aplica otimizações automáticas no sistema e registro

### 4. Análise Completa do Sistema
- Combina limpeza, segurança e performance em um único relatório
- Fornece recomendações personalizadas

### 5. Ferramentas Avançadas
- Gerenciar arquivos em quarentena
- Visualizar logs de escaneamento
- Verificação de integridade de arquivos do sistema
- Análise de uso de disco

## 🛠️ Tecnologias Utilizadas

- **Python**: Linguagem principal
- **psutil**: Monitoramento de sistema e processos
- **winreg**: Manipulação do Registro do Windows
- **sqlite3**: Banco de dados interno para assinaturas e histórico
- **hashlib**: Verificação de integridade de arquivos
- **subprocess**: Execução de comandos do sistema

## 📝 Exemplo de Uso

```
=== PC OPTIMIZER PRO - SISTEMA COMPLETO DE OTIMIZAÇÃO E SEGURANÇA ===
   Limpeza Profunda | Antivírus Integrado | Otimização Avançada
   100% Gratuito | Offline | Proteção em Tempo Real
========================================================================
💻 Sistema: nt
👤 Usuário: SeuUsuario
🕒 Data/Hora: 01/01/2024 10:00:00
✅ Executando com privilégios de Administrador

📋 MENU PRINCIPAL:
1️⃣  🧹 Limpeza Completa do Sistema
2️⃣  🛡️  Escaneamento Antivírus
3️⃣  ⚡ Otimização de Performance
4️⃣  📊 Análise Completa do Sistema
5️⃣  🔧 Ferramentas Avançadas
6️⃣  ⚙️  Configurações
7️⃣  📈 Relatórios e Estatísticas
8️⃣  ❓ Ajuda e Sobre
0️⃣  🚪 Sair
--------------------------------------------------
Escolha uma opção: 1

🧹 LIMPEZA COMPLETA DO SISTEMA
==================================================
🔍 Escaneando arquivos temporários...
📂 Fase 1: Arquivos Temporários
   Encontrados: 150 arquivos (250.5 MB)
...
```

## ⚙️ Funcionalidades Técnicas

- **Verificação automática do Python e dependências**: Instala `psutil`, `winreg` e outras se necessário
- **Tratamento de erros**: Mensagens informativas para problemas comuns
- **Codificação UTF-8**: Suporte completo a caracteres especiais
- **Modo administrador**: Detecta e alerta sobre a necessidade de privilégios elevados

## 🐛 Solução de Problemas

### Python não encontrado
- Instale Python de [python.org](https://python.org)
- Ou use a Microsoft Store
- Certifique-se de marcar "Add to PATH" durante a instalação

### Erro ao instalar dependências
- Execute o script como Administrador
- Verifique sua conexão com a internet (para instalar pacotes)

### Erro de permissão durante a limpeza/escaneamento
- Execute como administrador se necessário
- Alguns arquivos do sistema podem exigir permissões especiais

### Script abre e fecha rapidamente
- Execute pelo Prompt de Comando para ver mensagens de erro
- Certifique-se de que todas as dependências foram instaladas corretamente

## 📜 Licença

Este projeto é fornecido apenas para fins educacionais e de uso pessoal. O uso deste software é de sua inteira responsabilidade.

## ⚠️ Aviso Legal

- Faça backup dos seus dados importantes antes de usar ferramentas de limpeza e otimização.
- A modificação de configurações do sistema e do registro pode afetar o funcionamento do seu computador.
- Use com responsabilidade.

## 📧 Suporte

Este é um projeto educacional. Para problemas, consulte as mensagens de erro no console.

---

**Desenvolvido com ❤️ para a comunidade**
```
