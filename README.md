# PC Optimizer Pro

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-green.svg)](https://windows.microsoft.com)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)](#licença)

Um otimizador e antivírus completo para Windows, construído com Python. Este script permite limpar o sistema, escanear ameaças, otimizar a performance e analisar a saúde geral do seu computador.

## 📋 Índice

- [Características](#-características)
- [Instalação](#-instalação)
- [Como Usar](#-como-usar)
- [Funcionalidades](#-funcionalidades)
- [Tecnologias](#-tecnologias)
- [Solução de Problemas](#-solução-de-problemas)
- [Licença](#-licença)

## ✨ Características

### 🖥️ Interface Amigável
- Menu interativo em português brasileiro
- Navegação intuitiva com emojis
- Feedback visual detalhado das operações

### 🧹 Limpeza Profunda do Sistema
- Arquivos temporários e cache
- Cache de navegadores web
- Arquivos de log do sistema
- Limpeza da lixeira
- Detecção e remoção de arquivos duplicados

### 🛡️ Antivírus Integrado
- **Detecção Avançada**: Hash e padrões de ameaças
- **Sistema de Quarentena**: Isolamento seguro de arquivos suspeitos
- **Tipos de Escaneamento**:
  - Rápido (pastas críticas)
  - Completo (todo o sistema)
  - Personalizado (pastas específicas)

### ⚡ Otimização de Performance
- Análise de programas de inicialização
- Gerenciamento de serviços do sistema
- Otimizações automáticas do registro
- Relatórios de performance detalhados

### 📊 Análise Completa
- Relatórios de estado do sistema
- Recomendações personalizadas
- Estatísticas de uso e performance
- Monitoramento de recursos

### 🔧 Ferramentas Avançadas
- Gerenciamento de quarentena
- Logs de escaneamento
- Verificação de integridade do sistema
- Análise detalhada de uso de disco

## 🚀 Instalação

### Pré-requisitos

- **Sistema Operacional**: Windows 10/11
- **Python**: Versão 3.7 ou superior
  - Download: [python.org](https://python.org)
  - Alternativa: Microsoft Store

### Passos de Instalação

1. **Baixar o Script**
   ```bash
   # Clone o repositório ou baixe o arquivo pc_optimizer_pro.py
   # Salve em uma pasta conhecida (ex: C:\pc_optimizer)
   ```

2. **Verificar Python**
   ```cmd
   python --version
   # ou
   py --version
   ```

3. **Executar como Administrador** (Recomendado)
   ```cmd
   # Abra CMD/PowerShell como Administrador
   cd "C:\caminho\para\a\pasta\do\script"
   python pc_optimizer_pro.py
   ```

## 💡 Como Usar

### Menu Principal

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

### Exemplo de Execução

```
=== PC OPTIMIZER PRO - SISTEMA COMPLETO DE OTIMIZAÇÃO E SEGURANÇA ===
   Limpeza Profunda | Antivírus Integrado | Otimização Avançada
   100% Gratuito | Offline | Proteção em Tempo Real
========================================================================
💻 Sistema: Windows 11
👤 Usuário: SeuUsuario
🕒 Data/Hora: 22/09/2025 14:30:00
✅ Executando com privilégios de Administrador

🧹 LIMPEZA COMPLETA DO SISTEMA
==================================================
🔍 Escaneando arquivos temporários...
📂 Fase 1: Arquivos Temporários
   ✅ Encontrados: 150 arquivos (250.5 MB)
📂 Fase 2: Cache de Navegadores
   ✅ Encontrados: 89 arquivos (128.3 MB)
...
```

## 🛠️ Funcionalidades

### 1. Limpeza Completa do Sistema
- **Arquivos Temporários**: Remove %TEMP%, Windows\Temp
- **Cache de Navegadores**: Chrome, Firefox, Edge
- **Logs do Sistema**: Windows, aplicações
- **Lixeira**: Esvaziamento seguro
- **Duplicados**: Algoritmo de detecção por hash

### 2. Escaneamento Antivírus
| Tipo | Descrição | Tempo Estimado |
|------|-----------|----------------|
| **Rápido** | Pastas críticas do sistema | 2-5 minutos |
| **Completo** | Todos os drives e partições | 30min - 2h |
| **Personalizado** | Pasta ou arquivo específico | Variável |

### 3. Otimização de Performance
- **Programas de Inicialização**: Análise e desabilitação seletiva
- **Serviços do Windows**: Otimização baseada em uso
- **Registro do Windows**: Limpeza e otimização segura
- **Memória RAM**: Liberação de processos desnecessários

### 4. Ferramentas Avançadas
- **Quarentena**: Visualizar, restaurar ou excluir permanentemente
- **Logs Detalhados**: Histórico completo de operações
- **Integridade do Sistema**: Verificação SFC e DISM
- **Análise de Disco**: Mapeamento visual do uso de espaço

## 🔧 Tecnologias

| Biblioteca | Função | Versão |
|------------|---------|--------|
| **psutil** | Monitoramento de sistema | Latest |
| **winreg** | Manipulação do registro | Built-in |
| **sqlite3** | Banco de dados interno | Built-in |
| **hashlib** | Verificação de integridade | Built-in |
| **subprocess** | Comandos do sistema | Built-in |
| **pathlib** | Manipulação de caminhos | Built-in |

## 🐛 Solução de Problemas

### ❌ Python não encontrado
```bash
# Soluções:
1. Instalar Python: https://python.org
2. Microsoft Store: "Python 3.x"
3. Verificar PATH nas variáveis de ambiente
```

### ❌ Erro de dependências
```bash
# Execute como Administrador:
pip install psutil
# ou
python -m pip install psutil --user
```

### ❌ Erro de permissão
```bash
# Soluções:
1. Executar CMD/PowerShell como Administrador
2. Verificar UAC (Controle de Conta de Usuário)
3. Temporariamente desabilitar antivírus
```

### ❌ Script fecha imediatamente
```bash
# Debug:
1. Executar via CMD para ver erros
2. Verificar codificação do arquivo (UTF-8)
3. Atualizar Python para versão mais recente
```

## 📊 Recursos do Sistema

### Requisitos Mínimos
- **RAM**: 2GB (4GB recomendado)
- **Espaço em Disco**: 100MB para logs e quarentena
- **Processador**: Qualquer processador moderno
- **Privilégios**: Administrador (recomendado)

### Compatibilidade
- ✅ Windows 10 (todas as versões)
- ✅ Windows 11 (todas as versões)  
- ✅ Windows Server 2016/2019/2022
- ❌ Windows 7/8 (não testado)

## 🔐 Segurança e Privacidade

### Características de Segurança
- **Offline**: Funciona sem internet após instalação
- **Código Aberto**: Transparência total
- **Sem Telemetria**: Nenhum dado enviado externamente
- **Quarentena Segura**: Isolamento de ameaças
- **Backup Automático**: Registro antes de modificações

### Dados Coletados
- **Nenhum**: O software não coleta nem transmite dados pessoais
- **Logs Locais**: Apenas armazenados no computador do usuário
- **Sem Analytics**: Nenhum rastreamento de uso

## 📈 Estatísticas de Performance

> **Resultados típicos** (sistema com 6 meses de uso):
> - 📁 **Arquivos Limpos**: 2,000 - 5,000 arquivos
> - 💾 **Espaço Liberado**: 500MB - 2GB
> - ⚡ **Melhoria na Inicialização**: 10-30%
> - 🔍 **Ameaças Detectadas**: 0-15 (adware/PUPs)

## 📜 Licença

Este projeto é fornecido **apenas para fins educacionais e de uso pessoal**. 

### Termos de Uso
- ✅ Uso pessoal e educacional
- ✅ Modificação para aprendizado
- ❌ Distribuição comercial
- ❌ Uso corporativo sem autorização

## ⚠️ Aviso Legal

### Importante
- 📋 **Backup**: Sempre faça backup antes de usar ferramentas de sistema
- 🔧 **Responsabilidade**: O uso é de sua inteira responsabilidade  
- ⚙️ **Modificações**: Alterações no registro podem afetar o sistema
- 🔒 **Segurança**: Execute apenas de fontes confiáveis

### Isenção de Responsabilidade
O desenvolvedor não se responsabiliza por danos ao sistema, perda de dados ou qualquer outro problema decorrente do uso deste software.

## 🤝 Contribuição

### Como Contribuir
1. 🍴 Fork o projeto
2. 🌟 Crie uma branch para sua feature
3. ✅ Teste suas modificações
4. 📝 Documente as mudanças
5. 🔄 Envie um Pull Request

### Diretrizes
- Mantenha o código limpo e documentado
- Teste em ambiente Windows
- Siga os padrões PEP 8 para Python
- Inclua exemplos de uso

## 📞 Suporte

### Canais de Suporte
- 📧 **Issues**: Use a seção Issues do GitHub
- 📖 **Documentação**: Consulte este README
- 🔍 **Debug**: Execute via CMD para ver logs detalhados

### FAQ
**P: O programa é seguro?**  
R: Sim, é código aberto e não envia dados externos.

**P: Funciona offline?**  
R: Sim, após instalar as dependências.

**P: Precisa ser Administrador?**  
R: Recomendado para acesso total ao sistema.

---

<div align="center">

**Desenvolvido com ❤️ para a comunidade brasileira**

[⬆️ Voltar ao topo](#pc-optimizer-pro)

</div>
