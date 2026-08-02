# 🔒 Framework Autônomo de Remediação de Vulnerabilidades em Projetos Legados

> Pipeline DevSecOps que detecta, decide e corrige vulnerabilidades SCA automaticamente, com auditoria persistente no Supabase, clonagem automática do repositório alvo e menor impacto em projetos legados.

[![Trivy](https://img.shields.io/badge/SCA-Trivy-blue)](https://trivy.dev)
[![OSV](https://img.shields.io/badge/Database-OSV%20API-red)](https://osv.dev)
[![Supabase](https://img.shields.io/badge/DB-Supabase%20PostgreSQL-3ECF8E?logo=supabase)](https://supabase.com)
[![AI](https://img.shields.io/badge/AI-Google%20Gemini-8E75B2?logo=google)](https://ai.google.dev)
[![Multi-Language](https://img.shields.io/badge/Support-PHP%20%7C%20Node%20%7C%20Python-green)]()

---

## Sobre o Projeto

Framework desenvolvido como **Trabalho de Conclusão de Curso (TCC)** em Segurança Cibernética. Implementa remediação autônoma de vulnerabilidades em projetos legados multi-linguagem, com foco em compatibilidade (estratégia same-major), virtual patching com validação formal e rastreabilidade completa.

### Problema

Projetos legados acumulam bibliotecas vulneráveis. Corrigir manualmente é lento, arriscado e difícil de auditar. Muitas vezes a correção de uma vulnerabilidade quebra a compatibilidade do sistema legado.

### Solução

O framework detecta, decide e corrige automaticamente — com **dois níveis de mitigação**:
1. **Patch direto**: atualiza a lib para versão segura (same-major)
2. **Virtual Patch aprimorado**: se o update quebrar compatibilidade, a IA gera código de mitigação validado (existência, tamanho e sintaxe) sem alterar a lib

---

## Como Escanear um Repositório Legado Vulnerável

O framework aceita **qualquer repositório GitHub** como alvo. Você aponta a URL e ele cuida do resto — clona, escaneia, remedia e registra.

### Opção 1 — GitHub Actions (recomendado)

Configure as variáveis no seu workflow YAML ou como secrets no repositório:

```yaml
env:
  TARGET_REPO_URL: https://github.com/org/repo-legado.git
  TARGET_REPO_BRANCH: main
  TARGET_PATH: /tmp/target-repo   # opcional, padrão já é /tmp/target-repo
  GH_TOKEN: ${{ secrets.GH_TOKEN }}
  DATABASE_URL: ${{ secrets.DATABASE_URL }}
  GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

O Stage 0 detecta automaticamente se o repo já foi clonado pelo Actions ou se precisa clonar — **zero configuração extra**.

### Opção 2 — Execução Local

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Configurar variáveis de ambiente
export TARGET_REPO_URL=https://github.com/org/repo-legado.git
export TARGET_REPO_BRANCH=main
export GH_TOKEN=ghp_seu_token_aqui
export DATABASE_URL=postgresql://...
export GEMINI_API_KEY=...

# 3. Gerar relatório Trivy sobre o repo alvo
#    (o framework clona em /tmp/target-repo automaticamente)
trivy fs /tmp/target-repo --format json --output reports/report.json

# 4. Executar o pipeline
python framework.py
```

> **Dica:** Se `TARGET_REPO_URL` estiver configurado e `/tmp/target-repo` não existir, o Stage 0 clona automaticamente antes de qualquer scan. Não é mais necessário clonar manualmente.

### Comportamento do Stage 0 (Detecção Automática)

| Situação | O que o framework faz |
|---|---|
| Diretório alvo existe com `.git/` | Reutiliza — comportamento idêntico ao anterior |
| Diretório alvo existe, sem `.git/`, com `TARGET_REPO_URL` | Remove inconsistência e re-clona |
| Diretório alvo existe, sem `.git/`, sem `TARGET_REPO_URL` | Registra aviso e continua |
| Diretório alvo **não existe**, com `TARGET_REPO_URL` | **Clona automaticamente** |
| Diretório alvo **não existe**, sem `TARGET_REPO_URL` | Erro + encerra com código 1 |

### Executar a Migration de Banco Antes do Primeiro Uso

Se o seu banco Supabase já existia antes desta versão, aplique a migration para adicionar as colunas de virtual patch:

```bash
psql $DATABASE_URL -f database/migrate_add_virtual_patch_columns.sql
```

---

## Fluxo Completo

```
Push em develop (ou execução manual)
      │
      ▼
┌─────────────────┐
│  PIPELINE 1     │
│  Security Scan  │
└──────┬──────────┘
       │
       ▼
┌──────────────────────────────────────────────────┐
│  framework.py (Orquestrador)                     │
│                                                  │
│  STAGE 0 · Validação / Clone do Repositório Alvo │
│    ├── Detecta se TARGET_PATH já existe          │
│    ├── Clona automaticamente se necessário       │
│    └── Compatível com GitHub Actions (sem clone) │
│                                                  │
│  STAGE 1 · persist_history.py                   │
│    ├── Consulta banco curado (Supabase)          │
│    ├── Enriquecimento com OSV API                │
│    └── Salva histórico no Supabase               │
│                                                  │
│  STAGE 2 · AI Agent (Google Gemini)             │
│    ├── Analisa CVEs e contexto                   │
│    ├── Decide APPROVED / MANUAL_REVIEW           │
│    └── Fallback por severidade se IA off         │
│                                                  │
│  STAGE 3 · Aplicação de Patches                 │
│    ├── composer / npm / pip                      │
│    ├── Smoke test pós-update                     │
│    ├── ✅ Passou → REMEDIATED                    │
│    └── ❌ Falhou → Virtual Patch aprimorado      │
│          ├── git checkout (manifesto correto)    │
│          ├── IA gera virtual patch               │
│          ├── Validação: existência + tamanho     │
│          │   + sintaxe (py_compile/php-l/node)   │
│          └── Registra no Supabase com path+code  │
└──────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────┐
│  fix/remediation    │  ← Branch com correções
│  (push automático)  │
└──────────┬──────────┘
           │
           ▼
┌──────────────────────────────────────────────────┐
│  PIPELINE 2 (disparada pela Pipeline 1)          │
│  Security Gate                                   │
│                                                  │
│  1. Re-scan Trivy (exit-code 1)                  │
│  2. Smoke test PHP                               │
│  3. Registro no Supabase                         │
│  4. ✅ Se passou: PR fix/remediation→homolog     │
│     ❌ Se falhou: homolog_status=REJECTED        │
└──────────────────────────────────────────────────┘
           │
           ▼
    Merge manual para homolog
           │
           ▼
    Código remediado em homolog
```

---

## Análise Comparativa com Soluções de Mercado

### Tabela Comparativa: Estado da Arte em SCA

| Ferramenta | Implantação | Licença | Fonte CVEs | Linguagens | Estratégia Versioning | Banco Homologado | Decisão Automática | Virtual Patching | Validação Pós-Fix | Rollback Registrado | Auditoria Persistente | Rastreabilidade | Re-scan Pós-Merge | PR Automático | Security Gate | Custo/ano |
|------------|-------------|---------|------------|------------|----------------------|------------------|--------------------|-----------------|-------------------|---------------------|-----------------------|-----------------|-------------------|---------------|---------------|-----------|
| **Este Framework** | Self-hosted (Actions) | MIT | Trivy + OSV API | PHP, Node, Python | **Same-major (legado)** | **Sim (Supabase curado)** | **IA + fallback** | **Sim (IA gera + validação)** | **Sim (re-scan Trivy)** | **Sim (previous_version)** | **Supabase (permanente)** | **Completa (por execução)** | **Sim** | Sim | Sim (exit-code 1) | **$0** |
| **Dependabot** | SaaS (GitHub) | Proprietário | GitHub Advisory | 20+ | Latest stable | Não | Não | Não | Não | Não | Não persistente | Limitada | Não | Sim | Não | $0 |
| **Snyk** | SaaS/On-prem | Freemium | Snyk Intel DB | 30+ | Latest stable | Não | Parcial | Não | Opcional | Não | SaaS (limitado) | Dashboard (pago) | Não | Sim | Configurável | ~$12.000 |
| **Renovate** | Self-hosted | AGPL | Múltiplas fontes | 40+ | Configurável | Não | Sim (regras) | Não | Não | Não | Logs em arquivo | Limitada | Não | Sim | Não | $0 |
| **OWASP DC** | Self-hosted | Apache 2.0 | NVD + NIST | 10+ | N/A | Não | Não | Não | N/A | N/A | Não | Não | Não | Não | Não | $0 |

> **Nota:** Dados baseados nas documentações oficiais e publicações acadêmicas sobre ferramentas SCA (Software Composition Analysis). Acesso em julho de 2026.

---

## Diferenciais da Solução

### 1. Clonagem Automática do Repositório Alvo (novo)

O framework agora é capaz de clonar qualquer repositório GitHub diretamente — basta configurar `TARGET_REPO_URL`. Não é necessário nenhuma etapa manual de clone antes de chamar `framework.py`. O Stage 0 detecta automaticamente se o repositório já existe localmente (cenário GitHub Actions) ou precisa ser clonado (execução local ou novo ambiente).

### 2. Decisão por IA com Fallback Inteligente

A IA (Google Gemini) analisa cada vulnerabilidade considerando:
- Versão instalada e versões disponíveis
- Banco de versões homologadas pela equipe
- Dados da OSV API
- Estratégia same-major para projetos legados

**Se a IA estiver indisponível**, o fallback por severidade assume automaticamente:
- CRITICAL/HIGH + versão segura → APPROVED
- MEDIUM → MANUAL_REVIEW
- LOW → IGNORE

### 3. Virtual Patching Aprimorado com Validação Formal (novo)

Quando o update da dependência quebra a compatibilidade (validado por smoke test), o framework executa o fluxo completo:

1. ❌ Smoke test falha após update
2. ↩️ `git checkout` reverte **apenas os manifestos do ecossistema** (não mais todos os 5 arquivos de uma vez)
3. ✅ Verifica o código de retorno do `git checkout` — se falhar, marca `FAILED` imediatamente sem tentar gerar o patch
4. 🧠 IA gera **Virtual Patch** — código de mitigação salvo em `virtual_patches/`
5. 🔍 **Validação do patch** antes de persistir:
   - Arquivo existe no caminho informado
   - Tamanho > 50 bytes
   - Sintaxe válida (`py_compile` para Python, `php -l` para PHP, `node --check` para Node.js)
6. 💾 Registra no Supabase com `virtual_patch_path`, `virtual_patch_data` e `previous_version`

```
Exemplo:
  Guzzle 6.3.0 → tentativa de update 6.5.8 → smoke test falha
    → git checkout composer.json composer.lock (só PHP)
    → IA gera virtual_patches/guzzlehttp_guzzle_virtual_patch.php
    → Validação: existe ✅ | > 50 bytes ✅ | php -l ✅
    → remediation_status = 'VIRTUAL_PATCH'
    → virtual_patch_path + virtual_patch_data persistidos no Supabase
```

### 4. Estratégia Same-Major para Projetos Legados

Diferente de Dependabot e Snyk que recomendam a versão mais recente disponível, este framework prioriza **a menor versão que corrige a vulnerabilidade dentro da mesma série major**. Isso reduz o risco de breaking changes em sistemas legados que não podem ser refatorados rapidamente.

```
Guzzle 6.3.0 (5 CVEs HIGH)
  Dependabot → 7.8.1  (breaking changes, requer PHP 7.2.5+)
  Este framework → 6.5.8  (mesma série, zero breaking changes)
```

### 5. Banco de Versões Homologadas (Curado pela Equipe)

Nenhuma das soluções de mercado permite que a equipe de segurança **pré-aprove versões específicas** com registro de quem aprovou, quando e por quê. Este framework implementa uma tabela `homologated_versions` consultada **antes** da OSV API, garantindo que apenas versões já testadas no ambiente da organização sejam aplicadas.

```
Fluxo de consulta:
1. Banco curado (Supabase) → versão aprovada pela equipe
2. OSV API (Google)        → fallback se não encontrado (enriquece com osv_id)
```

### 6. Auditoria Persistente com Histórico por Data

Enquanto Dependabot não persiste histórico e Renovate salva apenas logs em arquivo, este framework registra **cada execução no Supabase** com:
- Timestamp de detecção, decisão e remediação
- CVE → pacote → versão instalada → versão recomendada → status
- ID do workflow run para rastreabilidade até o GitHub Actions
- `source_db`: origem da recomendação (CURATED_DB / OSV_API)
- Status de homologação (PENDING / VALIDATED / REJECTED)
- Dados completos do Virtual Patch (caminho do arquivo e código)

O histórico **nunca é sobrescrito** — cada pipeline run insere novos registros, permitindo análise de evolução temporal da postura de segurança.

### 7. Ciclo de Validação Dupla com Duas Pipelines

```
Pipeline 1 (ai-agent-security-pipeline.yml):
  Trivy Scan → IA decide → Patches → fix/remediation
    ↓ (dispara Pipeline 2)

Pipeline 2 (homolog-security-gate.yml):
  Re-scan Trivy → Smoke test → Supabase → PR para homolog
```

Se o re-scan detectar que a vulnerabilidade persiste, o pipeline registra `homolog_status = 'REJECTED'` e **não cria o PR**. O merge para homolog permanece bloqueado.

### 8. Rollback Rastreável

Antes de aplicar qualquer correção, o script salva `previous_version` no banco. Em caso de falha no re-scan, é possível identificar exatamente qual versão estava instalada antes e reverter manualmente com rastreabilidade completa.

---

## Stack

- **Python 3.10+** — framework e scripts
- **Google Gemini API** — IA para decisão e geração de virtual patches
- **Supabase (PostgreSQL 16)** — auditoria persistente e banco curado
- **Trivy** — scanner SCA multi-linguagem
- **OSV API** (Google) — fonte de versões seguras
- **GitHub Actions** — pipeline CI/CD
- **PHP/Composer, Node.js/npm, Python/pip** — linguagens suportadas

---

## Estrutura

```
open_innovation_unifacens_2026_refatoracao/
│
├── framework.py                          # Orquestrador principal (Stage 0–4)
├── requirements.txt                      # Dependências Python
├── pytest.ini                            # Configuração pytest
├── .env                                  # Variáveis de ambiente (não versionado)
│
├── .github/workflows/
│   ├── ai-agent-security-pipeline.yml   # Pipeline 1: scan → remediate → fix/remediation
│   └── homolog-security-gate.yml        # Pipeline 2: re-scan → PR → homolog
│
├── database/
│   ├── schema.sql                        # Tabelas PostgreSQL (idempotente)
│   ├── migrate_add_previous_version.sql  # Migration: previous_version, source_db, ecosystem...
│   └── migrate_add_virtual_patch_columns.sql  # Migration: virtual_patch_path, virtual_patch_data
│   └── seed_homologated_versions.sql     # Versões curadas pela equipe
│
├── scripts/
│   ├── db.py                             # Conexão centralizada (Supabase)
│   ├── ai_agent.py                       # IA + Virtual Patching (Google Gemini)
│   ├── context_collector.py              # Detecção de ecossistema + clone_target_repository()
│   ├── persist_history.py                # Stage 1: persistência + enriquecimento OSV
│   ├── decision_engine.py                # (Legacy) Decisão por severidade
│   ├── remediate_2.py                    # (Legacy) Aplicação de patches
│   ├── ai_analyzer.py                    # (Legacy) Orquestrador alternativo
│   └── ai_remediation.py                 # (Legacy) Pipeline híbrida
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                       # Fixtures compartilhadas (mock_conn, tmp_patch_dir)
│   ├── test_stage0.py                    # 6 testes para Stage 0 (auto-clone)
│   └── test_stage3_virtual_patch.py      # 8 testes para Stage 3 (virtual patch + validação)
│
└── reports/
    └── report.json                       # Gerado pelo Trivy (não versionado)
```

---

## Banco de Dados (Supabase)

O Supabase mantém **histórico permanente** — cada execução do pipeline cria novos registros sem sobrescrever os anteriores.

### `pipeline_executions`
Registra cada run do GitHub Actions com status e métricas.

| Coluna | Descrição |
|--------|-----------|
| `id` | UUID único |
| `repository_name` | Repositório alvo |
| `workflow_run_id` | ID do GitHub Actions run |
| `started_at` | Início da execução |
| `finished_at` | Fim da execução |
| `status` | RUNNING / SUCCESS / FAILED / PARTIAL |
| `homolog_status` | PENDING / VALIDATED / REJECTED (definido pela Pipeline 2) |
| `vulnerabilities_found` | Total de vulnerabilidades detectadas |
| `vulnerabilities_resolved` | Total de vulnerabilidades corrigidas |
| `reduction_percentage` | Percentual de redução |

### `vulnerability_records`
Ciclo de vida completo de cada CVE:

| Coluna | Descrição |
|--------|-----------|
| `cve_id` | Identificador CVE |
| `package_name` | Pacote vulnerável |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `installed_version` | Versão atual |
| `previous_version` | Versão antes do revert (rastreabilidade de rollback) |
| `fixed_version` | Versão que corrige (do Trivy) |
| `recommended_version` | Versão recomendada (curado ou OSV) |
| `osv_reference` | ID da OSV (ex: GHSA-xxxx) |
| `source_db` | CURATED_DB / OSV_API / NONE |
| `decision_status` | PENDING → APPROVED / MANUAL_REVIEW / IGNORE |
| `remediation_status` | OPEN → REMEDIATED / FAILED / ROLLED_BACK / VIRTUAL_PATCH |
| `ecosystem` | PHP / Node.js / Python |
| `virtual_patch_path` | Caminho absoluto do arquivo de virtual patch gerado |
| `virtual_patch_data` | Código completo do virtual patch |
| `ai_justification` | Justificativa da IA |
| `created_at` / `updated_at` | Timestamps |

### `homologated_versions`
Banco curado pela equipe — consultado **antes** da OSV API. Garante que apenas versões testadas e aprovadas sejam aplicadas em projetos legados.

### Migration (novos campos)

Se o banco já existe de uma versão anterior, aplique:

```bash
psql $DATABASE_URL -f database/migrate_add_virtual_patch_columns.sql
```

Este script é **idempotente** — pode ser executado múltiplas vezes sem erro.

### Consultas de Auditoria

```sql
-- Histórico de todas as execuções
SELECT repository_name, started_at, status, homolog_status,
       vulnerabilities_found, vulnerabilities_resolved
FROM pipeline_executions
ORDER BY started_at DESC;

-- Vulnerabilidades por execução com decisão
SELECT cve_id, package_name, severity, installed_version,
       recommended_version, decision_status, remediation_status,
       source_db, osv_reference, ecosystem
FROM vulnerability_records
WHERE execution_id = '<uuid>';

-- Virtual patches gerados (com código e caminho)
SELECT package_name, installed_version, previous_version,
       virtual_patch_path, remediation_status, ai_justification
FROM vulnerability_records
WHERE remediation_status = 'VIRTUAL_PATCH';

-- Taxa de sucesso de remediações
SELECT
    COUNT(*) FILTER (WHERE remediation_status = 'REMEDIATED')     AS corrigidas,
    COUNT(*) FILTER (WHERE remediation_status = 'VIRTUAL_PATCH')  AS virtual_patches,
    COUNT(*) FILTER (WHERE remediation_status = 'FAILED')         AS falhas,
    COUNT(*) FILTER (WHERE remediation_status = 'ROLLED_BACK')    AS rollbacks
FROM vulnerability_records
WHERE decision_status = 'APPROVED';
```

---

## Configuração

### 1. Variáveis de ambiente locais (`.env`)

```env
DATABASE_URL=postgresql://<usuario>:<senha>@<host>:<porta>/postgres
DB_SSLMODE=require
GEMINI_API_KEY=<sua_chave_google_gemini>

# Repositório alvo (obrigatório se o repo não estiver pré-clonado)
TARGET_REPO_URL=https://github.com/org/repo-legado.git
TARGET_REPO_BRANCH=main
TARGET_PATH=/tmp/target-repo

# Token GitHub (necessário para clonar repos privados)
GH_TOKEN=ghp_...
```

A chave Gemini é obtida gratuitamente em: https://aistudio.google.com/apikey

### 2. Secrets no GitHub Actions

No repositório: **Settings → Secrets and variables → Actions → New repository secret**

| Nome | Valor |
|------|-------|
| `DATABASE_URL` | Connection string do seu banco Supabase |
| `GEMINI_API_KEY` | Chave da API Google Gemini |
| `GH_TOKEN` | Personal Access Token com acesso ao repo alvo |

A connection string do Supabase está disponível em:
**Supabase Dashboard → Project → Settings → Database → Connection string → URI**

### 3. Branches necessárias

```bash
git checkout -b homolog
git push origin homolog
git checkout develop
```

### 4. Aplicar schema e migrations no Supabase

```bash
pip install -r requirements.txt

# Schema completo (primeira vez)
python - <<EOF
import sys; sys.path.insert(0, "scripts")
from db import connect_db
conn = connect_db()
conn.cursor().execute(open("database/schema.sql").read())
conn.commit()
EOF

# Migration de virtual patch (se o banco já existia)
psql $DATABASE_URL -f database/migrate_add_virtual_patch_columns.sql
```

---

## Testes

```bash
# Instalar dependências de teste
pip install pytest hypothesis

# Rodar todos os testes
python -m pytest tests/ -v
```

Saída esperada: **14 testes passando** (6 Stage 0 + 8 Stage 3).

```
tests/test_stage0.py::test_stage0_git_dir_exists_returns_path_without_clone  PASSED
tests/test_stage0.py::test_stage0_no_git_no_url_returns_path_with_warning    PASSED
tests/test_stage0.py::test_stage0_no_git_with_url_removes_dir_and_clones     PASSED
tests/test_stage0.py::test_stage0_absent_path_with_url_clone_succeeds         PASSED
tests/test_stage0.py::test_stage0_absent_path_clone_fails_exits               PASSED
tests/test_stage0.py::test_stage0_absent_path_no_url_exits                    PASSED
tests/test_stage3_virtual_patch.py::...  (8 testes)                           PASSED
```

---

## Pipeline GitHub Actions

### Pipeline 1: `ai-agent-security-pipeline.yml`

**Trigger:** Push em `develop` ou execução manual (`workflow_dispatch`).

**Jobs:**

**1. `security-scan`**
- Instala Trivy
- Executa scan SCA em formato JSON e tabela
- Faz upload do `report.json` como artifact

**2. `remediation`**
- Detecta ecossistemas no relatório Trivy e instala apenas os gerenciadores necessários
- Aplica schema e migrations no Supabase (incluindo `migrate_add_virtual_patch_columns.sql`)
- Executa `framework.py` (Stages 0–3)
- Cria/atualiza branch `fix/remediation` com as correções e virtual patches gerados
- Dispara a Pipeline 2 via `workflow_dispatch`

### Pipeline 2: `homolog-security-gate.yml`

**Trigger:** Disparada pela Pipeline 1 via `workflow_dispatch`.

**Steps:**
1. **Re-scan Trivy** (exit-code 1 — bloqueia se vulnerável)
2. **Smoke test PHP** (sintaxe + composer install)
3. **Registro no Supabase** (homolog_status = VALIDATED / REJECTED)
4. **Se aprovado**: cria PR `fix/remediation → homolog`

---

## Ambiente de Teste PHP

O `composer.json` usa **Guzzle 6.3.0 propositalmente** — ambiente vulnerável para demonstração do TCC.

| CVE | Severidade | Corrigida em |
|-----|------------|--------------|
| CVE-2022-29248 | HIGH | 6.5.6+ |
| CVE-2022-31042 | HIGH | 6.5.7+ |
| CVE-2022-31043 | HIGH | 6.5.7+ |
| CVE-2022-31090 | HIGH | 6.5.8+ |
| CVE-2022-31091 | HIGH | 6.5.8+ |

Remediação esperada: `6.3.0 → 6.5.8` (banco curado) ou OSV API como fallback.

⚠️ Ambiente apenas para pesquisa acadêmica.

---

## Licença

[MIT](LICENSE)

---

TCC em Segurança Cibernética — Unifacens 2026
