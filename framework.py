"""
Framework Autônomo de Remediação SCA
A IA é o cérebro: após o Trivy fazer o scan, o agente decide e orquestra tudo.

Requisitos implementados:
  Req 1  - Análise do repositório
  Req 2  - Varredura inicial (Trivy)
  Req 3  - Análise orientada por IA + consulta OSV
  Req 4  - Aplicação automatizada de patches
  Req 5  - Validação pós-remediação
  Req 8  - Smoke test de estabilidade
  Req 10 - Tratamento de erros, logs detalhados, retry
  Req 11 - Configuração via variáveis de ambiente
  Req 12 - Histórico completo no Supabase

FLUXO:
  1. O GitHub Actions clona o repositório alvo em /tmp/target-repo
  2. O Trivy executa o scan sobre o repositório alvo
  3. O relatório é salvo em reports/report.json
  4. framework.py lê o relatório
  5. A IA analisa as vulnerabilidades
  6. As correções são aplicadas diretamente em /tmp/target-repo
  7. O smoke test valida as alterações
  8. O resultado é registrado no Supabase

OBSERVAÇÃO:
  O clone do repositório alvo é responsabilidade do workflow YAML.
  O framework.py NÃO clona novamente o repositório.
"""

import os
import sys
import json
import time
import subprocess
import shutil
from datetime import datetime

from dotenv import load_dotenv


# ============================================================
# CONFIGURAÇÃO INICIAL
# ============================================================

load_dotenv()

# Garante que scripts/ esteja no PYTHONPATH
SCRIPTS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "scripts"
)

sys.path.insert(0, SCRIPTS_PATH)


# ============================================================
# IMPORTS DOS MÓDULOS EXISTENTES
# ============================================================

from db import connect_db

from context_collector import (
    detect_ecosystem,
    detect_ecosystems,
    clone_target_repository,
    commit_and_push_patches,
)


# ============================================================
# CONFIGURAÇÕES VIA ENV
# ============================================================

MIN_SEVERITY = os.getenv(
    "MIN_SEVERITY",
    "HIGH"
)

TARGET_REPO_URL = os.getenv(
    "TARGET_REPO_URL",
    ""
)

TARGET_REPO_BRANCH = os.getenv(
    "TARGET_REPO_BRANCH",
    "main"
)

TARGET_BRANCH_FIX = os.getenv(
    "TARGET_BRANCH_FIX",
    "fix-remediation"
)

TARGET_PATH = os.getenv(
    "TARGET_PATH",
    "/tmp/target-repo"
)

PACKAGE_MANAGERS = {
    "PHP": "composer",
    "Node.js": "npm",
    "Python": "pip",
}


# ============================================================
# LOG
# ============================================================

def log(msg, level="INFO"):
    """
    Registra mensagens padronizadas no log.
    """

    ts = datetime.utcnow().strftime("%H:%M:%S")

    print(
        f"[{ts}] {level}: {msg}",
        flush=True
    )


# ============================================================
# AGENTE DE IA
# ============================================================

def get_ai_agent():
    """
    Carrega o agente de IA de forma lazy.

    Caso o agente não esteja disponível,
    o framework utiliza fallback baseado em severidade.
    """

    try:

        from ai_agent import analisar_lote

        log(
            "Agente de IA carregado (Google Gemini)"
        )

        return analisar_lote

    except Exception as e:

        log(
            f"Agente de IA não disponível: {e}. "
            f"Usando fallback por severidade.",
            "WARN"
        )

        return None


# ============================================================
# NOME DO REPOSITÓRIO
# ============================================================

def get_target_repo_name():
    """
    Extrai owner/repository da URL do repositório alvo.
    """

    if not TARGET_REPO_URL:

        return os.getenv(
            "GITHUB_REPOSITORY",
            "local"
        )

    url = TARGET_REPO_URL.rstrip("/")

    if url.endswith(".git"):

        url = url[:-4]

    if "github.com" in url:

        if "github.com/" in url:

            repo = url.split(
                "github.com/",
                1
            )[1]

        elif "github.com:" in url:

            repo = url.split(
                "github.com:",
                1
            )[1]

        else:

            repo = url

        return repo.rstrip("/")

    return url


# ============================================================
# BANCO DE DADOS — HELPERS
# ============================================================

def db_safe(
    fn,
    conn,
    *args,
    **kwargs
):
    """
    Executa operação no banco sem interromper
    o pipeline caso o banco apresente erro.
    """

    try:

        return fn(
            conn,
            *args,
            **kwargs
        )

    except Exception as e:

        log(
            f"DB error (non-fatal): {e}",
            "WARN"
        )

        try:

            conn.rollback()

        except Exception:

            pass

        return None


def db_create_execution(
    conn,
    repo,
    run_id
):
    """
    Cria registro da execução no Supabase.
    """

    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO pipeline_executions
            (
                repository_name,
                workflow_run_id,
                status,
                vulnerabilities_found,
                vulnerabilities_resolved,
                reduction_percentage
            )
        VALUES
            (
                %s,
                %s,
                'RUNNING',
                0,
                0,
                0
            )
        RETURNING id
        """,
        (
            repo,
            run_id
        )
    )

    execution_id = cur.fetchone()[0]

    conn.commit()

    cur.close()

    return execution_id


def db_finish_execution(
    conn,
    execution_id,
    status,
    found,
    resolved
):
    """
    Finaliza registro da execução.
    """

    percentage = (
        round(
            resolved / found * 100,
            2
        )
        if found > 0
        else 0
    )

    cur = conn.cursor()

    cur.execute(
        """
        UPDATE pipeline_executions
        SET
            status = %s,
            finished_at = NOW(),
            vulnerabilities_found = %s,
            vulnerabilities_resolved = %s,
            reduction_percentage = %s
        WHERE id = %s
        """,
        (
            status,
            found,
            resolved,
            percentage,
            execution_id
        )
    )

    conn.commit()

    cur.close()

    log(
        f"Execução finalizada: "
        f"{status} | "
        f"{resolved}/{found} "
        f"({percentage}%) resolvidas"
    )


# ============================================================
# STAGE 0 — VALIDAR REPOSITÓRIO ALVO
# ============================================================

def stage0_validate_target():
    """
    Valida e, quando necessário, clona o repositório alvo.

    Tabela de decisão (cinco ramificações):

      A — TARGET_PATH existe e contém .git/
          → reutiliza diretório existente.

      B — TARGET_PATH existe, sem .git/, TARGET_REPO_URL configurada
          → remove diretório inconsistente e clona novamente.

      C — TARGET_PATH existe, sem .git/, sem TARGET_REPO_URL
          → registra aviso e continua sem clonar (compatibilidade).

      D — TARGET_PATH não existe e TARGET_REPO_URL configurada
          → clona o repositório remoto.

      E — TARGET_PATH não existe e sem TARGET_REPO_URL
          → log de erro e sys.exit(1).
    """

    log("=" * 60)

    log(
        "STAGE 0 — Validação do Repositório Alvo"
    )

    log("=" * 60)

    log(
        f"📦 Repositório alvo: "
        f"{TARGET_REPO_URL or 'não informado'}"
    )

    log(
        f"🌿 Branch configurada: "
        f"{TARGET_REPO_BRANCH}"
    )

    log(
        f"📁 Diretório alvo: "
        f"{TARGET_PATH}"
    )

    git_dir = os.path.join(TARGET_PATH, ".git")

    path_exists = os.path.exists(TARGET_PATH)
    has_git = path_exists and os.path.exists(git_dir)

    if path_exists and has_git:

        # ── Branch A ─────────────────────────────────────────
        # Diretório existe e é um repositório Git válido.
        # Comportamento idêntico ao original.

        log(
            f"✅ repositório alvo detectado como existente: "
            f"{TARGET_PATH}"
        )

        return (
            TARGET_PATH,
            get_target_repo_name()
        )

    if path_exists and not has_git:

        if TARGET_REPO_URL:

            # ── Branch B ─────────────────────────────────────
            # Diretório existe mas não é um repositório Git,
            # e a URL remota está configurada.
            # Remove o diretório inconsistente e clona.

            log(
                f"⚠️ Diretório '{TARGET_PATH}' existe mas não é "
                "um repositório Git válido. "
                "TARGET_REPO_URL configurada — "
                "removendo diretório inconsistente e clonando.",
                "WARN"
            )

            shutil.rmtree(TARGET_PATH, ignore_errors=True)

            # fall through to clone logic below

        else:

            # ── Branch C ─────────────────────────────────────
            # Diretório existe mas não é um repositório Git,
            # e TARGET_REPO_URL não está configurada.
            # Registra aviso e continua sem clonar.

            log(
                f"⚠️ Diretório '{TARGET_PATH}' existe mas não é "
                "um repositório Git válido e "
                "TARGET_REPO_URL não está configurada. "
                "Continuando sem clonar.",
                "WARN"
            )

            return (
                TARGET_PATH,
                get_target_repo_name()
            )

    else:

        # path_exists is False
        if not TARGET_REPO_URL:

            # ── Branch E ─────────────────────────────────────
            # Diretório não existe e URL remota não configurada.

            log(
                f"❌ Diretório '{TARGET_PATH}' não existe e "
                "TARGET_REPO_URL não está configurada. "
                "Impossível prosseguir.",
                "ERROR"
            )

            sys.exit(1)

        # ── Branch D ─────────────────────────────────────────
        # Diretório não existe mas URL remota está configurada.
        # fall through to clone logic below

    # ── Clone (Branches B e D) ────────────────────────────────
    log(
        f"📥 Clonando repositório remoto: "
        f"{TARGET_REPO_URL}"
    )

    cloned_path = clone_target_repository(
        TARGET_REPO_URL,
        branch=TARGET_REPO_BRANCH,
        target_path=TARGET_PATH
    )

    if cloned_path is None:

        log(
            f"❌ Falha ao clonar o repositório "
            f"'{TARGET_REPO_URL}' em '{TARGET_PATH}'.",
            "ERROR"
        )

        sys.exit(1)

    log(
        f"✅ Repositório clonado com sucesso em: "
        f"{cloned_path}"
    )

    return (
        TARGET_PATH,
        get_target_repo_name()
    )


# ============================================================
# STAGE 1 — TRIVY + SUPABASE
# ============================================================

def stage1_load_and_persist(
    conn,
    target_path,
    report_path="reports/report.json"
):
    """
    Lê o relatório Trivy e persiste vulnerabilidades.
    """

    log("=" * 60)

    log(
        "STAGE 1 — Leitura do Trivy Report "
        "+ Persistência Supabase"
    )

    log(
        f"Alvo: {target_path}"
    )

    log("=" * 60)

    if not os.path.exists(report_path):

        log(
            f"Relatório não encontrado: "
            f"{report_path}",
            "ERROR"
        )

        sys.exit(1)

    run_id = os.getenv(
        "GITHUB_RUN_ID",
        f"local-{int(time.time())}"
    )

    repo = get_target_repo_name()

    execution_id = db_safe(
        db_create_execution,
        conn,
        repo,
        run_id
    )

    if execution_id:

        log(
            f"Execução criada no Supabase: "
            f"{execution_id} "
            f"(repositório: {repo})"
        )

    with open(
        report_path,
        encoding="utf-8"
    ) as f:

        report = json.load(f)

    all_results = report.get(
        "Results",
        []
    )

    total_vulns = sum(
        len(
            result.get(
                "Vulnerabilities"
            ) or []
        )
        for result in all_results
    )

    if total_vulns == 0:

        log(
            "✅ Nenhuma vulnerabilidade encontrada. "
            "Pipeline encerra com sucesso."
        )

        if execution_id:

            db_safe(
                db_finish_execution,
                conn,
                execution_id,
                "SUCCESS",
                0,
                0
            )

        sys.exit(0)

    log(
        f"Vulnerabilidades detectadas: "
        f"{total_vulns}"
    )

    try:

        from persist_history import (
            query_vulnerability_data
        )

        use_persist_history = True

    except ImportError:

        log(
            "persist_history.py não disponível, "
            "usando fallback.",
            "WARN"
        )

        use_persist_history = False

    cur = conn.cursor()

    count = 0

    for result in all_results:

        result_type = result.get(
            "Type",
            ""
        ).lower()

        target = result.get(
            "Target",
            ""
        ).lower()

        if (
            "composer" in result_type
            or "composer" in target
        ):

            ecosystem = "PHP"

        elif (
            "npm" in result_type
            or "package" in result_type
            or "package" in target
        ):

            ecosystem = "Node.js"

        elif (
            "pip" in result_type
            or "poetry" in result_type
            or "requirements" in target
        ):

            ecosystem = "Python"

        else:

            ecosystem = "UNKNOWN"

        log(
            f"\n🌍 Ecossistema: "
            f"{ecosystem} "
            f"(Type: {result.get('Type')})"
        )

        for vuln in (
            result.get(
                "Vulnerabilities"
            ) or []
        ):

            cve_id = vuln.get(
                "VulnerabilityID"
            )

            pkg = vuln.get(
                "PkgName"
            )

            version = vuln.get(
                "InstalledVersion"
            )

            severity = vuln.get(
                "Severity",
                "UNKNOWN"
            )

            fixed_ver = vuln.get(
                "FixedVersion"
            )

            cur.execute(
                """
                SELECT id
                FROM vulnerability_records
                WHERE execution_id = %s
                  AND cve_id = %s
                  AND package_name = %s
                  AND installed_version = %s
                  AND ecosystem = %s
                """,
                (
                    execution_id,
                    cve_id,
                    pkg,
                    version,
                    ecosystem
                )
            )

            if cur.fetchone():

                log(
                    f"[DUPLICADO] "
                    f"{cve_id} em "
                    f"{pkg}:{version} "
                    f"({ecosystem}) — ignorando"
                )

                continue

            count += 1

            vulnerability_data = None

            source = "NONE"

            osv_ref = None

            recommended_version = None

            if use_persist_history:

                vulnerability_data = (
                    query_vulnerability_data(
                        cur,
                        pkg,
                        version,
                        ecosystem
                    )
                )

                if vulnerability_data:

                    source = vulnerability_data.get(
                        "source",
                        "UNKNOWN"
                    )

                    osv_ref = vulnerability_data.get(
                        "osv_id"
                    )

                    recommended_version = (
                        vulnerability_data.get(
                            "recommended_version"
                        )
                    )

            log(
                f"  {pkg} "
                f"{version} "
                f"[{severity}] "
                f"→ "
                f"{recommended_version or 'N/A'} "
                f"({source})"
            )

            try:

                cur.execute(
                    """
                    INSERT INTO vulnerability_records
                        (
                            execution_id,
                            cve_id,
                            package_name,
                            severity,
                            installed_version,
                            fixed_version,
                            remediation_status,
                            osv_reference,
                            recommended_version,
                            source_db,
                            ecosystem
                        )
                    VALUES
                        (
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            'OPEN',
                            %s,
                            %s,
                            %s,
                            %s
                        )
                    """,
                    (
                        execution_id,
                        cve_id,
                        pkg,
                        severity,
                        version,
                        fixed_ver,
                        osv_ref,
                        recommended_version,
                        source,
                        ecosystem
                    )
                )

            except Exception as e:

                log(
                    f"DB insert error para "
                    f"{pkg}: {e}",
                    "WARN"
                )

                conn.rollback()

                continue

    if execution_id:

        try:

            cur.execute(
                """
                UPDATE pipeline_executions
                SET vulnerabilities_found = %s
                WHERE id = %s
                """,
                (
                    count,
                    execution_id
                )
            )

        except Exception:

            pass

    conn.commit()

    cur.close()

    log(
        f"✅ {count} vulnerabilidades "
        f"salvas no Supabase "
        f"(repositório: {repo})"
    )

    return (
        execution_id,
        count
    )


# ============================================================
# STAGE 2 — IA
# ============================================================

def stage2_ai_decide(conn):

    log("=" * 60)

    log(
        "STAGE 2 — Agente de IA: "
        "Análise e Decisão de Remediação"
    )

    log("=" * 60)

    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            id,
            package_name,
            severity,
            recommended_version,
            installed_version,
            cve_id,
            fixed_version,
            ecosystem
        FROM vulnerability_records
        WHERE remediation_status = 'OPEN'
          AND decision_status = 'PENDING'
        ORDER BY
            ecosystem,
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
        """
    )

    rows = cur.fetchall()

    cur.close()

    if not rows:

        log(
            "Nenhuma vulnerabilidade pendente."
        )

        return

    by_ecosystem = {}

    for row in rows:

        (
            vuln_id,
            pkg,
            severity,
            recommended_version,
            installed_version,
            cve,
            fixed,
            ecosystem
        ) = row

        by_ecosystem.setdefault(
            ecosystem,
            []
        ).append(
            {
                "id": vuln_id,
                "package_name": pkg,
                "severity": severity,
                "recommended_version": recommended_version,
                "installed_version": installed_version,
                "cve_id": cve,
                "fixed_version": fixed,
                "ecosystem": ecosystem,
            }
        )

    log(
        f"\n🌍 Ecossistemas com vulnerabilidades: "
        f"{', '.join(by_ecosystem.keys())}"
    )

    analisar_lote = get_ai_agent()

    approved = 0

    manual = 0

    ignored = 0

    cur = conn.cursor()

    for ecosystem, vulns in by_ecosystem.items():

        log(
            f"\n{ecosystem}:"
        )

        log(
            f"  📊 {len(vulns)} "
            f"vulnerabilidade(s)"
        )

        if analisar_lote:

            try:

                decisoes = analisar_lote(
                    vulns
                )

                for decision_data in decisoes:

                    pkg = decision_data[
                        "package_name"
                    ]

                    decision = decision_data[
                        "decision"
                    ]

                    recommended_version = (
                        decision_data.get(
                            "recommended_version"
                        )
                    )

                    justification = (
                        decision_data.get(
                            "justification",
                            ""
                        )
                    )

                    if decision == "APPROVED":

                        approved += 1

                    elif decision == "IGNORE":

                        ignored += 1

                    else:

                        manual += 1

                    cur.execute(
                        """
                        UPDATE vulnerability_records
                        SET
                            decision_status = %s,
                            ai_justification = %s,
                            recommended_version =
                                COALESCE(
                                    %s,
                                    recommended_version
                                ),
                            updated_at = NOW()
                        WHERE package_name = %s
                          AND ecosystem = %s
                          AND remediation_status = 'OPEN'
                          AND decision_status = 'PENDING'
                        """,
                        (
                            decision,
                            justification,
                            recommended_version,
                            pkg,
                            ecosystem
                        )
                    )

                conn.commit()

            except Exception as e:

                log(
                    f"Agente de IA falhou: "
                    f"{e}. "
                    f"Usando fallback.",
                    "WARN"
                )

                conn.rollback()

                analisar_lote = None

        if not analisar_lote:

            seen = set()

            for vuln in vulns:

                pkg = vuln[
                    "package_name"
                ]

                if pkg in seen:

                    continue

                seen.add(pkg)

                severity = vuln[
                    "severity"
                ]

                if severity in (
                    "CRITICAL",
                    "HIGH"
                ):

                    decision = "APPROVED"

                    approved += 1

                elif severity == "LOW":

                    decision = "IGNORE"

                    ignored += 1

                else:

                    decision = "MANUAL_REVIEW"

                    manual += 1

                cur.execute(
                    """
                    UPDATE vulnerability_records
                    SET
                        decision_status = %s,
                        ai_justification =
                            'Fallback: regra de severidade '
                            '(IA indisponível)',
                        updated_at = NOW()
                    WHERE package_name = %s
                      AND ecosystem = %s
                      AND remediation_status = 'OPEN'
                      AND decision_status = 'PENDING'
                    """,
                    (
                        decision,
                        pkg,
                        ecosystem
                    )
                )

            conn.commit()

    cur.close()

    log(
        f"\n✅ Decisões finais: "
        f"Approved={approved} | "
        f"Manual Review={manual} | "
        f"Ignored={ignored}"
    )


# ============================================================
# COMANDOS DE REMEDIAÇÃO
# ============================================================

COMMANDS = {

    "composer":
        lambda pkg, ver:
        [
            "composer",
            "require",
            f"{pkg}:{ver}",
            "--no-interaction"
        ],

    "npm":
        lambda pkg, ver:
        [
            "npm",
            "install",
            f"{pkg}@{ver}"
        ],

    "pip":
        lambda pkg, ver:
        [
            "pip",
            "install",
            f"{pkg}=={ver}"
        ],
}


# ============================================================
# SMOKE TEST
# ============================================================

def run_smoke_test(
    ecosystem,
    target_path
):

    if ecosystem == "PHP":

        php_files = []

        for root, dirs, files in os.walk(
            target_path
        ):

            dirs[:] = [
                d for d in dirs
                if d != "vendor"
            ]

            for filename in files:

                if filename.endswith(
                    ".php"
                ):

                    php_files.append(
                        os.path.join(
                            root,
                            filename
                        )
                    )

        for php_file in php_files:

            result = subprocess.run(
                [
                    "php",
                    "-l",
                    php_file
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:

                log(
                    f"❌ Smoke test PHP falhou: "
                    f"{result.stderr[:200]}",
                    "WARN"
                )

                return False

        if os.path.exists(
            os.path.join(
                target_path,
                "composer.json"
            )
        ):

            result = subprocess.run(
                [
                    "composer",
                    "install",
                    "--no-interaction",
                    "--no-progress",
                    "--prefer-dist"
                ],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:

                log(
                    f"❌ Smoke test Composer falhou: "
                    f"{result.stderr[:200]}",
                    "WARN"
                )

                return False

        return True

    elif ecosystem == "Node.js":

        for root, dirs, files in os.walk(
            target_path
        ):

            dirs[:] = [
                d for d in dirs
                if d != "node_modules"
            ]

            for filename in files:

                if filename.endswith(
                    ".js"
                ):

                    file_path = os.path.join(
                        root,
                        filename
                    )

                    result = subprocess.run(
                        [
                            "node",
                            "--check",
                            file_path
                        ],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    if result.returncode != 0:

                        return False

        return True

    elif ecosystem == "Python":

        for root, dirs, files in os.walk(
            target_path
        ):

            dirs[:] = [
                d for d in dirs
                if d not in (
                    "venv",
                    "env",
                    ".venv"
                )
            ]

            for filename in files:

                if filename.endswith(
                    ".py"
                ):

                    file_path = os.path.join(
                        root,
                        filename
                    )

                    result = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "py_compile",
                            file_path
                        ],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    if result.returncode != 0:

                        log(
                            f"❌ Smoke test Python "
                            f"falhou: {file_path}",
                            "WARN"
                        )

                        return False

        return True

    return True


# ============================================================
# VIRTUAL PATCH
# ============================================================

def validate_virtual_patch(
    patch_data: dict,
    ecosystem: str
) -> bool:
    """
    Validates a generated virtual patch before it is persisted.

    Performs three sequential checks:
      1. Existence  — the file reported in patch_data["file_path"] must exist.
      2. Size       — the file must be larger than 50 bytes.
      3. Syntax     — ecosystem-aware syntax check via subprocess:
                      Python  → py_compile
                      PHP     → php -l
                      Node.js → node --check
                      Others  → skipped (returns True immediately)

    Returns True only when all applicable checks pass.
    On any failure, logs a warning and returns False.
    On syntax failure, also attempts to remove the invalid file.

    Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7
    """

    # ── Step 1 — Existence check ─────────────────────────────
    file_path = patch_data["file_path"]

    if not os.path.isfile(file_path):

        log(
            f"⚠️ validate_virtual_patch: "
            f"arquivo não encontrado: {file_path}",
            "WARN"
        )

        return False

    # ── Step 2 — Size check ──────────────────────────────────
    if os.path.getsize(file_path) <= 50:

        log(
            f"⚠️ validate_virtual_patch: "
            f"arquivo muito pequeno (≤ 50 bytes): {file_path}",
            "WARN"
        )

        return False

    # ── Step 3 — Syntax check (ecosystem-dependent) ──────────
    if ecosystem == "Python":

        cmd = [sys.executable, "-m", "py_compile", file_path]

    elif ecosystem == "PHP":

        cmd = ["php", "-l", file_path]

    elif ecosystem == "Node.js":

        cmd = ["node", "--check", file_path]

    else:

        # Unknown / unsupported ecosystem — skip syntax check
        return True

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30
    )

    if result.returncode != 0:

        log(
            f"⚠️ validate_virtual_patch: "
            f"sintaxe inválida para {ecosystem} "
            f"(returncode={result.returncode}): "
            f"{result.stderr[:200]}",
            "WARN"
        )

        try:

            os.remove(file_path)

        except OSError:

            pass

        return False

    return True


def generate_virtual_patch(
    cur,
    pkg,
    ecosystem,
    old_ver,
    target_path
):

    try:

        from ai_agent import (
            gerar_virtual_patch
        )

        cur.execute(
            """
            SELECT cve_id
            FROM vulnerability_records
            WHERE package_name = %s
              AND ecosystem = %s
              AND decision_status = 'APPROVED'
              AND remediation_status = 'OPEN'
            """,
            (
                pkg,
                ecosystem
            )
        )

        cves = [
            row[0]
            for row in cur.fetchall()
        ]

        return gerar_virtual_patch(
            package_name=pkg,
            cves=cves,
            installed_version=old_ver,
            ecosystem=ecosystem,
            target_path=target_path
        )

    except Exception as e:

        log(
            f"Falha ao gerar Virtual Patch: "
            f"{e}",
            "WARN"
        )

        return None


# ============================================================
# STAGE 3 — APLICAÇÃO DOS PATCHES
# ============================================================

def stage3_apply_patches(
    conn,
    target_path
):

    log("=" * 60)

    log(
        "STAGE 3 — Aplicação de Patches"
    )

    log(
        f"Alvo: {target_path}"
    )

    log("=" * 60)

    cur = conn.cursor()

    cur.execute(
        """
        SELECT DISTINCT ecosystem
        FROM vulnerability_records
        WHERE decision_status = 'APPROVED'
          AND remediation_status = 'OPEN'
          AND ecosystem != 'UNKNOWN'
        ORDER BY ecosystem
        """
    )

    ecosystems = [
        row[0]
        for row in cur.fetchall()
    ]

    if not ecosystems:

        log(
            "Nenhuma vulnerabilidade aprovada "
            "para patch."
        )

        cur.close()

        return 0

    total_remediated = 0

    total_failed = 0

    total_virtual_patched = 0

    for ecosystem in ecosystems:

        package_manager = (
            PACKAGE_MANAGERS.get(
                ecosystem
            )
        )

        if not package_manager:

            continue

        if not shutil.which(
            package_manager
        ):

            log(
                f"{package_manager} "
                f"não encontrado no PATH.",
                "ERROR"
            )

            continue

        cur.execute(
            """
            SELECT DISTINCT ON (package_name)
                id,
                package_name,
                installed_version,
                recommended_version,
                ai_justification
            FROM vulnerability_records
            WHERE decision_status = 'APPROVED'
              AND remediation_status = 'OPEN'
              AND ecosystem = %s
            ORDER BY package_name
            """,
            (
                ecosystem,
            )
        )

        rows = cur.fetchall()

        for (
            _,
            pkg,
            old_ver,
            new_ver,
            justification
        ) in rows:

            if new_ver:

                cmd = COMMANDS[
                    package_manager
                ](
                    pkg,
                    new_ver
                )

            else:

                if package_manager == "composer":

                    cmd = [
                        "composer",
                        "update",
                        pkg,
                        "--no-interaction"
                    ]

                elif package_manager == "npm":

                    cmd = [
                        "npm",
                        "update",
                        pkg
                    ]

                else:

                    cmd = [
                        "pip",
                        "install",
                        "--upgrade",
                        pkg
                    ]

            log(
                f"🔧 {pkg}: "
                f"{old_ver} → "
                f"{new_ver or 'update genérico'}"
            )

            result = subprocess.run(
                cmd,
                cwd=target_path,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:

                log(
                    "✅ Update aplicado."
                )

                smoke_ok = run_smoke_test(
                    ecosystem,
                    target_path
                )

                if smoke_ok:

                    cur.execute(
                        """
                        UPDATE vulnerability_records
                        SET
                            remediation_status =
                                'REMEDIATED',
                            previous_version =
                                installed_version,
                            updated_at = NOW()
                        WHERE package_name = %s
                          AND ecosystem = %s
                          AND decision_status =
                                'APPROVED'
                          AND remediation_status =
                                'OPEN'
                        """,
                        (
                            pkg,
                            ecosystem
                        )
                    )

                    total_remediated += 1

                else:

                    log(
                        "⚠️ Smoke test falhou. "
                        "Tentando Virtual Patch.",
                        "WARN"
                    )

                    # ── Ecosystem-aware manifest list ─────────
                    if ecosystem == "PHP":
                        revert_files = [
                            "composer.json",
                            "composer.lock",
                        ]
                    elif ecosystem == "Node.js":
                        revert_files = [
                            "package.json",
                            "package-lock.json",
                        ]
                    else:
                        # Python
                        revert_files = [
                            "requirements.txt",
                        ]

                    revert_result = subprocess.run(
                        [
                            "git",
                            "checkout",
                            "--",
                        ] + revert_files,
                        cwd=target_path,
                        capture_output=True,
                        text=True
                    )

                    if revert_result.returncode != 0:

                        log(
                            f"❌ git checkout de reversão "
                            f"falhou (rc="
                            f"{revert_result.returncode}): "
                            f"{revert_result.stderr[:300]}",
                            "ERROR"
                        )

                        cur.execute(
                            """
                            UPDATE vulnerability_records
                            SET
                                remediation_status =
                                    'FAILED',
                                updated_at = NOW()
                            WHERE package_name = %s
                              AND ecosystem = %s
                              AND decision_status =
                                    'APPROVED'
                              AND remediation_status =
                                    'OPEN'
                            """,
                            (
                                pkg,
                                ecosystem
                            )
                        )

                        conn.commit()

                        total_failed += 1

                        continue

                    patch_data = (
                        generate_virtual_patch(
                            cur,
                            pkg,
                            ecosystem,
                            old_ver,
                            target_path
                        )
                    )

                    if patch_data:

                        if not validate_virtual_patch(
                            patch_data,
                            ecosystem
                        ):

                            try:
                                os.remove(
                                    patch_data["file_path"]
                                )
                            except OSError:
                                pass

                            cur.execute(
                                """
                                UPDATE vulnerability_records
                                SET
                                    remediation_status =
                                        'FAILED',
                                    updated_at = NOW()
                                WHERE package_name = %s
                                  AND ecosystem = %s
                                  AND decision_status =
                                        'APPROVED'
                                  AND remediation_status =
                                        'OPEN'
                                """,
                                (
                                    pkg,
                                    ecosystem
                                )
                            )

                            conn.commit()

                            total_failed += 1

                            continue

                        cur.execute(
                            """
                            UPDATE vulnerability_records
                            SET
                                remediation_status =
                                    'VIRTUAL_PATCH',
                                previous_version = %s,
                                virtual_patch_path =
                                    %s,
                                virtual_patch_data =
                                    %s,
                                updated_at = NOW()
                            WHERE package_name = %s
                              AND ecosystem = %s
                              AND decision_status =
                                    'APPROVED'
                              AND remediation_status =
                                    'OPEN'
                            """,
                            (
                                old_ver,
                                patch_data[
                                    "file_path"
                                ],
                                patch_data[
                                    "patch_code"
                                ],
                                pkg,
                                ecosystem
                            )
                        )

                        log(
                            f"📄 Virtual patch salvo: "
                            f"{patch_data['file_path']} "
                            f"({len(patch_data['patch_code'])} bytes)"
                        )

                        total_virtual_patched += 1

                    else:

                        total_failed += 1

            else:

                log(
                    f"❌ Falha no update: "
                    f"{result.stderr[:300]}",
                    "WARN"
                )

                patch_data = (
                    generate_virtual_patch(
                        cur,
                        pkg,
                        ecosystem,
                        old_ver,
                        target_path
                    )
                )

                if patch_data:

                    if not validate_virtual_patch(
                        patch_data,
                        ecosystem
                    ):

                        try:
                            os.remove(
                                patch_data["file_path"]
                            )
                        except OSError:
                            pass

                        cur.execute(
                            """
                            UPDATE vulnerability_records
                            SET
                                remediation_status =
                                    'FAILED',
                                updated_at = NOW()
                            WHERE package_name = %s
                              AND ecosystem = %s
                              AND decision_status =
                                    'APPROVED'
                              AND remediation_status =
                                    'OPEN'
                            """,
                            (
                                pkg,
                                ecosystem
                            )
                        )

                        total_failed += 1

                        continue

                    cur.execute(
                        """
                        UPDATE vulnerability_records
                        SET
                            remediation_status =
                                'VIRTUAL_PATCH',
                            previous_version = %s,
                            virtual_patch_path =
                                %s,
                            virtual_patch_data =
                                %s,
                            updated_at = NOW()
                        WHERE package_name = %s
                          AND ecosystem = %s
                          AND decision_status =
                                'APPROVED'
                          AND remediation_status =
                                'OPEN'
                        """,
                        (
                            old_ver,
                            patch_data[
                                "file_path"
                            ],
                            patch_data[
                                "patch_code"
                            ],
                            pkg,
                            ecosystem
                        )
                    )

                    log(
                        f"📄 Virtual patch salvo: "
                        f"{patch_data['file_path']} "
                        f"({len(patch_data['patch_code'])} bytes)"
                    )

                    total_virtual_patched += 1

                else:

                    cur.execute(
                        """
                        UPDATE vulnerability_records
                        SET
                            remediation_status =
                                'FAILED',
                            updated_at = NOW()
                        WHERE package_name = %s
                          AND ecosystem = %s
                          AND decision_status =
                                'APPROVED'
                          AND remediation_status =
                                'OPEN'
                        """,
                        (
                            pkg,
                            ecosystem
                        )
                    )

                    total_failed += 1

        conn.commit()

    cur.close()

    total = (
        total_remediated
        + total_virtual_patched
    )

    log(
        f"\n✅ TOTAL: "
        f"{total_remediated} patches | "
        f"{total_virtual_patched} virtual patches | "
        f"{total_failed} falhas"
    )

    return total


# ============================================================
# STAGE 4 — VALIDAÇÃO
# ============================================================

def stage4_validate(
    conn,
    execution_id,
    vulns_before
):

    log("=" * 60)

    log(
        "STAGE 4 — Validação"
    )

    log("=" * 60)

    post_report_path = (
        "reports/report_post_patch.json"
    )

    success = True

    if os.path.exists(
        post_report_path
    ):

        try:

            with open(
                post_report_path,
                encoding="utf-8"
            ) as f:

                post_report = json.load(
                    f
                )

            vulns_after = sum(
                len(
                    result.get(
                        "Vulnerabilities"
                    ) or []
                )
                for result in post_report.get(
                    "Results",
                    []
                )
            )

            reduction = (
                round(
                    (
                        vulns_before
                        - vulns_after
                    )
                    / vulns_before
                    * 100,
                    2
                )
                if vulns_before > 0
                else 0
            )

            log(
                f"Vulnerabilidades: "
                f"{vulns_before} → "
                f"{vulns_after} "
                f"(redução: {reduction}%)"
            )

            if execution_id:

                cur = conn.cursor()

                cur.execute(
                    """
                    UPDATE pipeline_executions
                    SET
                        vulnerabilities_resolved = %s,
                        reduction_percentage = %s
                    WHERE id = %s
                    """,
                    (
                        vulns_before
                        - vulns_after,
                        reduction,
                        execution_id
                    )
                )

                conn.commit()

                cur.close()

            if vulns_after > 0:

                success = False

        except Exception as e:

            log(
                f"Erro ao ler relatório pós-patch: "
                f"{e}",
                "WARN"
            )

    else:

        log(
            "Relatório pós-patch não encontrado. "
            "A validação será realizada pelo "
            "Security Gate.",
            "WARN"
        )

    return success


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n"
        + "=" * 60
    )

    print(
        "🔒 FRAMEWORK AUTÔNOMO "
        "DE REMEDIAÇÃO SCA"
    )

    print(
        "   IA como agente de segurança central"
    )

    print(
        "   PHP + Node.js + Python"
    )

    print(
        "=" * 60
    )

    if not os.path.exists(
        "reports/report.json"
    ):

        log(
            "reports/report.json "
            "não encontrado. "
            "Execute o Trivy primeiro.",
            "ERROR"
        )

        sys.exit(1)

    target_path = TARGET_PATH

    target_repo = get_target_repo_name()

    conn = connect_db()

    execution_id = None

    vulnerabilities_found = 0

    try:

        # ----------------------------------------------------
        # STAGE 0
        # ----------------------------------------------------

        target_path, target_repo = (
            stage0_validate_target()
        )

        # ----------------------------------------------------
        # STAGE 1
        # ----------------------------------------------------

        (
            execution_id,
            vulnerabilities_found
        ) = stage1_load_and_persist(
            conn,
            target_path
        )

        # ----------------------------------------------------
        # STAGE 2
        # ----------------------------------------------------

        stage2_ai_decide(
            conn
        )

        # ----------------------------------------------------
        # STAGE 3
        # ----------------------------------------------------

        remediated = (
            stage3_apply_patches(
                conn,
                target_path
            )
        )

        # ----------------------------------------------------
        # COMMIT + PUSH DA BRANCH DE REMEDIAÇÃO
        # ----------------------------------------------------

        if remediated > 0:

            run_id = os.getenv(
                "GITHUB_RUN_ID",
                f"local-{int(time.time())}"
            )

            log(
                "📤 Criando e enviando branch "
                f"'{TARGET_BRANCH_FIX}'..."
            )

            pushed_branch = commit_and_push_patches(
                target_path,
                run_id,
                target_branch=TARGET_BRANCH_FIX
            )

            if pushed_branch:

                log(
                    f"✅ Branch '{pushed_branch}' "
                    "publicada com sucesso."
                )

            else:

                log(
                    "❌ Falha ao publicar a branch "
                    f"'{TARGET_BRANCH_FIX}'. "
                    "O Security Gate não poderá "
                    "validar a remediação.",
                    "ERROR"
                )

        else:

            log(
                "ℹ️ Nenhuma remediação aplicada. "
                "Nenhuma branch será criada."
            )

        # ----------------------------------------------------
        # STAGE 4
        # ----------------------------------------------------

        success = stage4_validate(
            conn,
            execution_id,
            vulnerabilities_found
        )

        status = (
            "SUCCESS"
            if success
            else "PARTIAL"
        )

        if execution_id:

            db_safe(
                db_finish_execution,
                conn,
                execution_id,
                status,
                vulnerabilities_found,
                remediated
            )

        print(
            "\n"
            + "=" * 60
        )

        if success:

            print(
                "✅ PIPELINE CONCLUÍDO"
            )

        else:

            print(
                "⚠️ PIPELINE CONCLUÍDO — "
                "Revisão manual necessária"
            )

        print(
            f"   Repositório alvo: "
            f"{target_repo}"
        )

        print(
            f"   Diretório: "
            f"{target_path}"
        )

        print(
            "=" * 60
        )

    except Exception as e:

        log(
            f"Erro crítico no pipeline: "
            f"{e}",
            "ERROR"
        )

        if execution_id:

            db_safe(
                db_finish_execution,
                conn,
                execution_id,
                "FAILED",
                vulnerabilities_found,
                0
            )

        raise

    finally:

        conn.close()


# ============================================================
# EXECUÇÃO
# ============================================================

if __name__ == "__main__":

    main()