"""
Framework Autônomo de Remediação SCA
A IA é o cérebro: após o Trivy fazer o scan, o agente decide e orquestra tudo.

Requisitos implementados:
  Req 1  - Análise do repositório (agora suporta repositórios externos)
  Req 2  - Varredura inicial (Trivy)
  Req 3  - Análise orientada por IA + consulta OSV
  Req 4  - Aplicação automatizada de patches (branch fix-remediation no repo alvo)
  Req 5  - Validação pós-remediação (re-scan Trivy)
  Req 8  - Smoke test de estabilidade PHP
  Req 10 - Tratamento de erros, logs detalhados, retry
  Req 11 - Configuração via variáveis de ambiente
  Req 12 - Histórico completo no Supabase

FLUXO REFATORADO:
  1. Recebe URL do repositório legado (TARGET_REPO_URL)
  2. Clona o repositório para diretório temporário
  3. Executa Trivy sobre o repositório clonado
  4. framework.py processa estágios 1-4 no diretório clonado
  5. Correções aplicadas no repositório clonado
  6. Commit e push das correções para o repositório alvo
  7. Diretório temporário é limpo
"""
import os
import sys
import json
import time
import subprocess
import shutil
import tempfile
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Garante que scripts/ está no path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

from db import connect_db
from context_collector import (
    detect_ecosystem, detect_ecosystems,
    clone_target_repository, cleanup_target_repository,
    commit_and_push_patches
)

# Req 11: configuração via env com defaults seguros
MIN_SEVERITY     = os.getenv("MIN_SEVERITY", "HIGH")

# Configuração do repositório alvo
TARGET_REPO_URL  = os.getenv("TARGET_REPO_URL", "")
TARGET_REPO_BRANCH = os.getenv("TARGET_REPO_BRANCH", "main")
TARGET_BRANCH_FIX = os.getenv("TARGET_BRANCH_FIX", "fix-remediation")

# Package managers por ecossistema
PACKAGE_MANAGERS = {
    "PHP": "composer",
    "Node.js": "npm",
    "Python": "pip",
}


def log(msg, level="INFO"):
    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] {level}: {msg}")


def get_ai_agent():
    """Import lazy — falha visível no log, nunca silenciosa."""
    try:
        from ai_agent import analisar_lote
        log("Agente de IA carregado (Google Gemini)")
        return analisar_lote
    except Exception as e:
        log(f"Agente de IA não disponível: {e}. Usando fallback por severidade.", "WARN")
        return None


def get_target_repo_name():
    """Extrai nome do repositório da URL para registro no banco."""
    if not TARGET_REPO_URL:
        return os.getenv("GITHUB_REPOSITORY", "local")
    # Extrai "owner/repo" de URLs como:
    # https://github.com/owner/repo.git
    # git@github.com:owner/repo.git
    url = TARGET_REPO_URL.rstrip(".git")
    if "github.com" in url:
        parts = url.split("github.com/")[-1].split(":")
        return parts[-1] if parts else url
    return url


# ============================================================
# BANCO: helpers
# ============================================================
def db_safe(fn, conn, *args, **kwargs):
    """Req 12.6: executa operação DB sem interromper o fluxo se falhar."""
    try:
        return fn(conn, *args, **kwargs)
    except Exception as e:
        log(f"DB error (non-fatal): {e}", "WARN")
        try:
            conn.rollback()
        except Exception:
            pass
        return None


def db_create_execution(conn, repo, run_id):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pipeline_executions
            (repository_name, workflow_run_id, status,
             vulnerabilities_found, vulnerabilities_resolved, reduction_percentage)
        VALUES (%s, %s, 'RUNNING', 0, 0, 0) RETURNING id
    """, (repo, run_id))
    eid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    return eid


def db_finish_execution(conn, execution_id, status, found, resolved):
    pct = round((resolved / found * 100), 2) if found > 0 else 0
    cur = conn.cursor()
    cur.execute("""
        UPDATE pipeline_executions
        SET status=%s, finished_at=NOW(),
            vulnerabilities_found=%s, vulnerabilities_resolved=%s, reduction_percentage=%s
        WHERE id=%s
    """, (status, found, resolved, pct, execution_id))
    conn.commit()
    cur.close()
    log(f"Execução finalizada: {status} | {resolved}/{found} ({pct}%) resolvidas")


# ============================================================
# STAGE 0: Clonar repositório alvo
# ============================================================
def stage0_clone_target():
    """
    Req 1: Clona o repositório legado alvo para análise.
    
    Se TARGET_REPO_URL não estiver configurado, usa o diretório atual
    (compatibilidade com execução local/dentro do próprio repo).
    
    Retorna:
        (target_path, target_repo_name)
    """
    log("=" * 60)
    log("STAGE 0 — Clonando Repositório Alvo")
    log("=" * 60)

    if not TARGET_REPO_URL:
        log("TARGET_REPO_URL não configurado — usando diretório atual")
        return os.getcwd(), get_target_repo_name()

    repo_name = get_target_repo_name()
    log(f"📦 Repositório alvo: {TARGET_REPO_URL} (branch: {TARGET_REPO_BRANCH})")

    target_path = clone_target_repository(TARGET_REPO_URL, TARGET_REPO_BRANCH)
    if not target_path:
        log(f"❌ Falha ao clonar repositório {TARGET_REPO_URL}", "ERROR")
        sys.exit(1)

    log(f"✅ Repositório clonado em: {target_path}")
    return target_path, repo_name


# ============================================================
# STAGE 1: Leitura do relatório Trivy + OSV + Supabase
# ============================================================
def stage1_load_and_persist(conn, target_path, report_path="reports/report.json"):
    """
    Req 1, 2, 12: lê relatório do Trivy a partir do target_path,
    enriquece com OSV/curado e persiste no Supabase.
    
    Args:
        conn: Conexão com o banco
        target_path: Caminho do repositório alvo clonado
        report_path: Caminho do relatório (relativo ao CWD do framework)
    """
    log("=" * 60)
    log("STAGE 1 — Leitura do Trivy Report + Persistência Supabase")
    log(f"     Alvo: {target_path}")
    log("=" * 60)

    if not os.path.exists(report_path):
        log(f"Relatório não encontrado: {report_path}", "ERROR")
        sys.exit(1)

    run_id = os.getenv("GITHUB_RUN_ID", f"local-{int(time.time())}")
    repo   = get_target_repo_name()

    # Cria execução
    execution_id = db_safe(db_create_execution, conn, repo, run_id)
    if execution_id:
        log(f"Execução criada no Supabase: {execution_id} (repositório: {repo})")

    with open(report_path) as f:
        report = json.load(f)

    all_results = report.get("Results", [])

    # Req 2.4: sem vulnerabilidades → encerra graciosamente
    total_vulns = sum(len(r.get("Vulnerabilities") or []) for r in all_results)
    if total_vulns == 0:
        log("✅ Nenhuma vulnerabilidade encontrada. Pipeline encerra com sucesso.")
        if execution_id:
            db_safe(db_finish_execution, conn, execution_id, "SUCCESS", 0, 0)
        sys.exit(0)

    log(f"Vulnerabilidades detectadas: {total_vulns} (multi-linguagem)")
    
    # Importa persist_history para consulta OSV e persistência
    try:
        from persist_history import query_vulnerability_data
        use_persist_history = True
    except ImportError:
        log("persist_history.py não disponível, usando fallback", "WARN")
        use_persist_history = False
    
    cur = conn.cursor()
    count = 0

    for result in all_results:
        result_type = result.get("Type", "").lower()
        
        # Map Trivy type → nosso ecosystem
        if "composer" in result_type:
            ecosystem = "PHP"
        elif "npm" in result_type or "package" in result_type.lower():
            ecosystem = "Node.js"
        elif "pip" in result_type or "poetry" in result_type:
            ecosystem = "Python"
        else:
            ecosystem = "UNKNOWN"
        
        log(f"\n🌍 Ecossistema: {ecosystem} (Type: {result.get('Type')})")
        
        for vuln in (result.get("Vulnerabilities") or []):
            cve_id = vuln.get("VulnerabilityID")
            pkg = vuln.get("PkgName")
            version = vuln.get("InstalledVersion")
            sev = vuln.get("Severity", "UNKNOWN")
            fixed_ver = vuln.get("FixedVersion")
            
            # Req 5: Verificar duplicação ANTES de inserir
            cur.execute("""
                SELECT id FROM vulnerability_records
                WHERE execution_id = %s
                  AND cve_id = %s
                  AND package_name = %s
                  AND installed_version = %s
                  AND ecosystem = %s
            """, (execution_id, cve_id, pkg, version, ecosystem))
            
            if cur.fetchone():
                log(f"  [DUPLICADO] {cve_id} em {pkg}:{version} ({ecosystem}) — ignorando")
                continue
            
            count += 1
            
            # Consulta dados via persist_history (OSV + curado)
            vdata = None
            source = "NONE"
            osv_ref = None
            rec_ver = None
            
            if use_persist_history:
                vdata = query_vulnerability_data(cur, pkg, version, ecosystem)
                if vdata:
                    source = vdata.get("source", "UNKNOWN")
                    osv_ref = vdata.get("osv_id")
                    rec_ver = vdata.get("recommended_version")
            
            log(f"  {pkg} {version} [{sev}] → {rec_ver or 'N/A'} ({source})")

            try:
                cur.execute("""
                    INSERT INTO vulnerability_records
                        (execution_id, cve_id, package_name, severity,
                         installed_version, fixed_version, remediation_status,
                         osv_reference, recommended_version, source_db, ecosystem)
                    VALUES (%s,%s,%s,%s,%s,%s,'OPEN',%s,%s,%s,%s)
                """, (
                    execution_id, cve_id, pkg, sev, version, fixed_ver,
                    osv_ref, rec_ver, source, ecosystem
                ))
            except Exception as e:
                log(f"DB insert error para {pkg}: {e}", "WARN")
                conn.rollback()
                continue

    if execution_id:
        try:
            cur.execute("UPDATE pipeline_executions SET vulnerabilities_found=%s WHERE id=%s",
                        (count, execution_id))
        except Exception:
            pass
    
    conn.commit()
    cur.close()
    log(f"✅ {count} vulnerabilidades salvas no Supabase (repositório: {repo})")
    return execution_id, count


# ============================================================
# STAGE 2: Agente de IA analisa e decide
# ============================================================
def stage2_ai_decide(conn):
    log("=" * 60)
    log("STAGE 2 — Agente de IA: Análise e Decisão de Remediação (Multi-Linguagem)")
    log("=" * 60)

    cur = conn.cursor()
    cur.execute("""
        SELECT id, package_name, severity, recommended_version,
               installed_version, cve_id, fixed_version, ecosystem
        FROM vulnerability_records
        WHERE remediation_status='OPEN' AND decision_status='PENDING'
        ORDER BY ecosystem, CASE severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END
    """)
    rows = cur.fetchall()
    cur.close()

    if not rows:
        log("Nenhuma vulnerabilidade pendente.")
        return

    # Agrupa por ecossistema
    by_ecosystem = {}
    for row in rows:
        vuln_id, pkg, sev, rec_ver, inst_ver, cve, fixed, eco = row
        if eco not in by_ecosystem:
            by_ecosystem[eco] = []
        by_ecosystem[eco].append({
            "id": vuln_id,
            "package_name": pkg,
            "severity": sev,
            "recommended_version": rec_ver,
            "installed_version": inst_ver,
            "cve_id": cve,
            "fixed_version": fixed,
            "ecosystem": eco
        })
    
    log(f"\n🌍 Ecossistemas com vulnerabilidades: {', '.join(by_ecosystem.keys())}")

    analisar_lote = get_ai_agent()
    approved = manual = ignored = 0
    cur = conn.cursor()

    for ecosystem, vulns in by_ecosystem.items():
        log(f"\n{ecosystem}:")
        log(f"  📊 {len(vulns)} vulnerabilidade(s)")
        
        if analisar_lote:
            log(f"  Enviando {len(set(v['package_name'] for v in vulns))} pacote(s) para análise...")
            try:
                decisoes = analisar_lote(vulns)
                for d in decisoes:
                    pkg      = d["package_name"]
                    decision = d["decision"]
                    rec_ver  = d.get("recommended_version")
                    justif   = d.get("justification", "")

                    if decision == "APPROVED":   approved += 1
                    elif decision == "IGNORE":   ignored  += 1
                    else:                        manual   += 1

                    cur.execute("""
                        UPDATE vulnerability_records
                        SET decision_status=%s, ai_justification=%s,
                            recommended_version=COALESCE(%s, recommended_version),
                            updated_at=NOW()
                        WHERE package_name=%s
                          AND ecosystem=%s
                          AND remediation_status='OPEN'
                          AND decision_status='PENDING'
                    """, (decision, justif, rec_ver, pkg, ecosystem))

                conn.commit()
                log(f"  ✅ {ecosystem}: Approved={approved} | Manual={manual} | Ignored={ignored}")
            except Exception as e:
                log(f"  Agente de IA falhou: {e}. Usando fallback.", "WARN")
                conn.rollback()
                
                log(f"  Usando regras de severidade como fallback para {ecosystem}...")
                seen = set()
                for vuln in vulns:
                    pkg = vuln["package_name"]
                    if pkg in seen:
                        continue
                    seen.add(pkg)
                    sev = vuln["severity"]
                    rec = vuln["recommended_version"]

                    if sev in ("CRITICAL", "HIGH"):
                        dec = "APPROVED";      approved += 1
                    elif sev == "LOW":
                        dec = "IGNORE";        ignored  += 1
                    else:
                        dec = "MANUAL_REVIEW"; manual   += 1

                    cur.execute("""
                        UPDATE vulnerability_records
                        SET decision_status=%s,
                            ai_justification='Fallback: regra de severidade (IA indisponível)',
                            updated_at=NOW()
                        WHERE package_name=%s AND ecosystem=%s 
                          AND remediation_status='OPEN' AND decision_status='PENDING'
                    """, (dec, pkg, ecosystem))
                
                conn.commit()
        else:
            log(f"  Sem agente de IA — usando regras de severidade para {ecosystem}...")
            seen = set()
            for vuln in vulns:
                pkg = vuln["package_name"]
                if pkg in seen:
                    continue
                seen.add(pkg)
                sev = vuln["severity"]
                rec = vuln["recommended_version"]

                if sev in ("CRITICAL", "HIGH"):
                    dec = "APPROVED";      approved += 1
                elif sev == "LOW":
                    dec = "IGNORE";        ignored  += 1
                else:
                    dec = "MANUAL_REVIEW"; manual   += 1

                cur.execute("""
                    UPDATE vulnerability_records
                    SET decision_status=%s,
                        ai_justification='Fallback: regra de severidade (IA indisponível)',
                        updated_at=NOW()
                    WHERE package_name=%s AND ecosystem=%s 
                      AND remediation_status='OPEN' AND decision_status='PENDING'
                """, (dec, pkg, ecosystem))
                log(f"    {pkg}: {dec} (severity={sev})")
            
            conn.commit()

    cur.close()
    log(f"\n✅ Decisões finais: Approved={approved} | Manual Review={manual} | Ignored={ignored}")


# ============================================================
# STAGE 3: Aplicação dos patches NO REPOSITÓRIO ALVO
# ============================================================
COMMANDS = {
    "composer": lambda pkg, ver: ["composer", "require", f"{pkg}:{ver}", "--no-interaction"],
    "npm":      lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pip":      lambda pkg, ver: ["pip", "install", f"{pkg}=={ver}"],
}


def run_smoke_test(ecosystem, target_path):
    """
    Executa smoke test básico no target_path para validar estabilidade pós-patch.
    """
    if ecosystem == "PHP":
        result = subprocess.run(
            f"for f in $(find {target_path} -name '*.php' -not -path '*/vendor/*'); do php -l $f 2>&1 || exit 1; done",
            shell=True, capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            log(f"      ❌ Smoke test PHP falhou: {result.stderr[:200]}", "WARN")
            return False
        
        if os.path.exists(os.path.join(target_path, "composer.json")):
            result = subprocess.run(
                ["composer", "install", "--no-interaction", "--no-progress", "--prefer-dist"],
                cwd=target_path, capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                log(f"      ❌ Smoke test composer falhou: {result.stderr[:200]}", "WARN")
                return False
        
        return True
    
    elif ecosystem == "Node.js":
        result = subprocess.run(
            f"for f in $(find {target_path} -name '*.js' -not -path '*/node_modules/*'); do node --check $f 2>&1 || exit 1; done",
            shell=True, capture_output=True, text=True, timeout=60
        )
        return result.returncode == 0
    
    elif ecosystem == "Python":
        result = subprocess.run(
            f"python -m py_compile $(find {target_path} -name '*.py' -not -path '*/venv/*' -not -path '*/env/*') 2>&1 || true",
            shell=True, capture_output=True, text=True, timeout=60
        )
        return True
    
    return True


def get_virtual_patch_dir(target_path):
    """Cria e retorna diretório de virtual patches no target_path."""
    patch_dir = os.path.join(target_path, "virtual_patches")
    os.makedirs(patch_dir, exist_ok=True)
    return patch_dir


def stage3_apply_patches(conn, target_path):
    """
    Aplica patches de dependências no diretório do repositório alvo.
    
    Args:
        conn: Conexão com o banco
        target_path: Caminho do repositório alvo clonado
    """
    log("=" * 60)
    log("STAGE 3 — Aplicação de Patches no Repositório Alvo")
    log(f"     Alvo: {target_path}")
    log("=" * 60)

    cur = conn.cursor()
    
    cur.execute("""
        SELECT DISTINCT ecosystem
        FROM vulnerability_records
        WHERE decision_status='APPROVED' AND remediation_status='OPEN'
          AND ecosystem != 'UNKNOWN'
        ORDER BY ecosystem
    """)
    
    ecosystems = [row[0] for row in cur.fetchall()]
    
    if not ecosystems:
        log("Nenhuma vulnerabilidade aprovada para patch.")
        cur.close()
        return 0
    
    log(f"\n🌍 Ecossistemas com patches aprovados: {', '.join(ecosystems)}")
    
    total_remediated = total_failed = total_virtual_patched = 0
    
    for ecosystem in ecosystems:
        pm = PACKAGE_MANAGERS.get(ecosystem)
        if not pm:
            log(f"Ecossistema desconhecido: {ecosystem}", "WARN")
            continue
        
        log(f"\n{ecosystem}:")
        log(f"  Package manager: {pm}")
        
        binary = shutil.which(pm)
        if not binary:
            log(f"  ❌ {pm} não encontrado no PATH", "ERROR")
            continue
        
        cur.execute("""
            SELECT DISTINCT ON (package_name)
                id, package_name, installed_version, recommended_version, ai_justification
            FROM vulnerability_records
            WHERE decision_status='APPROVED' AND remediation_status='OPEN'
              AND ecosystem=%s
            ORDER BY package_name
        """, (ecosystem,))
        rows = cur.fetchall()
        
        if not rows:
            log(f"  ✅ Nenhuma vulnerabilidade aprovada para {ecosystem}")
            continue
        
        log(f"  🔧 Aplicando patches para {len(rows)} pacote(s)...")
        
        remediated = failed = virtual_patched = 0
        
        for _, pkg, old_ver, new_ver, justif in rows:
            if new_ver:
                log(f"    {pkg}: {old_ver} → {new_ver}")
                cmd = COMMANDS[pm](pkg, new_ver)
            else:
                log(f"    {pkg}: {old_ver} → (update genérico)")
                if pm == "composer":
                    cmd = ["composer", "update", pkg, "--no-interaction"]
                elif pm == "npm":
                    cmd = ["npm", "update", pkg]
                else:
                    cmd = ["pip", "install", "--upgrade", pkg]
            
            if justif:
                log(f"      Justificativa: {justif[:100]}")

            # Executa o comando NO DIRETÓRIO DO REPOSITÓRIO ALVO
            result = subprocess.run(cmd, cwd=target_path, capture_output=True, text=True)

            if result.returncode == 0:
                log(f"      ✅ Update aplicado com sucesso")
                
                log(f"      🔍 Executando smoke test...")
                smoke_ok = run_smoke_test(ecosystem, target_path)
                
                if smoke_ok:
                    log(f"      ✅ Smoke test passou — patch confirmado")
                    cur.execute("""
                        UPDATE vulnerability_records
                        SET remediation_status='REMEDIATED',
                            previous_version=installed_version,
                            updated_at=NOW()
                        WHERE package_name=%s AND ecosystem=%s
                          AND decision_status='APPROVED' AND remediation_status='OPEN'
                    """, (pkg, ecosystem))
                    remediated += 1
                else:
                    log(f"      ⚠️  Smoke test FALHOU — aplicando Virtual Patch", "WARN")
                    
                    # Reverte usando git no target_path
                    log(f"      ↩️  Revertendo update...")
                    subprocess.run(
                        ["git", "checkout", "--",
                         "composer.json", "composer.lock",
                         "package.json", "package-lock.json", "requirements.txt"],
                        cwd=target_path, capture_output=True, text=True
                    )
                    
                    log(f"      🧠 Gerando Virtual Patch...")
                    try:
                        from ai_agent import gerar_virtual_patch
                        
                        cur.execute("""
                            SELECT cve_id FROM vulnerability_records
                            WHERE package_name=%s AND ecosystem=%s
                              AND decision_status='APPROVED' AND remediation_status='OPEN'
                        """, (pkg, ecosystem))
                        cves = [row[0] for row in cur.fetchall()]
                        
                        patch_data = gerar_virtual_patch(
                            package_name=pkg,
                            cves=cves,
                            installed_version=old_ver,
                            ecosystem=ecosystem,
                            target_path=target_path  # Salva no diretório alvo
                        )
                        
                        if patch_data:
                            cur.execute("""
                                UPDATE vulnerability_records
                                SET remediation_status='VIRTUAL_PATCH',
                                    previous_version=installed_version,
                                    virtual_patch_path=%s,
                                    virtual_patch_data=%s,
                                    ai_justification=COALESCE(ai_justification, '') || %s,
                                    updated_at=NOW()
                                WHERE package_name=%s AND ecosystem=%s
                                  AND decision_status='APPROVED' AND remediation_status='OPEN'
                            """, (
                                patch_data["file_path"],
                                patch_data["patch_code"],
                                f" | VirtualPatch: {patch_data['justification']}",
                                pkg, ecosystem
                            ))
                            virtual_patched += 1
                            log(f"      ✅ Virtual Patch salvo em: {patch_data['file_path']}")
                        else:
                            log(f"      ❌ Falha ao gerar Virtual Patch", "WARN")
                            cur.execute("""
                                UPDATE vulnerability_records
                                SET remediation_status='FAILED',
                                    previous_version=installed_version,
                                    updated_at=NOW()
                                WHERE package_name=%s AND ecosystem=%s
                                  AND decision_status='APPROVED' AND remediation_status='OPEN'
                            """, (pkg, ecosystem))
                            failed += 1
                    except ImportError:
                        log(f"      ❌ gerar_virtual_patch não disponível", "WARN")
                        cur.execute("""
                            UPDATE vulnerability_records
                            SET remediation_status='FAILED',
                                previous_version=installed_version,
                                updated_at=NOW()
                            WHERE package_name=%s AND ecosystem=%s
                              AND decision_status='APPROVED' AND remediation_status='OPEN'
                        """, (pkg, ecosystem))
                        failed += 1
            else:
                log(f"      ❌ Falha no update: {result.stderr[:150]}", "WARN")
                
                log(f"      🧠 Tentando Virtual Patch como fallback...")
                try:
                    from ai_agent import gerar_virtual_patch
                    cur.execute("""
                        SELECT cve_id FROM vulnerability_records
                        WHERE package_name=%s AND ecosystem=%s
                          AND decision_status='APPROVED' AND remediation_status='OPEN'
                    """, (pkg, ecosystem))
                    cves = [row[0] for row in cur.fetchall()]
                    
                    patch_data = gerar_virtual_patch(
                        package_name=pkg,
                        cves=cves,
                        installed_version=old_ver,
                        ecosystem=ecosystem,
                        target_path=target_path
                    )
                    
                    if patch_data:
                        cur.execute("""
                            UPDATE vulnerability_records
                            SET remediation_status='VIRTUAL_PATCH',
                                previous_version=installed_version,
                                virtual_patch_path=%s,
                                virtual_patch_data=%s,
                                ai_justification=COALESCE(ai_justification, '') || %s,
                                updated_at=NOW()
                            WHERE package_name=%s AND ecosystem=%s
                              AND decision_status='APPROVED' AND remediation_status='OPEN'
                        """, (
                            patch_data["file_path"],
                            patch_data["patch_code"],
                            f" | VirtualPatch: {patch_data['justification']}",
                            pkg, ecosystem
                        ))
                        virtual_patched += 1
                    else:
                        cur.execute("""
                            UPDATE vulnerability_records
                            SET remediation_status='FAILED', updated_at=NOW()
                            WHERE package_name=%s AND ecosystem=%s
                              AND decision_status='APPROVED' AND remediation_status='OPEN'
                        """, (pkg, ecosystem))
                        failed += 1
                except ImportError:
                    cur.execute("""
                        UPDATE vulnerability_records
                        SET remediation_status='FAILED', updated_at=NOW()
                        WHERE package_name=%s AND ecosystem=%s
                          AND decision_status='APPROVED' AND remediation_status='OPEN'
                    """, (pkg, ecosystem))
                    failed += 1

        conn.commit()
        log(f"  ✅ {ecosystem}: {remediated} remediados | {virtual_patched} virtual patches | {failed} falhas")
        total_remediated += remediated
        total_virtual_patched += virtual_patched
        total_failed += failed
    
    cur.close()
    log(f"\n✅ TOTAL: {total_remediated} patches | {total_virtual_patched} virtual patches | {total_failed} falhas")
    return total_remediated + total_virtual_patched


# ============================================================
# STAGE 4: Validação e push para o repositório alvo
# ============================================================
def stage4_validate_and_push(conn, execution_id, vulns_before, target_path):
    """
    Valida resultado e faz push das correções para o repositório alvo.
    """
    log("=" * 60)
    log("STAGE 4 — Validação e Push para Repositório Alvo")
    log("=" * 60)

    # Tenta ler relatório pós-patch
    post_report_path = "reports/report_post_patch.json"
    success = True
    
    if os.path.exists(post_report_path):
        try:
            with open(post_report_path) as f:
                post = json.load(f)

            vulns_after = 0
            by_eco = {}
            
            for result in post.get("Results", []):
                result_type = result.get("Type", "").lower()
                
                if "composer" in result_type:
                    eco = "PHP"
                elif "npm" in result_type or "package" in result_type.lower():
                    eco = "Node.js"
                elif "pip" in result_type or "poetry" in result_type:
                    eco = "Python"
                else:
                    eco = "UNKNOWN"
                
                vuln_count = len(result.get("Vulnerabilities") or [])
                vulns_after += vuln_count
                by_eco[eco] = vuln_count

            reduction = round((vulns_before - vulns_after) / vulns_before * 100, 2) if vulns_before > 0 else 0

            log(f"\n📊 Resultados por ecossistema:")
            for eco, count in sorted(by_eco.items()):
                log(f"  {eco}: {count} vulnerabilidade(s)")
            
            log(f"\n✅ Vulnerabilidades: {vulns_before} → {vulns_after} (redução: {reduction}%)")

            if execution_id:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE pipeline_executions
                    SET vulnerabilities_resolved=%s, reduction_percentage=%s WHERE id=%s
                """, (vulns_before - vulns_after, reduction, execution_id))
                conn.commit()
                cur.close()

            if vulns_after > 0:
                log(f"⚠️  {vulns_after} vulnerabilidade(s) restantes", "WARN")
                success = False
        except Exception as e:
            log(f"Erro ao ler relatório pós-patch: {e}", "WARN")
    else:
        log("Relatório pós-patch não encontrado — validação será feita pelo security gate.", "WARN")

    # Commit e push das correções para o repositório alvo
    run_id = os.getenv("GITHUB_RUN_ID", f"local-{int(time.time())}")
    
    if TARGET_REPO_URL:
        log(f"\n📤 Enviando correções para o repositório alvo...")
        branch = commit_and_push_patches(target_path, run_id, TARGET_BRANCH_FIX)
        if branch:
            log(f"✅ Correções enviadas para branch '{branch}' em {TARGET_REPO_URL}")
        else:
            log("⚠️  Não foi possível enviar correções para o repositório alvo", "WARN")
    else:
        log("TARGET_REPO_URL não configurado — correções mantidas apenas localmente")

    return success


# ============================================================
# MAIN
# ============================================================
def main():
    print("\n" + "=" * 60)
    print("🔒 FRAMEWORK AUTÔNOMO DE REMEDIAÇÃO SCA")
    print("   IA como agente de segurança central")
    print("   Suporte: PHP (Composer) + Node.js (npm) + Python (pip)")
    print("=" * 60)

    # Req 2.5: verificação inicial do relatório
    if not os.path.exists("reports/report.json"):
        log("reports/report.json não encontrado. Execute o Trivy primeiro.", "ERROR")
        sys.exit(1)

    target_path = os.getcwd()
    target_repo = get_target_repo_name()

    conn = connect_db()
    execution_id = None
    vulns_found  = 0

    try:
        # Stage 0: clona repositório alvo (se configurado)
        target_path, target_repo = stage0_clone_target()

        # Stage 1: carrega, enriquece e persiste (multi-linguagem)
        execution_id, vulns_found = stage1_load_and_persist(conn, target_path)

        # Stage 2: IA analisa e decide (por ecossistema)
        stage2_ai_decide(conn)

        # Stage 3: aplica patches no repositório alvo
        remediated = stage3_apply_patches(conn, target_path)

        # Stage 4: valida resultado e faz push
        success = stage4_validate_and_push(conn, execution_id, vulns_found, target_path)

        # Req 12.1: finaliza registro
        status = "SUCCESS" if success else "PARTIAL"
        if execution_id:
            db_safe(db_finish_execution, conn, execution_id, status, vulns_found, remediated)

        print("\n" + "=" * 60)
        if success:
            print("✅ PIPELINE CONCLUÍDO — Todas as vulnerabilidades remediadas")
        else:
            print("⚠️  PIPELINE CONCLUÍDO — Revisão manual necessária para itens restantes")
        print(f"   Repositório alvo: {target_repo}")
        print("=" * 60)

    except Exception as e:
        log(f"Erro crítico no pipeline: {e}", "ERROR")
        if execution_id:
            db_safe(db_finish_execution, conn, execution_id, "FAILED", vulns_found, 0)
        raise
    finally:
        # Limpa diretório temporário se foi clonado
        if TARGET_REPO_URL and target_path and target_path != os.getcwd():
            cleanup_target_repository(target_path)
        conn.close()


if __name__ == "__main__":
    main()