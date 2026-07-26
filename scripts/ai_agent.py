"""
Agente de IA - Cérebro do Framework de Remediação
Requisito 3: Análise orientada por IA via Google Gemini (gratuito)
Requisito 10: Retry com backoff exponencial até 5 tentativas
Requisito 4: Escolher VERSÃO MÍNIMA MITIGADA (same-major strategy)

NOTA: Usa Google Generative AI direto (sem OpenRouter).
      Chave gratuita em: https://aistudio.google.com/apikey
      Modelo: gemini-2.5-flash (gratuito, 60 req/min)
"""
import os
import json
import time
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

MODEL = os.getenv("AI_MODEL", "gemini-2.5-flash")
MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "600"))
TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.1"))
MAX_RETRIES = 5


def get_client():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY não configurada.\n"
            "Obtenha sua chave gratuita em: https://aistudio.google.com/apikey"
        )
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        MODEL,
        generation_config=genai.GenerationConfig(
            max_output_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
    )
    return model


def _call_with_retry(model, prompt):
    """Req 10: retry com backoff exponencial até 5 tentativas."""
    for attempt in range(MAX_RETRIES):
        try:
            response = model.generate_content(prompt)
            return response.text or ""
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            delay = 2 ** attempt
            print(f"    ⚠️  Tentativa {attempt + 1} falhou: {e}. Retry em {delay}s...")
            time.sleep(delay)


def get_curated_versions(package_name, ecosystem):
    """
    Consulta banco de dados curado (homologated_versions) para versões aprovadas.
    Retorna lista de versões seguras aprovadas, ordenada.
    
    Req 4: IA deve consultar banco curado para validar versão mínima mitigada.
    """
    try:
        from db import connect_db
        conn = connect_db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT safe_version, approved_by, notes, approved_at
            FROM homologated_versions
            WHERE package_name = %s AND ecosystem = %s
            ORDER BY approved_at DESC
        """, (package_name, ecosystem))
        
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        if rows:
            return [
                {
                    "version": r[0],
                    "approved_by": r[1],
                    "notes": r[2],
                    "approved_at": str(r[3]) if r[3] else None
                }
                for r in rows
            ]
    except Exception as e:
        print(f"    ⚠️  Erro ao consultar homologated_versions: {e}")
    
    return []


def analisar_pacote(package_name, installed_version, severity, cves,
                     fixed_versions, ecosystem, recommended_version=None):
    """
    Req 3: IA consulta OSV e decide estratégia de remediação para um pacote.
    Req 4: Escolhe VERSÃO MÍNIMA MITIGADA consultando banco curado.
    Consolida múltiplas CVEs do mesmo pacote em uma única decisão (Req 3.5).
    """
    client = get_client()
    
    # Req 4: Consulta versões aprovadas no banco curado
    curated_versions = get_curated_versions(package_name, ecosystem)

    context = {
        "package": package_name,
        "ecosystem": ecosystem,
        "installed_version": installed_version,
        "highest_severity": severity,
        "cves_affected": cves,
        "fixed_versions_available": fixed_versions if isinstance(fixed_versions, list) else [fixed_versions] if fixed_versions else [],
        "recommended_version_from_osv": recommended_version,
        "curated_approved_versions": [v["version"] for v in curated_versions],
        "project_type": "legacy - minimize breaking changes, same-major preferred"
    }

    prompt = f"""You are an autonomous DevSecOps security agent for legacy projects.

Analyze this vulnerability and decide the best remediation strategy.
IMPORTANT: Choose the MINIMUM VERSION that fixes all CVEs (same-major strategy).

Context:
{json.dumps(context, indent=2)}

Decision rules:
1. CRITICAL/HIGH severity with safe version → APPROVE (minimum safe version)
2. Prefer same-major version to avoid breaking changes (e.g., 6.3.0 → 6.5.8, NOT 7.x)
3. If curated_approved_versions exist, prefer one of them
4. If recommended_version_from_osv exists and is same-major, validate it
5. MEDIUM: APPROVE only if update risk is LOW and version is well-tested
6. LOW: IGNORE (not worth the risk)
7. If NO safe remediation exists: MANUAL_REVIEW
8. Consolidate all CVEs of same package into ONE version update

Respond ONLY with a valid JSON object, no markdown, no code fences.
Use this exact structure (values are examples only, replace with real data):
{"approved": true, "recommended_version": "MINIMUM_SAFE_VERSION", "risk_level": "LOW_or_MEDIUM_or_HIGH", "strategy": "same-major_or_newer_or_virtual_patch", "justification": "Brief explanation why this version was chosen"}"""

    try:
        content = _call_with_retry(client, prompt)

        # Remove markdown fences se presentes
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            if len(lines) > 2 and lines[-1].strip() == "```":
                content = "\n".join(lines[1:-1])
            else:
                content = "\n".join(lines[1:])
        content = content.strip()

        # Tenta parse direto
        try:
            result = json.loads(content)
            return result
        except json.JSONDecodeError:
            # Fallback: extrai JSON via regex (lida com strings quebradas)
            import re
            match = re.search(r'\{.*?"approved"\s*:\s*(true|false).*?\}', content, re.DOTALL)
            if match:
                raw = match.group(0)
                raw = raw.replace('\n', ' ').replace('\r', ' ')
                raw = raw.replace('\\"', "'")
                result = json.loads(raw)
                return result
            raise

    # Fallback: prefere curated se existir, caso contrário usa OSV
    safe_ver = None
    if curated_versions:
        safe_ver = curated_versions[0]["version"]
    elif recommended_version:
        safe_ver = recommended_version
    
    return {
        "approved": severity in ("CRITICAL", "HIGH") and bool(safe_ver),
        "recommended_version": safe_ver,
        "risk_level": "MEDIUM",
        "strategy": "fallback: curated or osv",
        "justification": f"Fallback: severity={severity}, curated={bool(curated_versions)}, version={safe_ver}"
    }


def gerar_virtual_patch(package_name, cves, installed_version, ecosystem, target_path="."):
    """
    Gera um virtual patch para mitigar vulnerabilidades SEM alterar a versão da lib.
    Usado quando o update da dependência quebra compatibilidade (smoke test falha).
    O patch é salvo no diretório do repositório alvo (target_path).
    
    Args:
        package_name: Nome do pacote vulnerável (ex: guzzlehttp/guzzle)
        cves: Lista de CVEs a mitigar
        installed_version: Versão atual instalada
        ecosystem: PHP, Node.js ou Python
        target_path: Diretório do repositório alvo onde salvar o patch
    
    Retorna:
        dict com patch_code, file_path e justification ou None se falhar
    """
    try:
        model = get_client()
    except Exception as e:
        print(f"    ⚠️  Erro ao criar cliente IA para virtual patch: {e}")
        return None

    # Define o tipo de arquivo e sintaxe baseado no ecossistema
    if ecosystem == "PHP":
        file_ext = "php"
        language = "PHP"
        comment = "//"
        filename_safe = package_name.replace("/", "_").replace("-", "_")
    elif ecosystem == "Node.js":
        file_ext = "js"
        language = "JavaScript"
        comment = "//"
        filename_safe = package_name.replace("/", "_").replace("-", "_")
    else:
        file_ext = "py"
        language = "Python"
        comment = "#"
        filename_safe = package_name.replace("/", "_").replace("-", "_")

    prompt = f"""You are a DevSecOps security engineer. A legacy project has a vulnerable dependency that CANNOT be updated because the new version breaks compatibility.

Generate a VIRTUAL PATCH — a code file that will be loaded by the application to MITIGATE the vulnerabilities WITHOUT changing the dependency version.

Package: {package_name} (version {installed_version})
Ecosystem: {ecosystem}
Language: {language}
CVEs to mitigate: {', '.join(cves)}

The virtual patch MUST:
1. Be valid {language} code that can be included/required by the main application
2. Intercept or wrap the vulnerable functionality to block the CVE attack vectors
3. NOT modify the original library files
4. Include clear comments explaining each mitigation
5. Start with a header comment identifying it as an auto-generated virtual patch

Return ONLY the source code, no markdown fences, no explanation.
""" + f"""
Example structure:
{comment} ============================================
{comment} Virtual Patch - Auto-generated by AI Agent
{comment} Package: {package_name}
{comment} CVEs: {', '.join(cves)}
{comment} This patch mitigates vulnerabilities without updating the library.
{comment} Generated: {__import__('datetime').datetime.now().isoformat()}
{comment} ============================================

[actual mitigation code here]
"""

    try:
        content = _call_with_retry(model, prompt)
        if not content:
            return None
            
        # Remove markdown fences se presentes
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1]) if len(lines) > 2 and lines[-1].strip() == "```" else "\n".join(lines[1:])
        content = content.strip()
        
        # Caminho do arquivo — salva NO REPOSITÓRIO ALVO
        patch_dir = os.path.join(target_path, "virtual_patches")
        os.makedirs(patch_dir, exist_ok=True)
        file_path = os.path.join(patch_dir, f"{filename_safe}_virtual_patch.{file_ext}")
        
        # Salva o patch no diretório alvo
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        print(f"      ✅ Virtual patch gerado em: {file_path} ({len(content)} bytes)")
        
        return {
            "patch_code": content,
            "file_path": file_path,
            "justification": f"Virtual Patch gerado para {package_name} ({', '.join(cves)}). "
                           f"Update quebrou compatibilidade, mitigação aplicada em {file_path}"
        }
    except Exception as e:
        print(f"    ⚠️  Erro ao gerar virtual patch: {e}")
        return None


def analisar_lote(vulnerabilidades):
    """
    Req 3: Analisa um lote agrupado por pacote.
    Req 3.5: Consolida múltiplas CVEs do mesmo pacote em uma única decisão.
    Retorna lista de dicts com decisão por pacote.
    """
    # Agrupa por pacote — consolida CVEs (Req 3.5)
    pacotes = {}
    for vuln in vulnerabilidades:
        pkg = vuln["package_name"]
        if pkg not in pacotes:
            pacotes[pkg] = {
                "package_name": pkg,
                "installed_version": vuln["installed_version"],
                "severity": vuln["severity"],
                "cves": [],
                "fixed_version": vuln.get("fixed_version", ""),
                "ecosystem": vuln.get("ecosystem", "PHP"),
                "recommended_version": vuln.get("recommended_version"),
                "ids": []
            }
        pacotes[pkg]["cves"].append(vuln["cve_id"])
        pacotes[pkg]["ids"].append(vuln["id"])

        # Mantém severidade mais alta
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        if sev_order.get(vuln["severity"], 9) < sev_order.get(pacotes[pkg]["severity"], 9):
            pacotes[pkg]["severity"] = vuln["severity"]

    resultados = []
    for pkg, info in pacotes.items():
        print(f"  🧠 IA analisando {pkg} {info['installed_version']} "
              f"(severity: {info['severity']}, CVEs: {len(info['cves'])})...")

        decisao = analisar_pacote(
            package_name=pkg,
            installed_version=info["installed_version"],
            severity=info["severity"],
            cves=info["cves"],
            fixed_versions=info["fixed_version"],
            ecosystem=info["ecosystem"],
            recommended_version=info["recommended_version"]
        )

        status = "✅ APPROVED" if decisao["approved"] else "⏸️  MANUAL_REVIEW"
        print(f"    → {status}: {decisao['justification'][:100]}")

        resultados.append({
            "package_name": pkg,
            "ids": info["ids"],
            "decision": "APPROVED" if decisao["approved"] else "MANUAL_REVIEW",
            "recommended_version": decisao.get("recommended_version"),
            "justification": decisao.get("justification", ""),
            "strategy": decisao.get("strategy", ""),
            "risk_level": decisao.get("risk_level", "MEDIUM")
        })

    return resultados