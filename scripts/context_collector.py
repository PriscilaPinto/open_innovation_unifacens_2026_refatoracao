import os
import shutil
import subprocess
import tempfile


# ==========================================
# DETECT MULTIPLE ECOSYSTEMS
# ==========================================

def detect_ecosystems(base_path=None):
    """
    Detecta todos os ecossistemas presentes no projeto.

    Se base_path for informado, a detecção será feita
    dentro desse diretório.

    Caso contrário, utiliza o diretório atual.

    Retorna uma lista de ecossistemas detectados.
    """

    base_path = os.path.abspath(base_path or os.getcwd())

    ecosystems = []

    # ==========================================
    # PHP / COMPOSER
    # ==========================================

    composer_json = os.path.join(
        base_path,
        "composer.json"
    )

    if os.path.isfile(composer_json):
        ecosystems.append({
            "ecosystem": "php",
            "curated_ecosystem": "PHP",
            "osv_ecosystem": "Packagist",
            "package_manager": "composer",
            "lockfile": "composer.lock",
            "validation_command": [
                "php",
                "index.php"
            ],
            "manifest_file": "composer.json"
        })

    # ==========================================
    # NODE / NPM
    # ==========================================

    package_json = os.path.join(
        base_path,
        "package.json"
    )

    if os.path.isfile(package_json):
        ecosystems.append({
            "ecosystem": "node",
            "curated_ecosystem": "Node.js",
            "osv_ecosystem": "npm",
            "package_manager": "npm",
            "lockfile": "package-lock.json",
            "validation_command": [
                "npm",
                "test"
            ],
            "manifest_file": "package.json"
        })

    # ==========================================
    # PYTHON / PIP
    # ==========================================

    requirements_txt = os.path.join(
        base_path,
        "requirements.txt"
    )

    if os.path.isfile(requirements_txt):
        ecosystems.append({
            "ecosystem": "python",
            "curated_ecosystem": "Python",
            "osv_ecosystem": "PyPI",
            "package_manager": "pip",
            "lockfile": "requirements.txt",
            "validation_command": [
                "pytest"
            ],
            "manifest_file": "requirements.txt"
        })

    return ecosystems


# ==========================================
# BACKWARDS COMPATIBILITY
# ==========================================

def detect_ecosystem(base_path=None):
    """
    Mantém compatibilidade com código legado.

    Retorna o primeiro ecossistema detectado.

    Caso nenhum ecossistema seja encontrado,
    retorna uma estrutura vazia.
    """

    ecosystems = detect_ecosystems(base_path)

    if ecosystems:
        return ecosystems[0]

    return {
        "ecosystem": None,
        "curated_ecosystem": None,
        "osv_ecosystem": None,
        "package_manager": None,
        "lockfile": None,
        "validation_command": None,
        "manifest_file": None
    }


# ==========================================
# DETECT PACKAGE ECOSYSTEM BY REPORT
# ==========================================

def detect_vulnerability_ecosystem(vulnerability_json):
    """
    Detecta o ecossistema de uma vulnerabilidade
    com base nas informações fornecidas pelo Trivy.

    Exemplos:

        Type: composer
        Target: composer.lock

        -> PHP

        Type: npm
        Target: package-lock.json

        -> Node.js

        Type: pip
        Target: requirements.txt

        -> Python
    """

    if not isinstance(vulnerability_json, dict):
        return None

    vuln_type = str(
        vulnerability_json.get("Type", "")
    ).lower()

    target = str(
        vulnerability_json.get("Target", "")
    ).lower()

    # ==========================================
    # PHP / COMPOSER
    # ==========================================

    if (
        "composer" in vuln_type
        or "packagist" in vuln_type
        or "composer.lock" in target
        or "composer.json" in target
    ):
        return "PHP"

    # ==========================================
    # NODE / NPM
    # ==========================================

    if (
        "npm" in vuln_type
        or "node" in vuln_type
        or "package-lock.json" in target
        or "package.json" in target
        or "yarn.lock" in target
        or "pnpm-lock.yaml" in target
    ):
        return "Node.js"

    # ==========================================
    # PYTHON / PIP
    # ==========================================

    if (
        "pip" in vuln_type
        or "python" in vuln_type
        or "pypi" in vuln_type
        or "requirements.txt" in target
        or "pipfile" in target
        or "poetry.lock" in target
    ):
        return "Python"

    return None


# ==========================================
# GITHUB TOKEN
# ==========================================

def _get_github_token():
    """
    Obtém o token utilizado para autenticação
    com o GitHub.

    Prioridade:

        1. GH_TOKEN
        2. GITHUB_TOKEN
        3. PAT
    """

    return (
        os.getenv("GH_TOKEN")
        or os.getenv("GITHUB_TOKEN")
        or os.getenv("PAT")
    )


# ==========================================
# AUTHENTICATED REPOSITORY URL
# ==========================================

def _build_authenticated_url(repo_url):
    """
    Adiciona autenticação à URL HTTPS do GitHub.

    Exemplo:

        https://github.com/org/repo.git

    torna-se:

        https://x-access-token:TOKEN@github.com/org/repo.git

    Caso nenhum token seja encontrado,
    retorna a URL original.
    """

    if not repo_url:
        return repo_url

    token = _get_github_token()

    if not token:
        return repo_url

    if not repo_url.startswith(
        "https://github.com/"
    ):
        return repo_url

    return repo_url.replace(
        "https://github.com/",
        f"https://x-access-token:{token}@github.com/",
        1
    )


# ==========================================
# CLONE TARGET REPOSITORY
# ==========================================

def clone_target_repository(
    repo_url,
    branch="main",
    target_path=None
):
    """
    Clona o repositório alvo.

    Se target_path for informado, utiliza esse
    diretório como destino.

    Caso contrário, cria um diretório temporário.

    Retorna:

        Caminho absoluto do repositório clonado

    ou:

        None em caso de erro.
    """

    if not repo_url:
        print(
            "❌ URL do repositório alvo não informada."
        )
        return None

    # ==========================================
    # DEFINIR CAMINHO
    # ==========================================

    if target_path:

        target_path = os.path.abspath(
            target_path
        )

        if os.path.exists(target_path):

            print(
                f"⚠️ Diretório já existe: "
                f"{target_path}"
            )

            # Se já for um repositório Git,
            # reutilizamos o diretório.
            if os.path.isdir(
                os.path.join(
                    target_path,
                    ".git"
                )
            ):
                print(
                    "✅ Repositório Git existente "
                    "será reutilizado."
                )

                return target_path

            print(
                "⚠️ Diretório existente não é "
                "um repositório Git."
            )

            shutil.rmtree(
                target_path,
                ignore_errors=True
            )

    else:

        target_path = tempfile.mkdtemp(
            prefix="target-repo-"
        )

        shutil.rmtree(
            target_path,
            ignore_errors=True
        )

    # ==========================================
    # AUTENTICAÇÃO
    # ==========================================

    clone_url = _build_authenticated_url(
        repo_url
    )

    print(
        "📦 Clonando repositório alvo..."
    )

    print(
        f"   Branch: {branch}"
    )

    print(
        f"   Diretório: {target_path}"
    )

    # ==========================================
    # GIT CLONE
    # ==========================================

    command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        branch,
        clone_url,
        target_path
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:

            print(
                "❌ Falha ao clonar "
                "repositório alvo."
            )

            if result.stderr:
                print(
                    result.stderr[-3000:]
                )

            shutil.rmtree(
                target_path,
                ignore_errors=True
            )

            return None

        print(
            "✅ Repositório clonado com sucesso."
        )

        print(
            f"📁 Caminho: {target_path}"
        )

        return target_path

    except subprocess.TimeoutExpired:

        print(
            "❌ Timeout ao clonar "
            "o repositório."
        )

        shutil.rmtree(
            target_path,
            ignore_errors=True
        )

        return None

    except Exception as e:

        print(
            "❌ Erro inesperado ao clonar "
            f"repositório: {e}"
        )

        shutil.rmtree(
            target_path,
            ignore_errors=True
        )

        return None


# ==========================================
# CLEANUP TARGET REPOSITORY
# ==========================================

def cleanup_target_repository(
    target_path
):
    """
    Remove o diretório temporário do
    repositório alvo.

    Atenção:
    Este método deve ser utilizado somente
    quando o diretório foi criado pelo framework.

    Não deve ser usado para remover um
    repositório de trabalho permanente.
    """

    if not target_path:
        return

    if not os.path.exists(
        target_path
    ):
        return

    try:

        shutil.rmtree(
            target_path,
            ignore_errors=True
        )

        print(
            "🧹 Diretório temporário removido: "
            f"{target_path}"
        )

    except Exception as e:

        print(
            "⚠️ Não foi possível remover "
            f"o diretório temporário: {e}"
        )


# ==========================================
# COMMIT AND PUSH PATCHES
# ==========================================

def commit_and_push_patches(
    target_path,
    run_id,
    target_branch="fix-remediation"
):
    """
    Cria ou atualiza a branch de remediação
    no repositório alvo.

    Fluxo:

        branch atual
             ↓
        checkout -B fix-remediation
             ↓
        git add -A
             ↓
        git commit
             ↓
        git push

    Retorna:

        Nome da branch em caso de sucesso

    ou:

        None em caso de falha.
    """

    if not target_path:

        print(
            "❌ Caminho do repositório "
            "alvo não informado."
        )

        return None

    target_path = os.path.abspath(
        target_path
    )

    if not os.path.isdir(
        target_path
    ):

        print(
            "❌ Diretório do repositório "
            f"não encontrado: {target_path}"
        )

        return None

    if not os.path.isdir(
        os.path.join(
            target_path,
            ".git"
        )
    ):

        print(
            "❌ O diretório informado "
            "não é um repositório Git."
        )

        return None

    try:

        # ==========================================
        # CONFIGURAÇÃO DO GIT
        # ==========================================

        subprocess.run(
            [
                "git",
                "config",
                "user.name",
                "DevSecOps AI Agent"
            ],
            cwd=target_path,
            check=True
        )

        subprocess.run(
            [
                "git",
                "config",
                "user.email",
                "devsecops-ai-agent@users.noreply.github.com"
            ],
            cwd=target_path,
            check=True
        )

        # ==========================================
        # CRIA / TROCA BRANCH
        # ==========================================

        print(
            f"🌿 Preparando branch "
            f"'{target_branch}'..."
        )

        branch_result = subprocess.run(
            [
                "git",
                "checkout",
                "-B",
                target_branch
            ],
            cwd=target_path,
            capture_output=True,
            text=True
        )

        if branch_result.returncode != 0:

            print(
                "❌ Falha ao criar/trocar "
                f"para branch '{target_branch}'."
            )

            print(
                branch_result.stderr
            )

            return None

        print(
            f"✅ Branch ativa: {target_branch}"
        )

        # ==========================================
        # VERIFICAR ALTERAÇÕES
        # ==========================================

        status_result = subprocess.run(
            [
                "git",
                "status",
                "--porcelain"
            ],
            cwd=target_path,
            capture_output=True,
            text=True,
            check=True
        )

        if not status_result.stdout.strip():

            print(
                "ℹ️ Nenhuma alteração detectada."
            )

            print(
                "ℹ️ Nada para commit/push."
            )

            return None

        print(
            "📝 Alterações detectadas:"
        )

        print(
            status_result.stdout
        )

        # ==========================================
        # GIT ADD
        # ==========================================

        subprocess.run(
            [
                "git",
                "add",
                "-A"
            ],
            cwd=target_path,
            check=True
        )

        # ==========================================
        # GIT COMMIT
        # ==========================================

        commit_message = (
            "fix(security): automatic "
            "vulnerability remediation "
            f"(run {run_id})"
        )

        commit_result = subprocess.run(
            [
                "git",
                "commit",
                "-m",
                commit_message
            ],
            cwd=target_path,
            capture_output=True,
            text=True
        )

        if commit_result.returncode != 0:

            combined_output = (
                (commit_result.stdout or "")
                +
                (commit_result.stderr or "")
            ).lower()

            if (
                "nothing to commit"
                in combined_output
            ):

                print(
                    "ℹ️ Nenhuma alteração "
                    "para realizar commit."
                )

                return None

            print(
                "❌ Falha ao criar commit."
            )

            print(
                commit_result.stderr
                or commit_result.stdout
            )

            return None

        print(
            "✅ Commit criado com sucesso."
        )

        # ==========================================
        # PUSH
        # ==========================================

        print(
            f"📤 Enviando branch "
            f"'{target_branch}'..."
        )

        push_result = subprocess.run(
            [
                "git",
                "push",
                "origin",
                target_branch,
                "--force-with-lease"
            ],
            cwd=target_path,
            capture_output=True,
            text=True,
            timeout=180
        )

        if push_result.returncode != 0:

            print(
                "❌ Falha ao executar push."
            )

            if push_result.stderr:

                print(
                    push_result.stderr[-3000:]
                )

            return None

        print(
            "✅ Push realizado com sucesso."
        )

        print(
            f"📌 Branch publicada: "
            f"{target_branch}"
        )

        return target_branch

    except subprocess.TimeoutExpired:

        print(
            "❌ Timeout durante o push "
            "para o GitHub."
        )

        return None

    except subprocess.CalledProcessError as e:

        print(
            f"❌ Erro em comando Git: {e}"
        )

        return None

    except Exception as e:

        print(
            "❌ Erro inesperado ao realizar "
            f"commit/push: {e}"
        )

        return None


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "🔍 DETECÇÃO DE ECOSSISTEMAS"
    )

    print("=" * 60)

    ecosystems = detect_ecosystems()

    print(
        f"Detectados {len(ecosystems)} "
        "ecossistema(s):"
    )

    if not ecosystems:

        print(
            "  ⚠️ Nenhum ecossistema detectado."
        )

    for eco in ecosystems:

        print(
            f"  - "
            f"{eco['curated_ecosystem']} "
            f"({eco['package_manager']})"
        )

    print("=" * 60)