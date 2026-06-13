from __future__ import annotations

import ast
import json
import re
import subprocess
import tempfile
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .models import (
    CodeChunk,
    CodeGraphEdge,
    CodeSymbol,
    Finding,
    FindingCategory,
    FindingSeverity,
    RepositoryMemory,
    sha256_text,
)


class RepositoryAccessError(ValueError):
    pass


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".tf",
    ".Dockerfile",
}

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    ".next",
    "tests",
    "examples",
    "sentinel_cli.py",
}


SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"),
    re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
)

PY_SQL_FSTRING = re.compile(
    r"\bquery\s*=\s*f(?P<quote>[\"']).*(SELECT|UPDATE|DELETE|INSERT).*\{[^}]+\}.*(?P=quote)",
    re.IGNORECASE,
)
PY_SQL_CONCAT = re.compile(
    r"\bquery\s*=\s*[\"'][^\"']*(SELECT|UPDATE|DELETE|INSERT)[^\"']*[\"']\s*\+",
    re.IGNORECASE,
)
JS_SQL_TEMPLATE = re.compile(
    r"`[^`]*(SELECT|UPDATE|DELETE|INSERT)[^`]*\$\{[^}]+\}[^`]*`",
    re.IGNORECASE,
)
UNSAFE_EXEC = re.compile(r"\b(eval|exec)\s*\(")
JS_UNSAFE_EXEC = re.compile(r"\b(eval|Function)\s*\(")
PY_PATH_TRAVERSAL = re.compile(
    r"\b(open|send_file|FileResponse|Path)\s*\([^)]*(request\.|input\s*\(|\.args|\.GET|\.POST)",
)
PY_PICKLE_LOAD = re.compile(r"\bpickle\.(load|loads)\s*\(")
PY_YAML_LOAD = re.compile(r"\byaml\.load\s*\(")
JS_XSS_SINK = re.compile(r"\.(innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML")
GIT_MERGE_CONFLICT = re.compile(r"^<{7}", re.MULTILINE)
PY_WEAK_RANDOM = re.compile(r"\brandom\.(random|randint|randrange|choice|choices)\s*\(")
SECURITY_CONTEXT = re.compile(r"(?i)(token|secret|password|csrf|session|otp|nonce|key)")


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_repo_path(settings: Settings, requested_path: str) -> Path:
    if requested_path.startswith("http://") or requested_path.startswith("https://"):
        parsed = urllib.parse.urlparse(requested_path)
        if not parsed.netloc:
            raise RepositoryAccessError(f"Invalid repository URL: {requested_path}")
        
        tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel-repo-"))
        try:
            import os
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            subprocess.run(
                ["git", "clone", "--depth", "1", requested_path, str(tmp_dir)],  # noqa: S603, S607
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
        except subprocess.CalledProcessError as e:
            raise RepositoryAccessError(f"Failed to clone repository: {e.stderr}") from e
        return tmp_dir

    repo_path = Path(requested_path).expanduser().resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise RepositoryAccessError(f"Repository path does not exist: {repo_path}")
    if not any(_is_relative_to(repo_path, root) for root in settings.allowed_repo_roots):
        allowed = ", ".join(str(root) for root in settings.allowed_repo_roots)
        raise RepositoryAccessError(f"Repository path is outside allowed roots: {allowed}")
    return repo_path


def safe_read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def is_supported_source(path: Path) -> bool:
    if path.name == "Dockerfile":
        return True
    return path.suffix in SUPPORTED_EXTENSIONS


import os
# Skip sentinel's own source only when running as GitHub Action
_is_github_action = os.getenv("GITHUB_ACTIONS") == "true"
_sentinel_own_path = Path(__file__).parent.resolve()

def iter_source_files(root: Path, *, max_file_bytes: int) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        # Never scan sentinel's own installed code when running in CI
        if _is_github_action and _sentinel_own_path in path.parents:
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        if not path.is_file() or not is_supported_source(path):
            continue
        if path.stat().st_size > max_file_bytes:
            continue
        files.append(path)
    return files


def tokenize(text: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text)}


def chunk_file(root: Path, path: Path, text: str, *, lines_per_chunk: int = 80) -> list[CodeChunk]:
    lines = text.splitlines()
    chunks: list[CodeChunk] = []
    relative = path.relative_to(root).as_posix()
    for start in range(0, max(len(lines), 1), lines_per_chunk):
        selected = lines[start : start + lines_per_chunk]
        chunk_text = "\n".join(selected)
        start_line = start + 1
        end_line = max(start_line, start + len(selected))
        chunks.append(
            CodeChunk(
                chunk_id=f"chunk_{sha256_text(f'{relative}:{start_line}:{end_line}')[:16]}",
                file_path=relative,
                start_line=start_line,
                end_line=end_line,
                text=chunk_text,
                token_fingerprint=sha256_text(" ".join(sorted(tokenize(chunk_text)))),
            )
        )
    return chunks


def extract_python_symbols(root: Path, path: Path, text: str) -> tuple[list[CodeSymbol], list[CodeGraphEdge]]:
    relative = path.relative_to(root).as_posix()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], []
    symbols: list[CodeSymbol] = []
    edges: list[CodeGraphEdge] = []
    defined_by_name: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol_id = f"sym_{sha256_text(f'{relative}:{node.name}:{node.lineno}')[:16]}"
            defined_by_name[node.name] = symbol_id
            symbols.append(
                CodeSymbol(
                    symbol_id=symbol_id,
                    name=node.name,
                    kind=node.__class__.__name__.replace("Def", "").lower(),
                    file_path=relative,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                )
            )

    parent_stack: list[str] = []

    class CallVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            current = defined_by_name.get(node.name)
            if current:
                parent_stack.append(current)
                self.generic_visit(node)
                parent_stack.pop()
            else:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)

        def visit_Call(self, node: ast.Call) -> None:
            if parent_stack and isinstance(node.func, ast.Name):
                target = defined_by_name.get(node.func.id)
                if target:
                    edges.append(
                        CodeGraphEdge(
                            source_id=parent_stack[-1],
                            target_id=target,
                            relationship="CALLS",
                        )
                    )
            self.generic_visit(node)

    CallVisitor().visit(tree)
    return symbols, edges


JS_SYMBOL = re.compile(
    r"(?P<prefix>function\s+|const\s+|let\s+|var\s+|class\s+)(?P<name>[A-Za-z_$][\w$]*)",
)


def extract_text_symbols(root: Path, path: Path, text: str) -> list[CodeSymbol]:
    relative = path.relative_to(root).as_posix()
    symbols: list[CodeSymbol] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = JS_SYMBOL.search(line)
        if not match:
            continue
        kind = "class" if match.group("prefix").strip() == "class" else "function"
        name = match.group("name")
        symbols.append(
            CodeSymbol(
                symbol_id=f"sym_{sha256_text(f'{relative}:{name}:{line_number}')[:16]}",
                name=name,
                kind=kind,
                file_path=relative,
                start_line=line_number,
                end_line=line_number,
            )
        )
    return symbols


def detect_findings(root: Path, path: Path, text: str) -> list[Finding]:
    relative = path.relative_to(root).as_posix()
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        for pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id="secrets.hardcoded_credential",
                        title="Hardcoded credential candidate",
                        category=FindingCategory.SECRET,
                        severity=FindingSeverity.CRITICAL,
                        file_path=relative,
                        line=line_number,
                        snippet=stripped,
                        confidence=0.85,
                        cwe="CWE-798",
                        remediation="Move the credential to a secret manager and rotate the leaked value.",
                    )
                )
        if path.suffix == ".py" and PY_SQL_FSTRING.search(line):
            findings.append(
                Finding(
                    rule_id="python.sql_injection.fstring",
                    title="SQL query uses f-string interpolation",
                    category=FindingCategory.INJECTION,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.92,
                    cwe="CWE-89",
                    remediation="Use parameterized database APIs instead of interpolating user input.",
                )
            )
        if path.suffix == ".py" and PY_SQL_CONCAT.search(line):
            findings.append(
                Finding(
                    rule_id="python.sql_injection.concat",
                    title="SQL query uses string concatenation",
                    category=FindingCategory.INJECTION,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.88,
                    cwe="CWE-89",
                    remediation="Replace query concatenation with parameter binding.",
                )
            )
        if path.suffix in {".js", ".jsx", ".ts", ".tsx"} and JS_SQL_TEMPLATE.search(line):
            findings.append(
                Finding(
                    rule_id="javascript.sql_injection.template",
                    title="SQL query uses template literal interpolation",
                    category=FindingCategory.INJECTION,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.9,
                    cwe="CWE-89",
                    remediation="Use prepared statements with parameter arrays.",
                )
            )
        if path.suffix == ".py" and UNSAFE_EXEC.search(line):
            findings.append(
                Finding(
                    rule_id="python.unsafe_execution",
                    title="Dynamic code execution",
                    category=FindingCategory.UNSAFE_EXECUTION,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.82,
                    cwe="CWE-94",
                    remediation="Replace dynamic execution with explicit parsing or a constrained evaluator.",
                )
            )
        if path.suffix == ".py" and PY_PATH_TRAVERSAL.search(line):
            findings.append(
                Finding(
                    rule_id="python.path_traversal.user_controlled_path",
                    title="User-controlled path reaches filesystem access",
                    category=FindingCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.8,
                    cwe="CWE-22",
                    remediation="Resolve the path under an allowlisted base directory and reject traversal.",
                )
            )
        if path.suffix == ".py" and PY_PICKLE_LOAD.search(line):
            findings.append(
                Finding(
                    rule_id="python.insecure_deserialization.pickle",
                    title="Pickle deserialization can execute attacker-controlled code",
                    category=FindingCategory.DESERIALIZATION,
                    severity=FindingSeverity.CRITICAL,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.9,
                    cwe="CWE-502",
                    remediation="Replace pickle with a safe structured format such as JSON for untrusted data.",
                )
            )
        if path.suffix in {".yaml", ".yml", ".py"} and PY_YAML_LOAD.search(line) and "SafeLoader" not in line:
            findings.append(
                Finding(
                    rule_id="python.yaml_load",
                    title="YAML load uses an unsafe loader",
                    category=FindingCategory.DESERIALIZATION,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.86,
                    cwe="CWE-20",
                    remediation="Use yaml.safe_load or yaml.load with SafeLoader.",
                )
            )
        if path.suffix == ".py" and PY_WEAK_RANDOM.search(line) and SECURITY_CONTEXT.search(line):
            findings.append(
                Finding(
                    rule_id="python.weak_random.security",
                    title="Non-cryptographic random used in security context",
                    category=FindingCategory.CRYPTOGRAPHY,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.82,
                    cwe="CWE-338",
                    remediation="Use the secrets module for tokens, nonces, and credentials.",
                )
            )
        if path.suffix in {".js", ".jsx", ".ts", ".tsx"} and JS_UNSAFE_EXEC.search(line):
            findings.append(
                Finding(
                    rule_id="javascript.unsafe_execution",
                    title="Dynamic JavaScript execution",
                    category=FindingCategory.UNSAFE_EXECUTION,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.82,
                    cwe="CWE-94",
                    remediation="Remove dynamic evaluation or route through a constrained interpreter.",
                )
            )
        if path.suffix in {".js", ".jsx", ".ts", ".tsx"} and JS_XSS_SINK.search(line):
            findings.append(
                Finding(
                    rule_id="javascript.xss.dom_sink",
                    title="Untrusted content reaches an HTML injection sink",
                    category=FindingCategory.XSS,
                    severity=FindingSeverity.HIGH,
                    file_path=relative,
                    line=line_number,
                    snippet=stripped,
                    confidence=0.78,
                    cwe="CWE-79",
                    remediation="Render text content safely or sanitize HTML with a reviewed allowlist.",
                )
            )
    if GIT_MERGE_CONFLICT.search(text):
        lines = text.splitlines()
        conflict_line = next(
            (idx + 1 for idx, line in enumerate(lines) if line.startswith("<<<<<<<")),
            1,
        )
        snippet = next((line for line in lines if line.startswith("<<<<<<<")), "<<<<<<<")
        findings.append(
            Finding(
                rule_id="git.merge_conflict",
                title="Unresolved Git merge conflict markers",
                category=FindingCategory.MISC,
                severity=FindingSeverity.HIGH,
                file_path=relative,
                line=conflict_line,
                snippet=snippet[:200],
                confidence=1.0,
                cwe="CWE-710",
                remediation="Resolve the merge conflict and remove all conflict markers before committing.",
            )
        )
    return findings


@dataclass(frozen=True)
class SearchResult:
    chunk: CodeChunk
    score: float


class RepositoryIngestor:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def ingest(self, requested_path: str, session_id: str | None = None) -> RepositoryMemory:
        import shutil

        from .checkov_scanner import CheckovConfig, CheckovScanner
        from .gitleaks_scanner import GitleaksConfig, GitleaksScanner
        from .semgrep_scanner import SemgrepConfig, SemgrepScanner
        from .trivy_scanner import TrivyConfig, TrivyScanner

        if session_id is None:
            session_id = "default-session"

        root = resolve_repo_path(self._settings, requested_path)
        chunks: list[CodeChunk] = []
        symbols: list[CodeSymbol] = []
        edges: list[CodeGraphEdge] = []
        findings: list[Finding] = []

        files = iter_source_files(root, max_file_bytes=self._settings.max_file_bytes)
        for path in files:
            text = safe_read_text(path)
            chunks.extend(chunk_file(root, path, text))
            findings.extend(detect_findings(root, path, text))
            if path.suffix == ".py":
                python_symbols, python_edges = extract_python_symbols(root, path, text)
                symbols.extend(python_symbols)
                edges.extend(python_edges)
            elif path.suffix in {".js", ".jsx", ".ts", ".tsx"}:
                symbols.extend(extract_text_symbols(root, path, text))

        if shutil.which("semgrep"):
            findings += SemgrepScanner(SemgrepConfig()).scan_repository(str(root), session_id)
        if shutil.which("gitleaks"):
            findings += GitleaksScanner(GitleaksConfig()).scan_repository(str(root), session_id)
        if shutil.which("trivy"):
            findings += TrivyScanner(TrivyConfig()).scan_repository(str(root), session_id)
        if shutil.which("checkov") and any((root / d).exists() for d in ["k8s", "helm", "terraform"]):
            findings += CheckovScanner(CheckovConfig()).scan_repository(str(root), session_id)

        memory = RepositoryMemory(
            root_path=str(root),
            files_indexed=len(files),
            chunks=chunks,
            symbols=symbols,
            edges=edges,
            findings=findings,
            validation_commands=self._detect_validation_commands(root),
        )

        # Connect Qdrant Vector database and Neo4j call graph database natively if they are running
        try:
            from .qdrant_memory import QdrantConfig, QdrantMemoryIndex
            qdrant_idx = QdrantMemoryIndex(QdrantConfig())
            qdrant_idx.index_chunks("dev-session", memory)
        except Exception:
            pass # Soft fallback for offline/local standalone mode

        try:
            import asyncio

            from .neo4j_memory import Neo4jConfig, Neo4jGraphIndex
            async def index_graph():
                graph_idx = Neo4jGraphIndex(Neo4jConfig())
                await graph_idx.index_memory("dev-session", memory)
                await graph_idx.close()
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(index_graph())
            else:
                asyncio.run(index_graph())
        except Exception:
            pass # Soft fallback if Neo4j container isn't online

        return memory

    def search(self, memory: RepositoryMemory, query: str, *, limit: int = 5) -> list[SearchResult]:
        """Semantic search — uses Azure AI Foundry embeddings when available,
        falls back to token-overlap Jaccard similarity."""
        from .azure_embeddings import get_embedder
        embedder = get_embedder()
        raw_results = embedder.search(memory, query, limit=limit)
        # Convert to legacy SearchResult type for backward compat
        return [SearchResult(chunk=r.chunk, score=r.score) for r in raw_results]

    def _detect_validation_commands(self, root: Path) -> list[list[str]]:
        configured = self._commands_from_sentinel_config(root)
        if configured:
            return configured
        if (root / "package.json").exists():
            try:
                package_json = json.loads(safe_read_text(root / "package.json"))
            except json.JSONDecodeError:
                package_json = {}
            scripts = package_json.get("scripts", {})
            if "test" in scripts:
                return [["npm", "test", "--", "--runInBand"]]
        if (root / "pytest.ini").exists() or any(root.glob("tests/test_*.py")):
            return [["python3", "-m", "unittest", "discover", "-s", "tests"]]
        if (root / "tests").exists():
            return [["python3", "-m", "unittest", "discover", "-s", "tests"]]
        return [["python3", "-m", "compileall", "."]]

    def _commands_from_sentinel_config(self, root: Path) -> list[list[str]]:
        config_path = root / "sentinel.json"
        if not config_path.exists():
            return []
        try:
            data = json.loads(safe_read_text(config_path))
        except json.JSONDecodeError:
            return []
        commands = data.get("validation_commands", [])
        sanitized: list[list[str]] = []
        for command in commands:
            if isinstance(command, list) and all(isinstance(part, str) for part in command):
                sanitized.append(command)
        return sanitized


class CodeMemoryIndex:
    def __init__(self, memory: RepositoryMemory) -> None:
        self.memory = memory
        self._symbols_by_file: dict[str, list[CodeSymbol]] = defaultdict(list)
        self._edges_by_symbol: dict[str, list[CodeGraphEdge]] = defaultdict(list)
        for symbol in memory.symbols:
            self._symbols_by_file[symbol.file_path].append(symbol)
        for edge in memory.edges:
            self._edges_by_symbol[edge.source_id].append(edge)

    def symbols_for_file(self, file_path: str) -> list[CodeSymbol]:
        return self._symbols_by_file.get(file_path, [])

    def graph_neighbors_for_file(self, file_path: str) -> list[CodeGraphEdge]:
        neighbors: list[CodeGraphEdge] = []
        for symbol in self.symbols_for_file(file_path):
            neighbors.extend(self._edges_by_symbol.get(symbol.symbol_id, []))
        return neighbors
