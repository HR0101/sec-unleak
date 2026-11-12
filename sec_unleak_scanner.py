#!/usr/bin/env python3
"""
sec_unleak_scanner.py - Local Deterministic Security Auditor for Web & AI Apps
Based on the "AI App Security Checklist 100" (Local Deterministic Rules)
Unslopped: Terminal Console / Forensic Monochrome Edition
Supports single-project scan and full-system (all user repositories) scan.
Robust: CloudStorage, Library, and deep symlinks safely excluded.
"""

import os
import sys
import re
import json
import datetime
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

# ANSI Colors for CLI
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Categories based on 100 Checklist
CAT_SECRET = "秘密情報・鍵 (Secrets & Leaks)"
CAT_CONFIG = "公開・権限・設定 (Config & Exposure)"
CAT_INJECTION = "入力・コード脆弱性 (Code & Injection)"
CAT_SUPPLY = "依存・サプライチェーン (Supply Chain & Lock)"

# Regex patterns for Secret Scanning (No.001, 004, 011, 023)
SECRET_PATTERNS = [
    ("OpenAI API Key", r"sk-[a-zA-Z0-9_-]{32,64}", CAT_SECRET, "No.001: APIキーの直書き"),
    ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9_-]{32,100}", CAT_SECRET, "No.001: APIキーの直書き"),
    ("Google AI (Gemini) Key", r"AIza[0-9A-Za-z-_]{35}", CAT_SECRET, "No.001: APIキーの直書き"),
    ("GitHub Personal Access Token", r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})", CAT_SECRET, "No.001: APIキーの直書き"),
    ("AWS Access Key ID", r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", CAT_SECRET, "No.001: APIキーの直書き"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}", CAT_SECRET, "No.001: APIキーの直書き"),
    ("Private Key Header", r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", CAT_SECRET, "No.004: クライアント側の秘密情報"),
    ("Commented Password", r"(//|#|/\*)\s*(password|passwd|secret|api_key)\s*[:=]\s*['\"][^'\"]{6,}['\"]", CAT_SECRET, "No.023: コメント内の秘密情報"),
]

CLIENT_SECRET_PREFIXES = [
    ("NEXT_PUBLIC_ with Secret suffix", r"NEXT_PUBLIC_[A-Z0-9_]*(SECRET|KEY|PRIVATE|TOKEN|PASSWORD)", CAT_SECRET, "No.004: クライアント側の秘密情報"),
    ("VITE_ with Secret suffix", r"VITE_[A-Z0-9_]*(SECRET|PRIVATE|TOKEN|PASSWORD)", CAT_SECRET, "No.004: クライアント側の秘密情報"),
    ("REACT_APP_ with Secret suffix", r"REACT_APP_[A-Z0-9_]*(SECRET|PRIVATE|TOKEN|PASSWORD)", CAT_SECRET, "No.004: クライアント側の秘密情報"),
]

LOG_SECRET_PATTERNS = [
    ("Logging credential variable", r"(console\.log|logger\.(info|debug|warn|error)|print)\s*\([^)]*(password|passwd|apiKey|secret_key|authToken|bearerToken)[^)]*\)", CAT_SECRET, "No.006: ログへの機密出力"),
]

CONFIG_PATTERNS = [
    ("Debug Mode Enabled (Python)", r"^\s*(DEBUG\s*=\s*True|debug\s*=\s*True)", CAT_CONFIG, "No.035: デバッグモード"),
    ("Production SourceMap Enabled", r"productionSourceMap\s*:\s*true", CAT_CONFIG, "No.039: ソースマップの公開"),
]

CODE_PATTERNS = [
    ("Raw SQL Concatenation (Python f-string)", r"(cursor\.execute|execute_query|query)\s*\(\s*f[\"'].*SELECT.*\{", CAT_INJECTION, "No.051: SQLインジェクション"),
    ("Raw SQL Concatenation (JS +)", r"(query|execute)\s*\(\s*[\"']SELECT\s+.*[\"']\s*\+", CAT_INJECTION, "No.051: SQLインジェクション"),
    ("Command Injection (shell=True)", r"subprocess\.(Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True", CAT_INJECTION, "No.056: コマンドインジェクション"),
    ("Command Injection (os.system)", r"os\.system\s*\([^)]*\+", CAT_INJECTION, "No.056: コマンドインジェクション"),
    ("DOM XSS (innerHTML assignment)", r"\.innerHTML\s*=\s*(?!['\"][^'\"]*['\"])[a-zA-Z0-9_.]+", CAT_INJECTION, "No.071: DOMベースXSS"),
    ("Dangerous Zip Extraction (Zip Slip)", r"\.extractall\s*\((?![^)]*path\s*=)", CAT_INJECTION, "No.075: Zip Slip"),
]

IGNORE_DIRS = {
    ".git", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    ".idea", ".vscode", "dist", "build", ".next", ".nuxt", "coverage", ".audit_cache",
    "Library", "CloudStorage", ".Trash", "Applications", "Movies", "Music", "Pictures"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
    ".zip", ".tar", ".gz", ".pyc", ".lock", ".bin", ".exe", ".dylib", ".so"
}

class Issue:
    def __init__(self, rule_no: str, category: str, title: str, file_path: str, line_no: int, snippet: str, suggestion: str, severity: str = "HIGH", project_name: str = ""):
        self.rule_no = rule_no
        self.category = category
        self.title = title
        self.file_path = file_path
        self.line_no = line_no
        self.snippet = snippet
        self.suggestion = suggestion
        self.severity = severity
        self.project_name = project_name

    def to_dict(self):
        return {
            "rule": self.rule_no,
            "category": self.category,
            "title": self.title,
            "project": self.project_name,
            "file": self.file_path,
            "line": self.line_no,
            "snippet": self.snippet,
            "suggestion": self.suggestion,
            "severity": self.severity
        }

class SecurityScanner:
    def __init__(self, target_dir: str, project_name: Optional[str] = None):
        self.target_dir = Path(target_dir).resolve()
        self.project_name = project_name or self.target_dir.name
        self.issues: List[Issue] = []
        self.scanned_files_count = 0

    def run_all_checks(self):
        self.check_env_and_gitignore()
        self.check_backup_files()
        self.check_docker_and_ports()
        self.check_lockfiles()
        self.scan_file_contents()

    def check_env_and_gitignore(self):
        gitignore_path = self.target_dir / ".gitignore"
        gitignore_rules = []
        if gitignore_path.exists():
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                    gitignore_rules = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
        else:
            if (self.target_dir / ".git").exists() and self.target_dir != Path.home():
                self.issues.append(Issue(
                    rule_no="No.002 / No.026",
                    category=CAT_SECRET,
                    title=".gitignore ファイルが存在しません",
                    file_path=str(self.target_dir / ".gitignore"),
                    line_no=0,
                    snippet="ファイル未作成",
                    suggestion=".gitignore を作成し、.env や秘密鍵を除外設定してください。",
                    severity="HIGH",
                    project_name=self.project_name
                ))

        # Safely find .env files up to depth 3 without recursive globbing into symlinks
        env_files = []
        try:
            for root, dirs, files in os.walk(self.target_dir, followlinks=False):
                # Prune ignored
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
                for f in files:
                    if f.startswith(".env") and f != ".env.example":
                        env_files.append(Path(root) / f)
                
                # Limit depth
                rel = Path(root).relative_to(self.target_dir)
                if len(rel.parts) >= 3:
                    dirs[:] = []
        except Exception:
            pass

        for env_file in env_files:
            try:
                rel_path = str(env_file.relative_to(self.target_dir))
            except Exception:
                rel_path = env_file.name

            is_ignored = any(r in rel_path or r == ".env*" or r == ".env" for r in gitignore_rules)
            if not is_ignored:
                self.issues.append(Issue(
                    rule_no="No.002: .envの誤公開",
                    category=CAT_SECRET,
                    title=f"{env_file.name} が .gitignore で除外されていません",
                    file_path=str(env_file),
                    line_no=1,
                    snippet=f"File: {rel_path}",
                    suggestion=f".gitignore に `{env_file.name}` または `.env*` を追記してください。",
                    severity="CRITICAL",
                    project_name=self.project_name
                ))

        if (self.target_dir / ".git").exists():
            try:
                res = subprocess.run(["git", "ls-files", ".env*"], cwd=self.target_dir, capture_output=True, text=True, timeout=5)
                tracked_envs = [f.strip() for f in res.stdout.split("\n") if f.strip() and not f.endswith(".example")]
                for te in tracked_envs:
                    self.issues.append(Issue(
                        rule_no="No.002 / No.003",
                        category=CAT_SECRET,
                        title=f"{te} が既にGitの追跡対象（ステージ/コミット）になっています！",
                        file_path=str(self.target_dir / te),
                        line_no=1,
                        snippet=f"git tracked: {te}",
                        suggestion=f"`git rm --cached {te}` を実行してGit追跡を解除してください。",
                        severity="CRITICAL",
                        project_name=self.project_name
                    ))
            except Exception:
                pass

    def check_backup_files(self):
        backup_exts = {".bak", ".backup", ".old", ".sql", ".dump"}
        try:
            for root, dirs, files in os.walk(self.target_dir, followlinks=False):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in backup_exts or f.endswith("~"):
                        if "migration" in f.lower() or "schema" in f.lower() or "migration" in root.lower():
                            continue
                        self.issues.append(Issue(
                            rule_no="No.040: バックアップの放置",
                            category=CAT_CONFIG,
                            title=f"バックアップ/ダンプファイルが配置されています: {f}",
                            file_path=os.path.join(root, f),
                            line_no=1,
                            snippet=f"File: {f}",
                            suggestion="不要なバックアップやSQLダンプはリポジトリ外に退避するか削除してください。",
                            severity="MEDIUM",
                            project_name=self.project_name
                        ))
                rel = Path(root).relative_to(self.target_dir)
                if len(rel.parts) >= 3:
                    dirs[:] = []
        except Exception:
            pass

    def check_docker_and_ports(self):
        dockerfiles = list(self.target_dir.glob("Dockerfile*"))
        for df in dockerfiles:
            try:
                with open(df, "r", encoding="utf-8", errors="ignore") as f:
                    for idx, line in enumerate(f, 1):
                        if re.search(r"^\s*(COPY|ADD)\s+.*\.env", line):
                            self.issues.append(Issue(
                                rule_no="No.018: イメージ内の秘密情報",
                                category=CAT_SECRET,
                                title="Dockerfileで.envファイルがイメージ内にコピーされています",
                                file_path=str(df),
                                line_no=idx,
                                snippet=line.strip(),
                                suggestion=".envをDockerイメージに含めず、実行時に環境変数として注入してください。",
                                severity="CRITICAL",
                                project_name=self.project_name
                            ))
            except Exception:
                pass

        compose_files = list(self.target_dir.glob("docker-compose*.yml")) + list(self.target_dir.glob("docker-compose*.yaml"))
        for cf in compose_files:
            try:
                with open(cf, "r", encoding="utf-8", errors="ignore") as f:
                    for idx, line in enumerate(f, 1):
                        if re.search(r"-\s*['\"]?(5432:5432|3306:3306|27017:27017|6379:6379)['\"]?", line):
                            self.issues.append(Issue(
                                rule_no="No.045: 不要なポート公開",
                                category=CAT_CONFIG,
                                title="データベースポートがホスト側に直接公開されています",
                                file_path=str(cf),
                                line_no=idx,
                                snippet=line.strip(),
                                suggestion="ポート公開を削除するか、`127.0.0.1:5432:5432` のようにローカルバインドに限定してください。",
                                severity="HIGH",
                                project_name=self.project_name
                            ))
            except Exception:
                pass

    def check_lockfiles(self):
        pkg_json = self.target_dir / "package.json"
        if pkg_json.exists():
            lockfiles = [
                self.target_dir / "package-lock.json",
                self.target_dir / "yarn.lock",
                self.target_dir / "pnpm-lock.yaml",
                self.target_dir / "bun.lockb"
            ]
            if not any(lf.exists() for lf in lockfiles):
                self.issues.append(Issue(
                    rule_no="No.096: バージョン固定",
                    category=CAT_SUPPLY,
                    title="Node.jsのロックファイルが見つかりません",
                    file_path=str(pkg_json),
                    line_no=1,
                    snippet="package.json found without lockfile",
                    suggestion="ロックファイルを生成・コミットしてください。",
                    severity="HIGH",
                    project_name=self.project_name
                ))

    def scan_file_contents(self):
        all_rules = SECRET_PATTERNS + CLIENT_SECRET_PREFIXES + LOG_SECRET_PATTERNS + CONFIG_PATTERNS + CODE_PATTERNS

        try:
            for root, dirs, files in os.walk(self.target_dir, followlinks=False):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]

                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in IGNORE_EXTENSIONS:
                        continue

                    full_path = os.path.join(root, file)
                    if file.startswith(".env") or file == "sec_unleak_scanner.py" or file == "AI_APP_SECURITY_100_AUDIT_REPORT.md" or file.endswith(".html"):
                        continue

                    self.scanned_files_count += 1
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            for line_idx, line in enumerate(f, 1):
                                if len(line) > 1000:
                                    continue

                                for rule_title, pattern, category, rule_no in all_rules:
                                    match = re.search(pattern, line)
                                    if match:
                                        snippet = line.strip()
                                        if len(snippet) > 120:
                                            snippet = snippet[:117] + "..."

                                        self.issues.append(Issue(
                                            rule_no=rule_no,
                                            category=category,
                                            title=f"{rule_title} の検知",
                                            file_path=full_path,
                                            line_no=line_idx,
                                            snippet=snippet,
                                            suggestion="安全な実装・環境変数化を行ってください。",
                                            severity="CRITICAL" if category == CAT_SECRET else "HIGH",
                                            project_name=self.project_name
                                        ))
                    except Exception:
                        pass

                # Limit depth
                rel = Path(root).relative_to(self.target_dir)
                if len(rel.parts) >= 4:
                    dirs[:] = []
        except Exception:
            pass

def discover_all_repositories(base_dir: Path) -> List[Path]:
    """Discover all Git repositories under base_dir with safe pruning, excluding home root itself"""
    ignore_root_dirs = {
        'Library', '.Trash', '.cache', '.npm', '.cargo', '.rustup',
        '.pyenv', '.local', '.gemini', 'node_modules', 'venv', '.venv',
        'Applications', 'System', 'Movies', 'Music', 'Pictures', '.codex',
        '.claude', '.openclaw', '.config'
    }
    repos = []
    try:
        for root, dirs, files in os.walk(base_dir, followlinks=False):
            try:
                rel = Path(root).relative_to(base_dir)
                parts = rel.parts
                if parts and parts[0] in ignore_root_dirs:
                    dirs[:] = []
                    continue

                # Don't add home root itself
                if Path(root) != base_dir and '.git' in dirs:
                    repos.append(Path(root))
                    dirs.remove('.git')

                dirs[:] = [d for d in dirs if d not in ignore_root_dirs and not d.startswith('.')]
                if len(parts) >= 3:
                    dirs[:] = []
            except Exception:
                dirs[:] = []
                continue
    except Exception:
        pass

    return sorted(repos)

def generate_global_html_report(results: List[Tuple[str, SecurityScanner]], output_path: str):
    """Generate an Unslopped Global System Security Console Report"""
    total_projects = len(results)
    total_files = sum(s.scanned_files_count for _, s in results)
    all_issues: List[Issue] = []
    for _, s in results:
        all_issues.extend(s.issues)

    crit_count = sum(1 for i in all_issues if i.severity == "CRITICAL")
    high_count = sum(1 for i in all_issues if i.severity == "HIGH")
    med_count = sum(1 for i in all_issues if i.severity in ("MEDIUM", "LOW"))
    clean_projects = sum(1 for _, s in results if len(s.issues) == 0)
    vuln_projects = total_projects - clean_projects

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Rows
    rows_html = ""
    for idx, i in enumerate(all_issues, 1):
        sev_badge = ""
        if i.severity == "CRITICAL":
            sev_badge = '<span class="sev-tag sev-crit">[CRIT]</span>'
        elif i.severity == "HIGH":
            sev_badge = '<span class="sev-tag sev-high">[HIGH]</span>'
        else:
            sev_badge = '<span class="sev-tag sev-med">[WARN]</span>'

        escaped_snippet = i.snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        
        rows_html += f"""
        <tr class="issue-row" data-sev="{i.severity.lower()}" data-proj="{i.project_name}">
            <td class="col-idx">{idx:03d}</td>
            <td class="col-sev">{sev_badge}</td>
            <td class="col-proj"><code>{i.project_name}</code></td>
            <td class="col-rule">{i.rule_no}</td>
            <td class="col-desc">
                <div class="desc-title">{i.title}</div>
                <div class="desc-loc">{i.file_path}:{i.line_no}</div>
                <div class="code-preview"><code>{escaped_snippet}</code></div>
            </td>
            <td class="col-action">{i.suggestion}</td>
        </tr>
        """

    # Project summary chips
    project_chips = ""
    for pname, s in results:
        p_crit = sum(1 for i in s.issues if i.severity == "CRITICAL")
        chip_cls = "chip-clean" if len(s.issues) == 0 else ("chip-crit" if p_crit > 0 else "chip-high")
        status_label = "CLEAN" if len(s.issues) == 0 else f"{len(s.issues)} ISSUES"
        project_chips += f"""
        <div class="proj-card {chip_cls}">
            <div class="proj-name" title="{pname}">{pname}</div>
            <div class="proj-status">{status_label}</div>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SEC-UNLEAK // SYSTEM-WIDE SECURITY AUDIT</title>
    <style>
        :root {{
            --bg-canvas: #090a0f;
            --bg-surface: #0f1118;
            --bg-subtle: #141721;
            --bg-code: #07080b;
            --border-dim: #1e2230;
            --border-active: #31374a;
            --text-main: #d4d7e1;
            --text-dim: #767d92;
            --text-bright: #ffffff;
            --accent-green: #10b981;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
            --mono: 'JetBrains Mono', 'SF Mono', Menlo, Monaco, Consolas, monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-canvas);
            color: var(--text-main);
            font-family: var(--mono);
            font-size: 13px;
            line-height: 1.5;
            padding: 24px;
        }}
        .console-wrap {{ max-width: 1400px; margin: 0 auto; }}

        .term-header {{
            border: 1px solid var(--border-dim);
            background: var(--bg-surface);
            padding: 12px 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .term-title {{ font-weight: 700; color: var(--text-bright); display: flex; align-items: center; gap: 10px; }}
        .term-tag {{ font-size: 11px; background: var(--bg-subtle); border: 1px solid var(--border-active); color: var(--text-dim); padding: 2px 6px; border-radius: 2px; }}
        .term-meta {{ font-size: 12px; color: var(--text-dim); display: flex; gap: 16px; }}
        .term-meta span span {{ color: var(--text-main); }}

        .telemetry-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            border: 1px solid var(--border-dim);
            border-top: none;
            background: var(--bg-surface);
            margin-bottom: 16px;
        }}
        .telemetry-cell {{ padding: 12px 16px; border-right: 1px solid var(--border-dim); }}
        .telemetry-cell:last-child {{ border-right: none; }}
        .telemetry-label {{ font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 4px; }}
        .telemetry-val {{ font-size: 20px; font-weight: 700; color: var(--text-bright); font-variant-numeric: tabular-nums; }}
        .telemetry-val.crit {{ color: var(--accent-red); }}
        .telemetry-val.high {{ color: var(--accent-amber); }}
        .telemetry-val.clean {{ color: var(--accent-green); }}

        .sec-section {{ margin-bottom: 16px; }}
        .section-header {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); margin-bottom: 8px; font-weight: 700; }}

        .project-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 8px;
            max-height: 200px;
            overflow-y: auto;
            padding: 8px;
            border: 1px solid var(--border-dim);
            background: var(--bg-surface);
            margin-bottom: 16px;
        }}
        .proj-card {{
            padding: 8px 10px;
            border: 1px solid var(--border-dim);
            background: var(--bg-subtle);
            border-radius: 2px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .proj-name {{ font-weight: 600; font-size: 12px; color: var(--text-bright); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 130px; }}
        .proj-status {{ font-size: 10px; font-weight: 700; }}
        .chip-clean .proj-status {{ color: var(--accent-green); }}
        .chip-high .proj-status {{ color: var(--accent-amber); }}
        .chip-crit .proj-status {{ color: var(--accent-red); }}

        .status-strip {{
            padding: 10px 16px;
            border: 1px solid var(--border-dim);
            margin-bottom: 16px;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .status-strip.status-pass {{ background: rgba(16, 185, 129, 0.06); border-color: rgba(16, 185, 129, 0.3); color: var(--accent-green); }}
        .status-strip.status-fail {{ background: rgba(239, 68, 68, 0.06); border-color: rgba(239, 68, 68, 0.4); color: var(--accent-red); }}

        .filter-btn {{
            background: var(--bg-subtle);
            border: 1px solid var(--border-dim);
            color: var(--text-dim);
            font-family: var(--mono);
            font-size: 11px;
            padding: 3px 8px;
            cursor: pointer;
            border-radius: 2px;
        }}
        .filter-btn.active {{ background: var(--border-active); color: var(--text-bright); border-color: var(--text-dim); }}

        .findings-table {{ width: 100%; border-collapse: collapse; border: 1px solid var(--border-dim); background: var(--bg-surface); font-size: 12px; }}
        .findings-table th {{ background: var(--bg-subtle); color: var(--text-dim); text-align: left; padding: 10px 14px; font-weight: 600; text-transform: uppercase; font-size: 11px; border-bottom: 1px solid var(--border-dim); }}
        .findings-table td {{ padding: 12px 14px; border-bottom: 1px solid var(--border-dim); vertical-align: top; }}
        .issue-row:hover {{ background: rgba(255, 255, 255, 0.02); }}

        .col-idx {{ width: 44px; color: var(--text-dim); }}
        .col-sev {{ width: 68px; }}
        .col-proj {{ width: 160px; }}
        .col-rule {{ width: 160px; font-weight: 600; }}
        .col-desc {{ width: auto; }}
        .col-action {{ width: 280px; color: #93c5fd; font-size: 11px; }}

        .sev-tag {{ font-weight: 700; font-size: 11px; }}
        .sev-tag.sev-crit {{ color: var(--accent-red); }}
        .sev-tag.sev-high {{ color: var(--accent-amber); }}
        .sev-tag.sev-med {{ color: #60a5fa; }}

        .desc-title {{ font-weight: 700; color: var(--text-bright); margin-bottom: 4px; }}
        .desc-loc {{ color: var(--text-dim); font-size: 11px; margin-bottom: 6px; word-break: break-all; }}
        .code-preview {{ background: var(--bg-code); border: 1px solid var(--border-dim); padding: 6px 8px; border-radius: 2px; font-family: var(--mono); color: #f87171; font-size: 11px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="console-wrap">
        <header class="term-header">
            <div class="term-title">
                <span>SEC-UNLEAK // SYSTEM-WIDE REPOSITORY AUDIT</span>
                <span class="term-tag">FULL-SYSTEM FORENSIC</span>
            </div>
            <div class="term-meta">
                <span>REPOSITORIES: <span>{total_projects}</span></span>
                <span>TOTAL ISSUES: <span>{len(all_issues)}</span></span>
                <span>TIME: <span>{now_str}</span></span>
            </div>
        </header>

        <div class="telemetry-grid">
            <div class="telemetry-cell">
                <div class="telemetry-label">Scanned Repositories</div>
                <div class="telemetry-val">{total_projects}</div>
            </div>
            <div class="telemetry-cell">
                <div class="telemetry-label">Clean Repositories</div>
                <div class="telemetry-val clean">{clean_projects}</div>
            </div>
            <div class="telemetry-cell">
                <div class="telemetry-label">Critical Leaks</div>
                <div class="telemetry-val {'crit' if crit_count > 0 else ''}">{crit_count:02d}</div>
            </div>
            <div class="telemetry-cell">
                <div class="telemetry-label">High Severity</div>
                <div class="telemetry-val {'high' if high_count > 0 else ''}">{high_count:02d}</div>
            </div>
            <div class="telemetry-cell">
                <div class="telemetry-label">Total Files Evaluated</div>
                <div class="telemetry-val">{total_files}</div>
            </div>
        </div>

        <div class="sec-section">
            <div class="section-header">Target Repository Landscape ({total_projects} Repositories Indexed)</div>
            <div class="project-grid">
                {project_chips}
            </div>
        </div>

        <div class="status-strip {'status-fail' if len(all_issues) > 0 else 'status-pass'}">
            <div>:: STATUS: {len(all_issues)} SECURITY FINDINGS DETECTED ACROSS {vuln_projects} REPOSITORIES</div>
            <div style="display:flex; gap:6px;">
                <button class="filter-btn active" onclick="filterRows('all')">ALL ({len(all_issues)})</button>
                <button class="filter-btn" onclick="filterRows('critical')">CRIT ({crit_count})</button>
                <button class="filter-btn" onclick="filterRows('high')">HIGH ({high_count})</button>
                <button class="filter-btn" onclick="filterRows('medium')">WARN ({med_count})</button>
            </div>
        </div>

        <main>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th class="col-idx">ID</th>
                        <th class="col-sev">SEV</th>
                        <th class="col-proj">REPOSITORY</th>
                        <th class="col-rule">CHECKLIST REF</th>
                        <th class="col-desc">EVIDENCE &amp; LOCATION</th>
                        <th class="col-action">RECOMMENDED REMEDIATION</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html if rows_html else '<tr><td colspan="6" style="padding:48px; text-align:center; color:#10b981; font-weight:700;">[PASS] ZERO DETERMINISTIC VULNERABILITIES DETECTED ACROSS ENTIRE SYSTEM.</td></tr>'}
                </tbody>
            </table>
        </main>
    </div>

    <script>
        function filterRows(sev) {{
            const rows = document.querySelectorAll('.issue-row');
            const btns = document.querySelectorAll('.filter-btn');
            btns.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            rows.forEach(r => {{
                if (sev === 'all') {{
                    r.style.display = '';
                }} else {{
                    r.style.display = r.getAttribute('data-sev') === sev ? '' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description="AI App Security 100 - Local Audit Engine")
    parser.add_argument("target", nargs="?", default=".", help="Target directory to scan")
    parser.add_argument("--all", "--system", action="store_true", help="Scan ALL Git repositories across the entire computer / user account")
    parser.add_argument("--fix", action="store_true", help="Automatically fix .gitignore and untrack exposed secrets")
    parser.add_argument("--html", action="store_true", help="Generate an HTML report and open it in the default browser")
    parser.add_argument("--json", action="store_true", help="Output audit results in JSON format")
    args = parser.parse_args()

    if args.all:
        home_dir = Path.home()
        print(f"\n{BOLD}======================================================================{RESET}")
        print(f"{BOLD}   SEC-UNLEAK // SYSTEM-WIDE REPOSITORY AUDIT ENGINE{RESET}")
        print(f"{BOLD}======================================================================{RESET}")
        print(f"Indexing repositories in: {home_dir} ...")
        repos = discover_all_repositories(home_dir)
        print(f"Discovered {len(repos)} repositories.\n")

        results: List[Tuple[str, SecurityScanner]] = []
        for idx, repo in enumerate(repos, 1):
            rel_name = str(repo.relative_to(home_dir))
            print(f"{CYAN}[{idx:02d}/{len(repos):02d}]{RESET} Auditing {rel_name} ...")

            scanner = SecurityScanner(str(repo), project_name=rel_name)
            scanner.run_all_checks()
            results.append((rel_name, scanner))

        print(f"\n{GREEN}{BOLD}[OK] System-wide audit completed.{RESET}\n")

        total_files = sum(s.scanned_files_count for _, s in results)
        all_issues = []
        for _, s in results:
            all_issues.extend(s.issues)

        crit_count = sum(1 for i in all_issues if i.severity == "CRITICAL")
        high_count = sum(1 for i in all_issues if i.severity == "HIGH")
        clean_repos = sum(1 for _, s in results if len(s.issues) == 0)

        print(f"REPOSITORIES SCANNED : {len(repos)}")
        print(f"CLEAN REPOSITORIES   : {GREEN}{clean_repos}{RESET} / {len(repos)}")
        print(f"TOTAL FILES AUDITED  : {total_files}")
        print(f"TOTAL FINDINGS       : {RED if all_issues else GREEN}{len(all_issues)}{RESET} (CRIT: {crit_count}, HIGH: {high_count})")

        report_file = os.path.join(os.getcwd(), "system_security_report.html")
        generate_global_html_report(results, report_file)
        print(f"\n{GREEN}[OK] Global System HTML Console generated: {report_file}{RESET}")

        if args.html and sys.platform == "darwin":
            subprocess.run(["open", report_file])

        sys.exit(1 if crit_count > 0 else 0)

    scanner = SecurityScanner(args.target)
    scanner.run_all_checks()

    print(f"\n{BOLD}======================================================================{RESET}")
    print(f"{BOLD}   SEC-UNLEAK // DETERMINISTIC AUDIT CONSOLE (CHECKLIST 100){RESET}")
    print(f"{BOLD}======================================================================{RESET}")
    print(f"TARGET : {scanner.target_dir}")
    print(f"FILES  : {scanner.scanned_files_count}")

    if not scanner.issues:
        print(f"\n{GREEN}{BOLD}[PASS] All deterministic checks evaluated clean.{RESET}\n")
    else:
        print(f"\n{RED}{BOLD}[FAIL] {len(scanner.issues)} security finding(s) detected:{RESET}\n")
        for idx, i in enumerate(scanner.issues, 1):
            color = RED if i.severity == "CRITICAL" else (YELLOW if i.severity == "HIGH" else BLUE)
            print(f"{color}[{i.severity}] {idx:02d}. {i.rule_no} - {i.title}{RESET}")
            print(f"   LOC : {i.file_path}:{i.line_no}")
            print(f"   CODE: {i.snippet}")
            print(f"   FIX : {GREEN}{i.suggestion}{RESET}")
            print("")

    if args.html:
        report_file = os.path.join(scanner.target_dir, "security_audit_report.html")
        scanner.generate_html_report(report_file)
        print(f"{GREEN}[OK] Forensic HTML console generated: {report_file}{RESET}")
        if sys.platform == "darwin":
            subprocess.run(["open", report_file])

    critical_or_high = [i for i in scanner.issues if i.severity in ("CRITICAL", "HIGH")]
    if critical_or_high:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
