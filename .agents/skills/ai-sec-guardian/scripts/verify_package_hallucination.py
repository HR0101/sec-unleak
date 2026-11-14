#!/usr/bin/env python3
"""
verify_package_hallucination.py
No.080 スロップスクワッティング（AI幻覚パッケージ）対策

LLMが提案したパッケージ名について，次の2段階で確認する．
  1. 公式レジストリ（npm / PyPI）に実在するか
  2. 実在する場合，攻撃者が先回りして登録した可能性を示す危険信号がないか
     （公開からの日数，ダウンロード数，リリース数，ソースリポジトリの有無，有名パッケージとの名前の近さ）

注意: 「実在する」ことは「正規である」ことの証明にはならない．
スロップスクワッティングは，AIが捏造した名前を攻撃者が先に登録しておく攻撃である．
そのため本スクリプトは，実在するパッケージを「正規」とは判定しない．
危険信号がなくても，導入前に人の目で配布元を確認すること．

使い方:
  python3 verify_package_hallucination.py <npm|pypi> <package> [package ...]

終了コード:
  0: すべて実在し，危険信号もない
  1: 実在しない，名前が不正，または危険信号のあるパッケージを含む
  2: 引数の誤り
  3: ネットワーク障害などで確認できなかったパッケージを含む（「存在しない」とは判定しない）
  130: Ctrl+C で中断した
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

# ---- 通信設定 ----
USER_AGENT = "sec-unleak-verifier/2.0"
REQUEST_TIMEOUT_SECONDS = 10
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1.5
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# ---- 危険信号の判定基準 ----
MIN_AGE_DAYS = 90
MIN_WEEKLY_DOWNLOADS_NPM = 1000
MIN_MONTHLY_DOWNLOADS_PYPI = 4000
MIN_RELEASE_COUNT = 2
SIMILARITY_THRESHOLD = 0.85
MIN_SIMILARITY_NAME_LENGTH = 5

# ---- 終了コード ----
EXIT_OK = 0
EXIT_RISK = 1
EXIT_USAGE = 2
EXIT_LOOKUP_FAILED = 3
EXIT_INTERRUPTED = 130

# ---- 判定結果 ----
VERDICT_INVALID_NAME = "INVALID_NAME"
VERDICT_NOT_FOUND = "NOT_FOUND"
VERDICT_UNPUBLISHED = "UNPUBLISHED"
VERDICT_LOOKUP_FAILED = "LOOKUP_FAILED"
VERDICT_REVIEW_REQUIRED = "EXISTS_REVIEW_REQUIRED"
VERDICT_NO_RED_FLAGS = "EXISTS_NO_RED_FLAGS"

RISK_VERDICTS = {
  VERDICT_INVALID_NAME,
  VERDICT_NOT_FOUND,
  VERDICT_UNPUBLISHED,
  VERDICT_REVIEW_REQUIRED,
}

VERDICT_MESSAGES = {
  VERDICT_INVALID_NAME: "[DANGER] レジストリの命名規則に合わない名前です．AIの捏造を疑ってください．",
  VERDICT_NOT_FOUND: "[DANGER] レジストリに存在しません．AIの幻覚の可能性があります．後から攻撃者に登録される恐れもあるため，導入しないでください．",
  VERDICT_UNPUBLISHED: "[DANGER] 公開が取り消されたパッケージです．導入しないでください．",
  VERDICT_LOOKUP_FAILED: "[UNKNOWN] 確認できませんでした．存在しないとは判定していません．時間をおいて再実行してください．",
  VERDICT_REVIEW_REQUIRED: "[WARN] 実在しますが危険信号があります．先回り登録やタイポスクワッティングを疑い，配布元を人の目で確認してください．",
  VERDICT_NO_RED_FLAGS: "[INFO] 実在し，自動で調べた範囲では危険信号はありません．正規性の保証ではないため，配布元は確認してください．",
}

# ---- 命名規則 ----
NPM_NAME_PATTERN = re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
NPM_MAX_NAME_LENGTH = 214
PYPI_NAME_PATTERN = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)

# ソースリポジトリとみなすホスト
REPOSITORY_HOST_PATTERN = re.compile(r"github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht", re.IGNORECASE)

# 名前の近さを比べる有名パッケージ（タイポスクワッティング検出用の簡易リスト）
POPULAR_PACKAGES = {
  "npm": [
    "react", "react-dom", "express", "lodash", "axios", "next", "typescript",
    "webpack", "eslint", "prettier", "jest", "chalk", "commander", "moment",
    "dayjs", "dotenv", "cors", "body-parser", "jsonwebtoken", "bcrypt",
    "mongoose", "socket.io", "uuid", "zod", "vite", "tailwindcss", "openai",
    "@anthropic-ai/sdk", "langchain", "nodemailer",
  ],
  "pypi": [
    "requests", "numpy", "pandas", "scipy", "matplotlib", "django", "flask",
    "fastapi", "pydantic", "sqlalchemy", "boto3", "urllib3", "pytest",
    "pillow", "beautifulsoup4", "selenium", "tensorflow", "torch",
    "transformers", "scikit-learn", "openai", "anthropic", "langchain",
    "httpx", "cryptography", "pyyaml", "python-dotenv", "jinja2", "uvicorn",
    "huggingface-hub",
  ],
}


def fetchJson(url: str) -> Tuple[str, Optional[Any], Optional[str]]:
  """URLからJSONを取得する．戻り値は (結果種別, データ, エラー理由)．結果種別は ok / not_found / failed．"""
  lastError = "unknown error"
  for attempt in range(1, MAX_ATTEMPTS + 1):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
      with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return "ok", json.loads(response.read().decode("utf-8")), None
    except urllib.error.HTTPError as error:
      # 404 だけを「存在しない」とみなし，それ以外は「確認できなかった」として扱う
      if error.code == 404:
        return "not_found", None, None
      lastError = f"HTTP {error.code}"
      if error.code not in RETRYABLE_STATUS_CODES:
        break
    except (urllib.error.URLError, OSError) as error:
      lastError = f"network error: {getattr(error, 'reason', error)}"
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
      lastError = f"invalid JSON response: {error}"
      break
    if attempt < MAX_ATTEMPTS:
      time.sleep(RETRY_BACKOFF_SECONDS * attempt)
  return "failed", None, lastError


def isValidName(ecosystem: str, name: str) -> bool:
  """パッケージ名がレジストリの命名規則に合っているかを返す．"""
  if ecosystem == "npm":
    return len(name) <= NPM_MAX_NAME_LENGTH and bool(NPM_NAME_PATTERN.match(name))
  return bool(PYPI_NAME_PATTERN.match(name))


def normalizeName(ecosystem: str, name: str) -> str:
  """比較用に名前を正規化する（PyPI は PEP 503 に従う）．"""
  if ecosystem == "pypi":
    return re.sub(r"[-_.]+", "-", name).lower()
  return name.lower()


def parseIsoTime(value: str) -> Optional[datetime]:
  """ISO 8601 形式の日時を UTC の datetime に変換する．秒未満は切り捨てる．"""
  match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", value or "")
  if not match:
    return None
  return datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def daysSince(moment: Optional[datetime]) -> Optional[int]:
  """指定日時から現在までの日数を返す．"""
  if moment is None:
    return None
  return (datetime.now(timezone.utc) - moment).days


def collectNpmSignals(name: str) -> Dict[str, Any]:
  """npm レジストリから実在確認と危険信号の材料を集める．"""
  encodedName = urllib.parse.quote(name, safe="@")
  kind, data, error = fetchJson(f"https://registry.npmjs.org/{encodedName}")
  if kind != "ok":
    return {"lookup": kind, "error": error}

  versions = data.get("versions") or {}
  if not versions:
    return {"lookup": "unpublished"}

  timeInfo = data.get("time") or {}
  repository = data.get("repository")
  repositoryUrl = repository.get("url") if isinstance(repository, dict) else repository
  maintainers = data.get("maintainers") or []

  downloadKind, downloadData, _ = fetchJson(f"https://api.npmjs.org/downloads/point/last-week/{encodedName}")
  downloads = downloadData.get("downloads") if downloadKind == "ok" and isinstance(downloadData, dict) else None

  firstPublished = parseIsoTime(timeInfo.get("created", ""))
  return {
    "lookup": "ok",
    "firstPublished": firstPublished.isoformat() if firstPublished else None,
    "ageDays": daysSince(firstPublished),
    "releaseCount": len(versions),
    "maintainerCount": len(maintainers),
    "hasRepository": bool(repositoryUrl),
    "downloads": downloads,
    "downloadsPeriod": "last-week",
    "minDownloads": MIN_WEEKLY_DOWNLOADS_NPM,
  }


def collectPypiSignals(name: str) -> Dict[str, Any]:
  """PyPI から実在確認と危険信号の材料を集める．"""
  kind, data, error = fetchJson(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json")
  if kind != "ok":
    return {"lookup": kind, "error": error}

  info = data.get("info") or {}
  releases = data.get("releases") or {}
  uploadTimes = [
    parseIsoTime(fileInfo.get("upload_time_iso_8601", ""))
    for files in releases.values()
    for fileInfo in files
  ]
  uploadTimes = [moment for moment in uploadTimes if moment is not None]
  firstPublished = min(uploadTimes) if uploadTimes else None
  releaseCount = sum(1 for files in releases.values() if files)
  if releaseCount == 0:
    return {"lookup": "unpublished"}

  candidateUrls = list((info.get("project_urls") or {}).values()) + [info.get("home_page") or ""]
  hasRepository = any(REPOSITORY_HOST_PATTERN.search(str(url)) for url in candidateUrls)

  # pypistats は正規化した名前しか受け付けず，レート制限も厳しいため，失敗しても危険信号にはしない
  statsName = urllib.parse.quote(normalizeName("pypi", name), safe="")
  downloadKind, downloadData, _ = fetchJson(f"https://pypistats.org/api/packages/{statsName}/recent")
  downloads = None
  if downloadKind == "ok" and isinstance(downloadData, dict):
    downloads = (downloadData.get("data") or {}).get("last_month")

  return {
    "lookup": "ok",
    "firstPublished": firstPublished.isoformat() if firstPublished else None,
    "ageDays": daysSince(firstPublished),
    "releaseCount": releaseCount,
    "maintainerCount": None,
    "hasRepository": hasRepository,
    "downloads": downloads,
    "downloadsPeriod": "last-month",
    "minDownloads": MIN_MONTHLY_DOWNLOADS_PYPI,
  }


def findSimilarPopularPackage(ecosystem: str, name: str) -> Optional[str]:
  """有名パッケージのうち，名前が酷似しているもの（完全一致は除く）を返す．"""
  normalized = normalizeName(ecosystem, name)
  popularNames = [normalizeName(ecosystem, popular) for popular in POPULAR_PACKAGES[ecosystem]]
  if normalized in popularNames or len(normalized) < MIN_SIMILARITY_NAME_LENGTH:
    return None
  for popular in popularNames:
    if len(popular) < MIN_SIMILARITY_NAME_LENGTH:
      continue
    if SequenceMatcher(None, normalized, popular).ratio() >= SIMILARITY_THRESHOLD:
      return popular
  return None


def evaluateRedFlags(ecosystem: str, name: str, signals: Dict[str, Any]) -> List[str]:
  """集めた材料から危険信号の一覧を作る．"""
  redFlags = []

  ageDays = signals.get("ageDays")
  if ageDays is None:
    redFlags.append("初回公開日を取得できません")
  elif ageDays < MIN_AGE_DAYS:
    redFlags.append(f"公開から {ageDays} 日しか経っていません（基準: {MIN_AGE_DAYS} 日以上）")

  downloads = signals.get("downloads")
  if downloads is not None and downloads < signals["minDownloads"]:
    redFlags.append(
      f"ダウンロード数が少なすぎます（{signals['downloadsPeriod']}: {downloads}，基準: {signals['minDownloads']} 以上）"
    )

  if signals.get("releaseCount", 0) < MIN_RELEASE_COUNT:
    redFlags.append(f"リリースが {signals.get('releaseCount', 0)} 件しかありません")

  if not signals.get("hasRepository"):
    redFlags.append("ソースリポジトリへのリンクがありません")

  similarPackage = findSimilarPopularPackage(ecosystem, name)
  if similarPackage:
    redFlags.append(f"有名パッケージ「{similarPackage}」と名前が酷似しています（タイポスクワッティングの可能性）")

  return redFlags


def verifyPackage(ecosystem: str, name: str) -> Dict[str, Any]:
  """1つのパッケージを検証し，判定結果を返す．"""
  if not isValidName(ecosystem, name):
    return {"verdict": VERDICT_INVALID_NAME, "exists": None}

  collector = collectNpmSignals if ecosystem == "npm" else collectPypiSignals
  signals = collector(name)
  lookup = signals.pop("lookup")

  if lookup == "not_found":
    return {"verdict": VERDICT_NOT_FOUND, "exists": False}
  if lookup == "unpublished":
    return {"verdict": VERDICT_UNPUBLISHED, "exists": False}
  if lookup == "failed":
    return {"verdict": VERDICT_LOOKUP_FAILED, "exists": None, "error": signals.get("error")}

  redFlags = evaluateRedFlags(ecosystem, name, signals)
  signals.pop("minDownloads", None)
  return {
    "verdict": VERDICT_REVIEW_REQUIRED if redFlags else VERDICT_NO_RED_FLAGS,
    "exists": True,
    "redFlags": redFlags,
    "signals": signals,
  }


def decideExitCode(results: Dict[str, Dict[str, Any]]) -> int:
  """全パッケージの判定結果から終了コードを決める．"""
  verdicts = {result["verdict"] for result in results.values()}
  if verdicts & RISK_VERDICTS:
    return EXIT_RISK
  if VERDICT_LOOKUP_FAILED in verdicts:
    return EXIT_LOOKUP_FAILED
  return EXIT_OK


def parseArguments() -> argparse.Namespace:
  """コマンドライン引数を解釈する．誤りがあれば終了コード 2 で終わる．"""
  parser = argparse.ArgumentParser(
    description="AIが提案したパッケージの実在と危険信号を確認します（No.080 スロップスクワッティング対策）．"
  )
  parser.add_argument("ecosystem", choices=["npm", "pypi", "python"], help="レジストリの種類")
  parser.add_argument("packages", nargs="+", help="確認するパッケージ名")
  return parser.parse_args()


def main() -> None:
  arguments = parseArguments()
  ecosystem = "pypi" if arguments.ecosystem == "python" else arguments.ecosystem

  results = {}
  for packageName in arguments.packages:
    result = verifyPackage(ecosystem, packageName)
    result["ecosystem"] = ecosystem
    result["message"] = VERDICT_MESSAGES[result["verdict"]]
    results[packageName] = result

  print(json.dumps(results, indent=2, ensure_ascii=False))
  sys.exit(decideExitCode(results))


if __name__ == "__main__":
  try:
    main()
  except KeyboardInterrupt:
    sys.exit(EXIT_INTERRUPTED)
