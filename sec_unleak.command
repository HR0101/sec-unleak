#!/bin/bash
# ==============================================================================
# sec_unleak.command - One-Click Local Security Auditor for macOS
# Based on the "AI App Security Checklist 100"
# ==============================================================================

cd "$(dirname "$0")"

BOLD="\033[1m"
GREEN="\033[92m"
CYAN="\033[96m"
YELLOW="\033[93m"
RED="\033[91m"
RESET="\033[0m"

clear
echo -e "${CYAN}${BOLD}"
echo "  ================================================================"
echo "        AIアプリの安全チェック 100選・ローカル監査ランチャー"
echo "  ================================================================"
echo -e "${RESET}"
echo -e "カレントディレクトリ: ${YELLOW}$(pwd)${RESET}"
echo ""
echo "実行モードを選択してください:"
echo -e "  ${BOLD}[1]${RESET} 現在のプロジェクトをスキャン ＋ HTMLレポートをブラウザで開く (デフォルト)"
echo -e "  ${BOLD}[2]${RESET} 自動修正付きスキャン (--fix: .gitignore自動追記 & Gitキャッシュ解除)"
echo -e "  ${BOLD}[3]${RESET} コンソールのみで高速スキャン (ターミナル出力のみ)"
echo -e "  ${BOLD}[4]${RESET}  パソコン全体（全開発プロジェクト）を一括監査 ＋ 統合HTMLレポート"
echo -e "  ${BOLD}[q]${RESET} 終了"
echo ""
read -p "選択 [1/2/3/4/q] (デフォルト: 1): " choice
choice=${choice:-1}

echo ""
echo -e "${CYAN}スキャンを実行しています...${RESET}"
echo "----------------------------------------------------------------"

case "$choice" in
    1)
        python3 sec_unleak_scanner.py . --html
        ;;
    2)
        python3 sec_unleak_scanner.py . --fix --html
        ;;
    3)
        python3 sec_unleak_scanner.py .
        ;;
    4)
        python3 sec_unleak_scanner.py --all --html
        ;;
    q|Q)
        echo "終了します。"
        exit 0
        ;;
    *)
        python3 sec_unleak_scanner.py . --html
        ;;
esac

STATUS=$?

echo ""
echo "----------------------------------------------------------------"
if [ $STATUS -eq 0 ]; then
    echo -e "${GREEN}${BOLD}[OK] 監査が完了しました。決定論的な脅威は検知されませんでした。${RESET}"
else
    echo -e "${RED}${BOLD}[WARN] 監査が完了しました。いくつかの警告・修正推奨事項があります。${RESET}"
fi
echo ""
echo -e "${YELLOW}AIによる文脈判断・プロンプト注入・エージェント監査が必要な項目は、${RESET}"
echo -e "${YELLOW}スキル『ai-sec-guardian』をご活用ください。${RESET}"
echo ""
read -p "エンターキーを押すとウィンドウを閉じます..."
