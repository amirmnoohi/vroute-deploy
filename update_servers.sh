#!/bin/bash
###############################################################################
#  Update a file on VS2..VS17 servers via SCP
#
#  Usage:  bash update_servers.sh
#          bash update_servers.sh /path/to/local/file /opt/remote/file
#          bash update_servers.sh /path/to/local/file /opt/remote/file "systemctl restart sync-online"
###############################################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# ── Servers (VS2 to VS14) ──
SERVERS=(vs2 vs3 vs4 vs5 vs6 vs7 vs8 vs9 vs10 vs11 vs12 vs13 vs14 vs15 vs16 vs17)

# ── Get local file, remote path, and optional restart command ──
if [[ -n "$1" && -n "$2" ]]; then
    LOCAL_FILE="$1"
    REMOTE_PATH="$2"
    RESTART_CMD="${3:-}"
else
    read -rp "Local file to upload: " LOCAL_FILE
    read -rp "Remote destination path: " REMOTE_PATH
    read -rp "Command to run after upload (leave empty to skip): " RESTART_CMD
fi

[[ -z "$LOCAL_FILE" ]] && { echo -e "${RED}No local file specified${NC}"; exit 1; }
[[ ! -f "$LOCAL_FILE" ]] && { echo -e "${RED}File not found: $LOCAL_FILE${NC}"; exit 1; }
[[ -z "$REMOTE_PATH" ]] && { echo -e "${RED}No remote path specified${NC}"; exit 1; }

# ── SSH credentials ──
read -rp "SSH username: " SSH_USER
[[ -z "$SSH_USER" ]] && { echo -e "${RED}Username cannot be empty${NC}"; exit 1; }

read -rsp "SSH password: " SSH_PASS
echo ""
[[ -z "$SSH_PASS" ]] && { echo -e "${RED}Password cannot be empty${NC}"; exit 1; }

# ── Check sshpass ──
if ! command -v sshpass &>/dev/null; then
    echo -e "${YELLOW}Installing sshpass...${NC}"
    apt install -y sshpass 2>/dev/null || { echo -e "${RED}Cannot install sshpass. Install it manually.${NC}"; exit 1; }
fi

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Uploading: ${GREEN}$LOCAL_FILE${NC}"
echo -e "  To:        ${GREEN}$REMOTE_PATH${NC}"
echo -e "  Servers:   ${GREEN}vs2.vroute.org .. vs17.vroute.org${NC} (${#SERVERS[@]} servers)"
if [[ -n "$RESTART_CMD" ]]; then
    echo -e "  After:     ${YELLOW}$RESTART_CMD${NC}"
fi
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

SUCCESS=0
FAIL=0

for srv in "${SERVERS[@]}"; do
    host="${srv}.vroute.org"
    printf "  %-6s %-22s " "$srv" "$host"

    if sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "$LOCAL_FILE" "${SSH_USER}@${host}:${REMOTE_PATH}" 2>/dev/null; then
        if [[ -n "$RESTART_CMD" ]]; then
            if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                "${SSH_USER}@${host}" "$RESTART_CMD" 2>/dev/null; then
                echo -e "${GREEN}OK + restarted${NC}"
            else
                echo -e "${YELLOW}OK (restart failed)${NC}"
            fi
        else
            echo -e "${GREEN}OK${NC}"
        fi
        ((SUCCESS++))
    else
        echo -e "${RED}FAIL${NC}"
        ((FAIL++))
    fi
done

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Done: ${GREEN}$SUCCESS OK${NC}, ${RED}$FAIL FAIL${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
