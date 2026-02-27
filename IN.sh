#!/bin/bash
# IN.sh - Iranian server setup script (nftables version)
# Routes source-range traffic through the tunnel, with bypass for configurable IPs
# Uses mark-based routing — works with WireGuard, OpenVPN, IKEv2 (XFRM), V2RAY (Xray), etc.
#
# All rules are added to the 'inet vrtunnel' nft table (created by setup.sh).
# No iptables commands — pure nftables.

set -u

# ============================================
# CONFIGURATION - Add your source ranges here
# (e.g. WireGuard, LAN, IKEv2, MikroTik clients)
# ============================================
SOURCE_RANGES=(
    "10.99.99.2"
    "10.1.0.0/16"
    "10.2.0.0/16"
    "10.3.0.0/16"
    "10.4.0.0/16"
    "10.5.0.0/16"
    "10.6.0.0/16"
)

TUNNEL_DEV="vrtun0"
TUNNEL_GATEWAY="10.99.99.1"
TABLE_ID="100"
TABLE_NAME="tunnel"
CHECK_INTERVAL=5

# Mark-based routing: source traffic → tunnel, bypass traffic → direct
SOURCE_FWMARK="0x2"
SOURCE_RULE_PRIO="50"

# Bypass configuration
BYPASS_CACHE_DIR="/var/cache/vrtunnel"
BYPASS_CACHE_FILE="${BYPASS_CACHE_DIR}/bypass-cidrs.txt"
BYPASS_URL="https://ip.vroute.org/bypass.csv"
BYPASS_FWMARK="0x1"
BYPASS_RULE_PRIO="99"

# Internal state
ENABLE_BYPASS=0
BYPASS_LAST_LOAD=0
NFT_TABLE="inet vrtunnel"

# ============================================
# Initial Setup (runs once - persistent configs)
# ============================================
setup_once() {
    echo "[*] Running initial setup..."

    # Make forwarding permanent (if not already set)
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        echo "[+] Made IP forwarding permanent in sysctl.conf"
    fi

    # Create routing table (if not exists)
    if ! grep -q "^${TABLE_ID} ${TABLE_NAME}" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "${TABLE_ID} ${TABLE_NAME}" >> /etc/iproute2/rt_tables
        echo "[+] Created routing table ${TABLE_NAME}"
    fi

    # Fix DNS: point to public resolvers (bypasses systemd-resolved + ISP poisoning)
    # The output_mangle nft rules mark DNS traffic with fwmark 0x2 → goes through tunnel
    if grep -q "127.0.0.53" /etc/resolv.conf 2>/dev/null; then
        # Disable systemd-resolved stub and use direct resolvers
        systemctl disable --now systemd-resolved &>/dev/null || true
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf << 'DNSEOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
DNSEOF
        echo "[+] Fixed resolv.conf → 1.1.1.1 / 8.8.8.8 (DNS goes through tunnel via nft)"
    fi

    # Install bypass prerequisites if bypass is enabled
    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        if ! command -v curl &>/dev/null; then
            echo "[*] Installing curl..."
            apt-get update -qq && apt-get install -y -qq curl || {
                echo "[!] Failed to install curl — bypass feature disabled"
                ENABLE_BYPASS=0
            }
        fi
        mkdir -p "$BYPASS_CACHE_DIR"
    fi

    echo "[*] Initial setup complete"
}

# ============================================
# nftables setup — add routing rules to inet vrtunnel table
# ============================================
setup_nft_rules() {
    # Ensure table exists (idempotent — setup.sh may have already created it)
    nft add table $NFT_TABLE 2>/dev/null

    # --- Prerouting: mark source traffic for policy routing ---
    # Priority mangle (-150) so marks are set before filter chains
    if ! nft list chain $NFT_TABLE prerouting &>/dev/null; then
        nft add chain $NFT_TABLE prerouting \
            '{ type filter hook prerouting priority mangle; policy accept; }'

        for subnet in "${SOURCE_RANGES[@]}"; do
            nft add rule $NFT_TABLE prerouting ip saddr "$subnet" counter meta mark set $SOURCE_FWMARK
        done
        echo "[+] Added source mark rules for ${#SOURCE_RANGES[@]} ranges"
    fi

    # --- Bypass set (only if bypass enabled) ---
    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        if ! nft list set $NFT_TABLE bypass &>/dev/null; then
            nft add set $NFT_TABLE bypass '{ type ipv4_addr; flags interval; auto-merge; }'
            # Bypass rule: override source mark (0x2 → 0x1) for bypass destinations
            # Appended AFTER source marks so it runs last
            nft add rule $NFT_TABLE prerouting ip daddr @bypass counter meta mark set $BYPASS_FWMARK
            echo "[+] Created bypass set and mark rule"
        fi
    fi

    # --- Output mangle chain (always created when tunnel exists) ---
    # Two purposes:
    #   1. DNS tunneling: mark ALL outgoing DNS (UDP+TCP 53) with fwmark 0x2 → tunnel
    #      Prevents ISP DNS poisoning for locally generated queries (V2RAY/Xray, system)
    #   2. Bypass for locally generated packets (V2RAY/Xray):
    #      Xray uses sockopt.mark=2 → packets go through OUTPUT, not PREROUTING.
    #      Override mark 0x2 → 0x1 for bypass destinations.
    if ! nft list chain $NFT_TABLE output_mangle &>/dev/null; then
        nft add chain $NFT_TABLE output_mangle \
            '{ type route hook output priority mangle; policy accept; }'
        echo "[+] Created output_mangle chain"
    fi

    # DNS tunneling — force all locally generated DNS through tunnel
    if ! nft list chain $NFT_TABLE output_mangle 2>/dev/null | grep -q "dport 53"; then
        nft add rule $NFT_TABLE output_mangle udp dport 53 counter meta mark set 0x00000002
        nft add rule $NFT_TABLE output_mangle tcp dport 53 counter meta mark set 0x00000002
        echo "[+] Added DNS tunneling rules (UDP+TCP 53 → fwmark 0x2)"
    fi

    # Bypass for locally generated packets (only if bypass enabled)
    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        if ! nft list chain $NFT_TABLE output_mangle 2>/dev/null | grep -q "@bypass"; then
            nft add rule $NFT_TABLE output_mangle \
                meta mark 0x00000002 ip daddr @bypass counter meta mark set 0x00000001
            echo "[+] Added output_mangle bypass rule for V2RAY/Xray"
        fi
    fi

    # RST drop: handled by setup.sh (both client and server get it)

    # --- NAT: masquerade tunnel traffic ---
    if ! nft list chain $NFT_TABLE postrouting &>/dev/null; then
        nft add chain $NFT_TABLE postrouting \
            '{ type nat hook postrouting priority srcnat; policy accept; }'
    fi
    if ! nft list chain $NFT_TABLE postrouting 2>/dev/null | grep -q "$TUNNEL_DEV"; then
        nft add rule $NFT_TABLE postrouting oifname "$TUNNEL_DEV" counter masquerade
        echo "[+] Added NAT masquerade for $TUNNEL_DEV"
    fi

    # --- NAT: masquerade bypass traffic on physical interface ---
    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        local phys_dev
        phys_dev=$(ip route show default | awk '/default/ {print $5; exit}')
        if [[ -n "$phys_dev" ]]; then
            if ! nft list chain $NFT_TABLE postrouting 2>/dev/null | grep -q "@bypass"; then
                nft add rule $NFT_TABLE postrouting oifname "$phys_dev" ip daddr @bypass counter masquerade
                echo "[+] Added bypass NAT masquerade on $phys_dev"
            fi
        fi
    fi

    # --- Per-interface forward accept rules ---
    for iface in tun0 tun1 wg0; do
        if ip link show "$iface" &>/dev/null; then
            if ! nft list chain $NFT_TABLE forward 2>/dev/null | grep -q "\"$iface\""; then
                nft add rule $NFT_TABLE forward oifname "$iface" counter accept
                nft add rule $NFT_TABLE forward iifname "$iface" counter accept
            fi
        fi
    done
    # Accept vpns* wildcard
    if ! nft list chain $NFT_TABLE forward 2>/dev/null | grep -q "vpns"; then
        nft add rule $NFT_TABLE forward iifname "vpns*" counter accept 2>/dev/null
        nft add rule $NFT_TABLE forward oifname "vpns*" counter accept 2>/dev/null
    fi
}

# ============================================
# Bypass functions
# ============================================

# Download bypass list using HTTP conditional requests.
update_bypass_cache() {
    local tmp_file="${BYPASS_CACHE_DIR}/bypass-download.tmp"
    local http_code

    local curl_args=(-sS -L --max-time 10 -o "$tmp_file" -w "%{http_code}" "$BYPASS_URL")
    if [[ -f "$BYPASS_CACHE_FILE" ]]; then
        curl_args=(-sS -L --max-time 10 -z "$BYPASS_CACHE_FILE" -o "$tmp_file" -w "%{http_code}" "$BYPASS_URL")
    fi

    local curl_err
    curl_err=$(mktemp)
    http_code=$(curl "${curl_args[@]}" 2>"$curl_err") || {
        echo "[!] Bypass download failed: $(cat "$curl_err")"
        rm -f "$tmp_file" "$curl_err"
        return 1
    }
    rm -f "$curl_err"

    if [[ "$http_code" == "304" ]]; then
        rm -f "$tmp_file"
        return 1
    fi

    if [[ "$http_code" != "200" ]]; then
        echo "[!] Bypass download returned HTTP $http_code"
        rm -f "$tmp_file"
        return 1
    fi

    # Extract CIDRs: skip header, take column 1
    local cidr_file="${BYPASS_CACHE_DIR}/bypass-cidrs.tmp"
    tail -n +2 "$tmp_file" | cut -d',' -f1 > "$cidr_file"
    rm -f "$tmp_file"

    local count
    count=$(wc -l < "$cidr_file")
    if [[ $count -lt 10 ]]; then
        echo "[!] Bypass list too small ($count entries), rejecting"
        rm -f "$cidr_file"
        return 1
    fi

    mv -f "$cidr_file" "$BYPASS_CACHE_FILE"
    echo "[+] Bypass list updated: $count CIDRs"
    return 0
}

# Reload bypass CIDRs into nft set (atomic flush + add)
setup_bypass_set() {
    [[ -f "$BYPASS_CACHE_FILE" ]] || return

    local file_mtime
    file_mtime=$(stat -c %Y "$BYPASS_CACHE_FILE" 2>/dev/null) || return
    if [[ $file_mtime -le $BYPASS_LAST_LOAD ]]; then
        return
    fi

    # Build nft commands: flush then add all elements
    local nft_cmds="flush set $NFT_TABLE bypass"$'\n'
    local batch=""
    while IFS= read -r cidr; do
        [[ -n "$cidr" ]] || continue
        batch="${batch}${batch:+, }${cidr}"
    done < "$BYPASS_CACHE_FILE"

    if [[ -n "$batch" ]]; then
        nft_cmds+="add element $NFT_TABLE bypass { ${batch} }"
        if echo "$nft_cmds" | nft -f - 2>/dev/null; then
            BYPASS_LAST_LOAD=$file_mtime
            local count
            count=$(wc -l < "$BYPASS_CACHE_FILE")
            echo "[+] Bypass nft set reloaded: $count entries"
        else
            echo "[!] Failed to reload bypass nft set"
        fi
    fi
}

# Main bypass orchestrator
check_bypass() {
    [[ $ENABLE_BYPASS -eq 1 ]] || return
    update_bypass_cache
    setup_bypass_set
}

# ============================================
# Check routing rules (runs every CHECK_INTERVAL)
# ============================================
check_rules() {
    local changes=0

    # Check IP forwarding
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) != "1" ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "[+] Enabled IP forwarding"
        changes=1
    fi

    # Check default route through tunnel
    if ! ip route show table ${TABLE_ID} 2>/dev/null | grep -q "default via ${TUNNEL_GATEWAY}"; then
        if ip route add default via ${TUNNEL_GATEWAY} dev ${TUNNEL_DEV} table ${TABLE_ID} 2>/dev/null; then
            echo "[+] Added default route through tunnel"
            changes=1
        else
            echo "[!] Failed to add default route (${TUNNEL_DEV} may be down)"
            return
        fi
    fi

    # Check ip rule: fwmark 0x2 → tunnel table
    if ! ip rule show | grep -q "fwmark ${SOURCE_FWMARK} lookup ${TABLE_NAME}"; then
        ip rule add fwmark "$SOURCE_FWMARK" table "$TABLE_ID" priority "$SOURCE_RULE_PRIO"
        echo "[+] Added source routing rule (fwmark ${SOURCE_FWMARK} → ${TABLE_NAME}, prio ${SOURCE_RULE_PRIO})"
        changes=1
    fi

    # Check ip rule: fwmark 0x1 → main table (bypass)
    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        if ! ip rule show | grep -q "fwmark ${BYPASS_FWMARK} lookup main"; then
            ip rule add fwmark "$BYPASS_FWMARK" table main priority "$BYPASS_RULE_PRIO"
            echo "[+] Added bypass ip rule (fwmark ${BYPASS_FWMARK} → main, prio ${BYPASS_RULE_PRIO})"
            changes=1
        fi
    fi

    # Check output_mangle chain (DNS tunneling + V2RAY bypass) — self-heal
    if ! nft list chain $NFT_TABLE output_mangle &>/dev/null; then
        echo "[!] output_mangle chain missing, re-creating..."
        nft add chain $NFT_TABLE output_mangle \
            '{ type route hook output priority mangle; policy accept; }'
        nft add rule $NFT_TABLE output_mangle udp dport 53 counter meta mark set 0x00000002
        nft add rule $NFT_TABLE output_mangle tcp dport 53 counter meta mark set 0x00000002
        if [[ $ENABLE_BYPASS -eq 1 ]]; then
            nft add rule $NFT_TABLE output_mangle \
                meta mark 0x00000002 ip daddr @bypass counter meta mark set 0x00000001
        fi
        echo "[+] Re-created output_mangle chain (DNS tunnel + bypass)"
        changes=1
    fi

    # Check nft table/chains still exist (re-create if setup.sh was re-run)
    if ! nft list chain $NFT_TABLE prerouting &>/dev/null; then
        echo "[!] nft rules missing, re-creating..."
        setup_nft_rules
        changes=1
    fi

    if [[ $changes -eq 0 ]]; then
        echo -ne "\r[✓] All rules OK - $(date '+%H:%M:%S')    "
    fi
}

# ============================================
# Show current status
# ============================================
show_status() {
    echo ""
    echo "=== Current Status ==="
    echo "Tunnel interface: $(ip link show ${TUNNEL_DEV} 2>/dev/null && echo 'UP' || echo 'DOWN')"
    echo "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo ""
    echo "Routing table ${TABLE_NAME}:"
    ip route show table ${TABLE_ID} 2>/dev/null || echo "  (empty)"
    echo ""
    echo "Policy rules:"
    ip rule show | grep -E "fwmark|${TABLE_NAME}" || echo "  (none)"
    echo ""
    echo "nftables (vrtunnel table):"
    nft list table $NFT_TABLE 2>/dev/null | head -40 || echo "  (not created yet)"
    echo ""
    echo "DNS resolver: $(grep -v '^#' /etc/resolv.conf 2>/dev/null | grep nameserver | head -1 || echo 'unknown')"
    if nft list chain $NFT_TABLE output_mangle 2>/dev/null | grep -q "dport 53"; then
        echo "DNS tunneling: active (UDP+TCP 53 → fwmark 0x2)"
    else
        echo "DNS tunneling: not set"
    fi
    echo ""

    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        echo "=== Bypass Status ==="
        local entry_count
        entry_count=$(nft list set $NFT_TABLE bypass 2>/dev/null | grep -c "^[[:space:]]" || echo 0)
        echo "Bypass nft set: ~$entry_count entries"
        if ip rule show | grep -q "fwmark ${BYPASS_FWMARK}"; then
            echo "Bypass fwmark rule: active (prio ${BYPASS_RULE_PRIO})"
        else
            echo "Bypass fwmark rule: not set"
        fi
        if nft list chain $NFT_TABLE output_mangle &>/dev/null; then
            echo "Output mangle (V2RAY): active"
        else
            echo "Output mangle (V2RAY): not set"
        fi
        if [[ -f "$BYPASS_CACHE_FILE" ]]; then
            echo "Bypass cache: $(wc -l < "$BYPASS_CACHE_FILE") CIDRs ($(stat -c '%y' "$BYPASS_CACHE_FILE" 2>/dev/null | cut -d. -f1))"
        else
            echo "Bypass cache: not downloaded yet"
        fi
        echo ""
    fi
}

# ============================================
# One-time migration: remove old iptables rules
# ============================================
cleanup_iptables() {
    local cleaned=0

    # Remove old iptables mangle marks
    for subnet in "${SOURCE_RANGES[@]}"; do
        iptables -t mangle -D PREROUTING -s "$subnet" -j MARK --set-mark "$SOURCE_FWMARK" 2>/dev/null && cleaned=1
    done

    # Remove old iptables RST drops
    iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null && cleaned=1
    iptables -D FORWARD -p tcp --tcp-flags RST RST -j DROP 2>/dev/null && cleaned=1

    # Remove old iptables NAT
    iptables -t nat -D POSTROUTING -o "$TUNNEL_DEV" -j MASQUERADE 2>/dev/null && cleaned=1

    # Remove old MSS clamp (now in setup.sh nft table)
    iptables -t mangle -D FORWARD -o "$TUNNEL_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1260 2>/dev/null && cleaned=1
    iptables -t mangle -D FORWARD -i "$TUNNEL_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1260 2>/dev/null && cleaned=1

    # Remove old bypass ipset match
    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        iptables -t mangle -D PREROUTING -m set --match-set bypass dst -j MARK --set-mark "$BYPASS_FWMARK" 2>/dev/null && cleaned=1
        local phys_dev
        phys_dev=$(ip route show default | awk '/default/ {print $5; exit}')
        iptables -t nat -D POSTROUTING -o "$phys_dev" -m set --match-set bypass dst -j MASQUERADE 2>/dev/null && cleaned=1
    fi

    # Remove old forward accept rules
    iptables -D FORWARD -j ACCEPT 2>/dev/null && cleaned=1

    # Destroy old ipset (replaced by nft set)
    ipset destroy bypass 2>/dev/null && cleaned=1

    if [[ $cleaned -eq 1 ]]; then
        echo "[+] Cleaned up old iptables/ipset rules (migrated to nftables)"
    fi
}

# ============================================
# Main loop
# ============================================
main() {
    if [[ $EUID -ne 0 ]]; then
        echo "[-] This script must be run as root"
        exit 1
    fi

    for arg in "$@"; do
        case "$arg" in
            --bypass) ENABLE_BYPASS=1 ;;
        esac
    done

    # Wait for tunnel interface to appear
    if ! ip link show ${TUNNEL_DEV} &>/dev/null; then
        echo "[*] Waiting for ${TUNNEL_DEV} to appear..."
        while ! ip link show ${TUNNEL_DEV} &>/dev/null; do
            sleep 1
        done
        echo "[+] ${TUNNEL_DEV} is up"
    fi

    setup_once

    # Migrate: remove old iptables rules
    cleanup_iptables

    # Create nft rules
    setup_nft_rules

    show_status

    # Initial bypass setup
    check_bypass

    echo "[*] Starting rule monitor (checking every ${CHECK_INTERVAL}s)..."
    if [[ $ENABLE_BYPASS -eq 1 ]]; then
        echo "[*] Monitoring ${#SOURCE_RANGES[@]} source range(s) via mark-based routing + tunnel bypass (nftables)"
    else
        echo "[*] Monitoring ${#SOURCE_RANGES[@]} source range(s) via mark-based routing (nftables, bypass disabled, use --bypass to enable)"
    fi
    echo "[*] Press Ctrl+C to stop"
    echo ""

    while true; do
        if ! ip link show ${TUNNEL_DEV} &>/dev/null; then
            echo ""
            echo "[!] ${TUNNEL_DEV} disappeared, waiting for it to come back..."
            while ! ip link show ${TUNNEL_DEV} &>/dev/null; do
                sleep 1
            done
            echo "[+] ${TUNNEL_DEV} is back"
            setup_nft_rules
        fi
        check_rules
        check_bypass
        sleep ${CHECK_INTERVAL}
    done
}

main "$@"