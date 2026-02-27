#!/bin/bash
###############################################################################
#  VRoute IKEv2 Deploy
#
#  Usage:  bash ikev2.sh
#
#  Installs and configures:
#    - strongSwan IKEv2 (10.4.0.0/16, ports 500+4500/UDP)
#    - Let's Encrypt RSA certificate (auto-renewed)
#    - EAP-RADIUS authentication (same RADIUS as OpenVPN)
#    - NAT + forwarding rules
#    - ikev2_online.py monitoring script
#    - Updates vroute.conf with IKEV2 server_id
#
#  Requires: deploy.sh must be run first (/opt/vroute.conf must exist)
#  Safe to re-run: skips completed steps.
###############################################################################

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
fatal() { echo -e "${RED}[FATAL]${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}━━━ STEP $1: $2 ━━━${NC}"; }

[[ $EUID -ne 0 ]] && fatal "Run as root"

# ── Prereqs ──
[[ ! -f /opt/vroute.conf ]] && fatal "/opt/vroute.conf not found. Run deploy.sh first."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
[[ -z "$IFACE" ]] && fatal "Cannot detect default network interface"

SERVER_NAME=$(python3 -c "import json; print(json.load(open('/opt/vroute.conf'))['server_name'])")
info "Server: $SERVER_NAME | Interface: $IFACE"

ERRORS=0

###############################################################################
#  STEP 1: Domain + IKEv2 server_id
###############################################################################
step 1 "IKEv2 configuration"

# Check if IKEV2 already configured in vroute.conf
IKEV2_ID=$(python3 -c "
import json
c = json.load(open('/opt/vroute.conf'))
print(c.get('server_ids', {}).get('IKEV2', ''))
" 2>/dev/null || true)

IKEV2_DOMAIN=$(python3 -c "
import json
c = json.load(open('/opt/vroute.conf'))
print(c.get('ikev2_domain', ''))
" 2>/dev/null || true)

if [[ -n "$IKEV2_ID" && -n "$IKEV2_DOMAIN" ]]; then
    info "IKEv2 already configured: id=$IKEV2_ID domain=$IKEV2_DOMAIN"
    read -rp "Re-configure? [y/N]: " RECONF
    if [[ "$RECONF" != "y" && "$RECONF" != "Y" ]]; then
        info "Keeping existing config."
    else
        IKEV2_ID=""
        IKEV2_DOMAIN=""
    fi
fi

if [[ -z "$IKEV2_ID" || -z "$IKEV2_DOMAIN" ]]; then
    echo ""
    read -rp "Domain for this server (e.g. vs14.vroute.org): " IKEV2_DOMAIN
    [[ -z "$IKEV2_DOMAIN" ]] && fatal "Domain cannot be empty"

    # Auto-generate ID
    SERVER_NUM=$(echo "$SERVER_NAME" | grep -oP '\d+$' || true)
    if [[ -n "$SERVER_NUM" ]]; then
        DEFAULT_IKEV2=$((700 + SERVER_NUM - 2))
        echo "  Auto-generated IKEv2 server_id: $DEFAULT_IKEV2"
        read -rp "Use this ID? [Y/n]: " USE_DEFAULT
        if [[ "$USE_DEFAULT" == "n" || "$USE_DEFAULT" == "N" ]]; then
            read -rp "  IKEv2 server_id: " IKEV2_ID
        else
            IKEV2_ID=$DEFAULT_IKEV2
        fi
    else
        read -rp "  IKEv2 server_id: " IKEV2_ID
    fi

    [[ -z "$IKEV2_ID" ]] && fatal "Server ID cannot be empty"

    # Update vroute.conf — add IKEV2 server_id and domain
    python3 << PYEOF
import json

with open("/opt/vroute.conf") as f:
    c = json.load(f)

c["server_ids"]["IKEV2"] = $IKEV2_ID
c["ikev2_domain"] = "$IKEV2_DOMAIN"

with open("/opt/vroute.conf", "w") as f:
    json.dump(c, f, indent=4)

print("Updated /opt/vroute.conf")
PYEOF

    info "Config updated: IKEV2 id=$IKEV2_ID, domain=$IKEV2_DOMAIN"
fi

###############################################################################
#  STEP 2: Install packages
###############################################################################
step 2 "Packages"

NEED_INSTALL=0
for pkg in strongswan strongswan-pki strongswan-swanctl charon-systemd libcharon-extra-plugins certbot; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        NEED_INSTALL=1
        break
    fi
done

if [[ $NEED_INSTALL -eq 1 ]]; then
    info "Installing strongSwan + certbot..."
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    apt update -qq
    apt install -y strongswan strongswan-pki strongswan-swanctl charon-systemd libcharon-extra-plugins certbot || {
        error "Package install failed"; ((ERRORS++))
    }
else
    info "All packages already installed."
fi

# charon-systemd provides the vici plugin (needed by swanctl / ikev2_online.py),
# but it also creates a competing strongswan.service.
# We use strongswan-starter (stroke/ipsec.conf), so disable the systemd one.
if systemctl is-enabled strongswan.service &>/dev/null 2>&1; then
    systemctl stop strongswan.service &>/dev/null 2>&1 || true
    systemctl disable strongswan.service &>/dev/null 2>&1 || true
    systemctl mask strongswan.service &>/dev/null 2>&1 || true
    info "Disabled competing strongswan.service (using strongswan-starter instead)."
fi

###############################################################################
#  STEP 3: Let's Encrypt certificate (RSA)
###############################################################################
step 3 "Let's Encrypt certificate"

CERT_DIR="/etc/letsencrypt/live/$IKEV2_DOMAIN"

if [[ -d "$CERT_DIR" ]]; then
    # Check if cert is RSA
    KEY_TYPE=$(openssl pkey -in "$CERT_DIR/privkey.pem" -noout -text 2>/dev/null | head -1 || true)
    if echo "$KEY_TYPE" | grep -qi "RSA"; then
        info "RSA certificate already exists for $IKEV2_DOMAIN"
    else
        warn "Existing cert is not RSA. Renewing as RSA..."
        certbot certonly --standalone -d "$IKEV2_DOMAIN" \
            --key-type rsa --rsa-key-size 2048 --force-renewal \
            --non-interactive --agree-tos --register-unsafely-without-email || {
            error "Certbot failed"; ((ERRORS++))
        }
    fi
else
    info "Requesting Let's Encrypt RSA certificate for $IKEV2_DOMAIN..."
    info "NOTE: Port 80 must be free for HTTP validation."

    certbot certonly --standalone -d "$IKEV2_DOMAIN" \
        --key-type rsa --rsa-key-size 2048 \
        --non-interactive --agree-tos --register-unsafely-without-email || {
        error "Certbot failed — ensure DNS A record points to this server and port 80 is free"
        ((ERRORS++))
    }
fi

###############################################################################
#  STEP 4: Install certs for strongSwan
###############################################################################
step 4 "strongSwan certificates"

mkdir -p /etc/ipsec.d/certs /etc/ipsec.d/private /etc/ipsec.d/cacerts

# Server cert (extract first cert only from fullchain)
if [[ -f "$CERT_DIR/fullchain.pem" ]]; then
    openssl x509 -in "$CERT_DIR/fullchain.pem" -out /etc/ipsec.d/certs/server.crt 2>/dev/null
    info "Server cert installed."
else
    error "fullchain.pem not found!"; ((ERRORS++))
fi

# Private key (convert to RSA format strongSwan understands)
if [[ -f "$CERT_DIR/privkey.pem" ]]; then
    openssl rsa -in "$CERT_DIR/privkey.pem" -out /etc/ipsec.d/private/server.pem 2>/dev/null
    chmod 600 /etc/ipsec.d/private/server.pem
    info "Private key installed."
else
    error "privkey.pem not found!"; ((ERRORS++))
fi

# CA chain
if [[ -f "$CERT_DIR/chain.pem" ]]; then
    cp "$CERT_DIR/chain.pem" /etc/ipsec.d/cacerts/lets-encrypt-chain.pem
    info "CA chain installed."
else
    error "chain.pem not found!"; ((ERRORS++))
fi

###############################################################################
#  STEP 5: strongSwan configuration
###############################################################################
step 5 "strongSwan configuration"

# ipsec.conf
cat > /etc/ipsec.conf << IPSECEOF
config setup
    uniqueids=never
    strictcrlpolicy=no

conn %default
    keyexchange=ikev2

conn ikev2
    auto=add
    type=tunnel
    compress=no
    fragmentation=yes
    forceencaps=yes

    # Server side
    left=%any
    leftid=@$IKEV2_DOMAIN
    leftcert=server.crt
    leftsubnet=0.0.0.0/0
    leftsendcert=always

    # Client side
    right=%any
    rightid=%any
    rightsourceip=10.4.0.0/16
    rightdns=8.8.8.8,8.8.4.4

    # Auth
    leftauth=pubkey
    rightauth=eap-radius
    eap_identity=%identity

    # Ciphers — GCM first for speed (AES-NI hw accel), CBC fallback for old clients
    ike=aes256gcm16-sha384-ecp384,aes256gcm16-sha256-ecp256,aes256gcm16-sha256-modp2048,aes128gcm16-sha256-ecp256,aes128gcm16-sha256-modp2048,aes256-sha256-ecp256,aes256-sha384-ecp384,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha256-modp1024,aes128-sha1-modp1024!
    esp=aes256gcm16,aes128gcm16,aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1!

    # Timers
    dpdaction=clear
    dpddelay=300s
    rekey=no
    ikelifetime=24h
    lifetime=24h
IPSECEOF
info "ipsec.conf written."

# ipsec.secrets
echo ": RSA /etc/ipsec.d/private/server.pem" > /etc/ipsec.secrets
info "ipsec.secrets written."

# EAP-RADIUS plugin
cat > /etc/strongswan.d/charon/eap-radius.conf << 'RADEOF'
eap-radius {
    load = yes
    servers {
        primary {
            address = 185.141.168.2
            port = 1812
            secret = 11041104
        }
    }
}
RADEOF
info "EAP-RADIUS config written."

# Suppress charon debug logging (fills journal with noise)
cat > /etc/strongswan.d/charon-logging.conf << 'LOGEOF'
charon {
    syslog {
        daemon {
            default = -1
        }
        auth {
            default = -1
        }
    }
    filelog {
    }
}
LOGEOF
info "Charon logging suppressed (default = -1)."

###############################################################################
#  STEP 6: Certificate auto-renewal hook
###############################################################################
step 6 "Certificate renewal hook"

mkdir -p /etc/letsencrypt/renewal-hooks/deploy

cat > /etc/letsencrypt/renewal-hooks/deploy/strongswan.sh << 'HOOKEOF'
#!/bin/bash
# Reload strongSwan certs after Let's Encrypt renewal

DOMAIN=$(basename "$RENEWED_LINEAGE")
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

if [[ -f "$CERT_DIR/fullchain.pem" ]]; then
    openssl x509 -in "$CERT_DIR/fullchain.pem" -out /etc/ipsec.d/certs/server.crt 2>/dev/null
    openssl rsa -in "$CERT_DIR/privkey.pem" -out /etc/ipsec.d/private/server.pem 2>/dev/null
    chmod 600 /etc/ipsec.d/private/server.pem
    cp "$CERT_DIR/chain.pem" /etc/ipsec.d/cacerts/lets-encrypt-chain.pem

    ipsec reload 2>/dev/null || true
    echo "[strongswan-hook] Certificates reloaded for $DOMAIN"
fi
HOOKEOF

chmod +x /etc/letsencrypt/renewal-hooks/deploy/strongswan.sh
info "Renewal hook installed — strongSwan will auto-reload on cert renewal."

###############################################################################
#  STEP 7: IP forwarding + NAT
###############################################################################
step 7 "Networking (forwarding + NAT)"

# Ensure IP forwarding
if [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    info "IP forwarding enabled."
else
    info "IP forwarding already enabled."
fi

# NOTE: Mark-based tunnel routing (fwmark 0x2 → tunnel table) is handled by IN.sh.
# Make sure 10.4.0.0/16 is in SOURCE_RANGES in IN.sh.
# IKEv2 uses XFRM (no virtual interface like wg0/tun0), so mark-based routing
# is required instead of source-based ip rules.

# Allow IPsec ports
for port in 500 4500; do
    if ! iptables -C INPUT -p udp --dport "$port" -j ACCEPT &>/dev/null; then
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        info "Opened UDP port $port"
    fi
done

netfilter-persistent save &>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null
info "Firewall rules saved."

###############################################################################
#  STEP 8: Deploy monitoring script
###############################################################################
step 8 "IKEv2 monitoring script"

if [[ -f "$SCRIPT_DIR/ikev2_online.py" ]]; then
    cp "$SCRIPT_DIR/ikev2_online.py" /opt/ikev2_online.py
    chmod +x /opt/ikev2_online.py
    info "Installed /opt/ikev2_online.py"
else
    warn "ikev2_online.py not found in package — skipping."
fi

###############################################################################
#  STEP 9: Start strongSwan
###############################################################################
step 9 "Start strongSwan"

# Disable local FreeRADIUS if it got installed (we use remote RADIUS)
if systemctl is-active --quiet freeradius 2>/dev/null; then
    systemctl stop freeradius
    systemctl disable freeradius
    info "Disabled local FreeRADIUS (using remote RADIUS)."
fi

systemctl enable strongswan-starter &>/dev/null
ipsec restart || { error "strongSwan failed to start"; ((ERRORS++)); }

# Verify (retry up to 5 seconds for strongSwan to fully load)
for i in 1 2 3 4 5; do
    sleep 1
    CONN_COUNT=$(ipsec statusall 2>/dev/null | grep -c "ikev2:" || true)
    [[ "$CONN_COUNT" -ge 1 ]] && break
done
if [[ "$CONN_COUNT" -ge 1 ]]; then
    info "strongSwan running — ikev2 connection loaded."
else
    warn "strongSwan started but ikev2 connection not loaded. Check: ipsec statusall"
fi

###############################################################################
#  DONE
###############################################################################
echo ""
echo "============================================================"
if [[ $ERRORS -eq 0 ]]; then
    info "IKEv2 deploy complete! (0 errors)"
else
    warn "IKEv2 deploy complete with $ERRORS error(s)"
fi
echo "============================================================"
echo ""
echo "  Server:        $SERVER_NAME"
echo "  Domain:        $IKEV2_DOMAIN"
echo "  IKEv2:         10.4.0.0/16 — ports 500+4500/UDP"
echo "  RADIUS:        185.141.168.2:1812"
echo "  Certificate:   Let's Encrypt RSA (auto-renews)"
echo "  Interface:     $IFACE"
echo ""
echo "  Client setup (iPhone / macOS):"
echo "    Type:        IKEv2"
echo "    Server:      $IKEV2_DOMAIN"
echo "    Remote ID:   $IKEV2_DOMAIN"
echo "    Local ID:    (leave empty)"
echo "    Auth:        Username + Password"
echo ""
echo "  Client setup (Android built-in):"
echo "    Type:            IKEv2/IPSec MSCHAPv2"
echo "    Server:          $IKEV2_DOMAIN"
echo "    Username:        <username>"
echo "    Password:        <password>"
echo "    IPSec identifier: <username>  *** MUST match username! ***"
echo "    IPSec pre-shared key: (leave empty)"
echo ""
echo "  Client setup (Windows 10/11):"
echo "    Type:        IKEv2"
echo "    Server:      $IKEV2_DOMAIN"
echo "    Auth:        Username + Password"
echo ""
echo "  Client setup (Android strongSwan app):"
echo "    Type:        IKEv2 EAP (Username/Password)"
echo "    Server:      $IKEV2_DOMAIN"
echo "    Username:    <username>"
echo "    CA cert:     Select automatically"
echo ""
echo "  Monitoring:"
echo "    python3 /opt/ikev2_online.py              # IKEv2 online users"
echo "    python3 /opt/ikev2_online.py -s username   # Sort by username"
echo "    ipsec statusall                            # Full SA details"
echo "    swanctl --list-sas                         # Active sessions"
echo ""
echo "  Logs:"
echo "    journalctl -u strongswan-starter -f        # strongSwan log"
echo "    journalctl -f | grep charon                # Detailed IKE log"
echo ""
echo "  Certificate renewal:"
echo "    certbot renew --dry-run                    # Test renewal"
echo "    # Auto-renewal via systemd timer (certbot)"
echo "    # strongSwan reloads automatically via deploy hook"
echo "============================================================"
