#!/bin/bash
###############################################################################
#  VRoute Server Deploy — All-in-One
#
#  Usage:  bash deploy.sh
#
#  Installs and configures:
#    - WireGuard    (wg0,  10.1.0.0/16,  port 11040/UDP)
#    - OpenVPN TCP  (tun0, 10.2.0.0/16,  port 11041/TCP) + RADIUS
#    - OpenVPN UDP  (tun1, 10.3.0.0/16,  port 11041/UDP) + RADIUS
#    - IKEv2        (xfrm, 10.4.0.0/16,  ports 500+4500/UDP) + EAP-RADIUS
#    - ocserv       (vpns, 10.5.0.0/16,  port 443 TCP+UDP/DTLS) + RADIUS
#    - L2TP/IPsec   (ppp,  10.6.0.0/24,  port 1701/UDP) + RADIUS
#    - V2RAY/VLESS  (xray, proxy,        port 11042/TCP) + MySQL UUID auth
#    - Monitoring scripts + sync-online service
#    - WG peer sync + V2RAY user sync services
#    - IP forwarding + NAT
#
#  Safe to re-run: skips completed steps, regenerates config if needed.
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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
[[ -z "$IFACE" ]] && fatal "Cannot detect default network interface"
info "Network interface: $IFACE"

# ── Hardcoded defaults ──
IPSEC_PSK="123456789"
RADIUS_IP="185.141.168.2"
RADIUS_AUTH_PORT=1812
RADIUS_ACCT_PORT=1813
RADIUS_SECRET="11041104"
L2TP_LOCAL_IP="10.6.0.1"
L2TP_POOL_START="10.6.0.10"
L2TP_POOL_END="10.6.0.254"
L2TP_SUBNET="10.6.0.0/24"
DNS1="8.8.8.8"
DNS2="8.8.4.4"

ERRORS=0

###############################################################################
#  STEP 1: Server config (/opt/vroute.conf)
###############################################################################
step 1 "Server configuration"

if [[ -f /opt/vroute.conf ]]; then
    info "Existing config found:"
    cat /opt/vroute.conf
    echo ""
    read -rp "Re-generate config? [y/N]: " REGEN
    if [[ "$REGEN" != "y" && "$REGEN" != "Y" ]]; then
        info "Keeping existing config."
        SERVER_NAME=$(python3 -c "import json; print(json.load(open('/opt/vroute.conf'))['server_name'])")
        DOMAIN=$(python3 -c "import json; c=json.load(open('/opt/vroute.conf')); print(c.get('ikev2_domain', c.get('ocserv_domain', '')))" 2>/dev/null || true)
        if [[ -z "$DOMAIN" ]]; then
            read -rp "Domain for this server (e.g. vs14.vroute.org): " DOMAIN
            [[ -z "$DOMAIN" ]] && fatal "Domain cannot be empty"
            # Add domain to existing config
            python3 << PYEOF
import json
with open("/opt/vroute.conf") as f:
    c = json.load(f)
c["ikev2_domain"] = "$DOMAIN"
c["ocserv_domain"] = "$DOMAIN"
with open("/opt/vroute.conf", "w") as f:
    json.dump(c, f, indent=4)
PYEOF
        fi
    else
        rm -f /opt/vroute.conf
    fi
fi

if [[ ! -f /opt/vroute.conf ]]; then
    echo ""
    read -rp "Server name (e.g. VS5): " SERVER_NAME
    [[ -z "$SERVER_NAME" ]] && fatal "Server name cannot be empty"

    read -rp "Domain for this server (e.g. vs14.vroute.org): " DOMAIN
    [[ -z "$DOMAIN" ]] && fatal "Domain cannot be empty"

    # Extract number for auto-generating IDs
    SERVER_NUM=$(echo "$SERVER_NAME" | grep -oP '\d+$' || true)
    if [[ -n "$SERVER_NUM" ]]; then
        DEFAULT_WG=$((500 + SERVER_NUM - 2))
        DEFAULT_OVPN=$((600 + SERVER_NUM - 2))
        DEFAULT_OCSERV=$((300 + SERVER_NUM - 2))
        DEFAULT_IKEV2=$((700 + SERVER_NUM - 2))
        DEFAULT_L2TP=$((400 + SERVER_NUM - 2))
        DEFAULT_V2RAY=$((800 + SERVER_NUM - 2))
        echo ""
        echo "  Auto-generated IDs based on $SERVER_NAME:"
        echo "    WIREGUARD = $DEFAULT_WG"
        echo "    OVPN      = $DEFAULT_OVPN"
        echo "    OCSERV    = $DEFAULT_OCSERV"
        echo "    IKEV2     = $DEFAULT_IKEV2"
        echo "    L2TP      = $DEFAULT_L2TP"
        echo "    V2RAY     = $DEFAULT_V2RAY"
        echo ""
        read -rp "Use these IDs? [Y/n]: " USE_DEFAULT
        if [[ "$USE_DEFAULT" == "n" || "$USE_DEFAULT" == "N" ]]; then
            read -rp "  WireGuard server_id: " WG_ID
            read -rp "  OpenVPN server_id:   " OVPN_ID
            read -rp "  ocserv server_id:    " OCSERV_ID
            read -rp "  IKEv2 server_id:     " IKEV2_ID
            read -rp "  L2TP server_id:      " L2TP_ID
            read -rp "  V2RAY server_id:     " V2RAY_ID
        else
            WG_ID=$DEFAULT_WG
            OVPN_ID=$DEFAULT_OVPN
            OCSERV_ID=$DEFAULT_OCSERV
            IKEV2_ID=$DEFAULT_IKEV2
            L2TP_ID=$DEFAULT_L2TP
            V2RAY_ID=$DEFAULT_V2RAY
        fi
    else
        echo ""
        read -rp "  WireGuard server_id: " WG_ID
        read -rp "  OpenVPN server_id:   " OVPN_ID
        read -rp "  ocserv server_id:    " OCSERV_ID
        read -rp "  IKEv2 server_id:     " IKEV2_ID
        read -rp "  L2TP server_id:      " L2TP_ID
        read -rp "  V2RAY server_id:     " V2RAY_ID
    fi

    [[ -z "$WG_ID" || -z "$OVPN_ID" || -z "$OCSERV_ID" || -z "$IKEV2_ID" || -z "$L2TP_ID" || -z "$V2RAY_ID" ]] && fatal "Server IDs cannot be empty"

    cat > /opt/vroute.conf << CONFEOF
{
    "server_name": "$SERVER_NAME",
    "server_ids": {
        "WIREGUARD": $WG_ID,
        "OVPN": $OVPN_ID,
        "OCSERV": $OCSERV_ID,
        "IKEV2": $IKEV2_ID,
        "L2TP": $L2TP_ID,
        "V2RAY": $V2RAY_ID
    },
    "db": {
        "host": "api.vroute.org",
        "port": 3306,
        "name": "vroute",
        "user": "vroute",
        "pass": "Amn.1104.@#\$"
    },
    "wg_interface": "wg0",
    "mgmt_sockets": {
        "TCP": "/run/openvpn-server/tcp-mgmt.sock",
        "UDP": "/run/openvpn-server/udp-mgmt.sock"
    },
    "ocserv_domain": "$DOMAIN",
    "ikev2_domain": "$DOMAIN"
}
CONFEOF

    info "Config written to /opt/vroute.conf"
    echo ""
    cat /opt/vroute.conf
    echo ""
fi

###############################################################################
#  STEP 2: Install packages
###############################################################################
step 2 "Packages"

NEED_INSTALL=0
for pkg in wireguard openvpn openvpn-auth-radius python3 python3-redis python3-mysql.connector \
           strongswan strongswan-pki libcharon-extra-plugins \
           xl2tpd ppp libradcli4 libradcli-dev ocserv certbot; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        NEED_INSTALL=1
        break
    fi
done

if [[ $NEED_INSTALL -eq 1 ]]; then
    info "Installing packages..."
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    apt update -qq
    apt install -y wireguard openvpn libradcli4 libradcli-dev openvpn-auth-radius \
        python3 python3-redis python3-mysql.connector iptables-persistent socat \
        strongswan strongswan-pki strongswan-swanctl charon-systemd libcharon-extra-plugins \
        xl2tpd ppp ocserv certbot || {
        error "Package install failed"; ((ERRORS++))
    }
else
    info "All packages already installed."
fi

###############################################################################
#  STEP 3: WireGuard
###############################################################################
step 3 "WireGuard"

if [[ -f /etc/wireguard/wg0.conf ]]; then
    info "wg0.conf already exists."
else
    cat > /etc/wireguard/wg0.conf << 'WGEOF'
[Interface]
PrivateKey = aEMYlWqihYOMOuB05FzJSHUtApGI7Jq7a3hdR4dwWEQ=
Address = 10.1.0.1/16
ListenPort = 11040
WGEOF
    info "wg0.conf written."
fi

if ip link show wg0 &>/dev/null; then
    info "wg0 already up."
else
    systemctl enable wg-quick@wg0
    wg-quick up wg0 || { error "Failed to bring up wg0"; ((ERRORS++)); }
    info "WireGuard UP on port 11040"
fi

###############################################################################
#  STEP 4: OpenVPN certificates
###############################################################################
step 4 "OpenVPN certificates"

mkdir -p /etc/openvpn/server/certs

cd /etc/openvpn/server/certs

# Copy certificates (always overwrite)
cp "$SCRIPT_DIR/cert_export_cert_export_CA.crt_0.crt" ca.crt
cp "$SCRIPT_DIR/cert_export_cert_export_Server.crt_0.crt" server.crt

# Decrypt encrypted private keys (will prompt for passphrase)
info "Decrypting CA key..."
openssl pkey -in "$SCRIPT_DIR/cert_export_cert_export_CA.crt_0.key" \
    -out ca.key || { error "Failed to decrypt CA key"; ((ERRORS++)); }

info "Decrypting Server key..."
openssl pkey -in "$SCRIPT_DIR/cert_export_cert_export_Server.crt_0.key" \
    -out server.key || { error "Failed to decrypt Server key"; ((ERRORS++)); }

chmod 600 ca.key server.key

# Generate fresh DH parameters
info "Generating DH parameters (2048-bit) — this may take a moment..."
openssl dhparam -out dh2048.pem 2048 || { error "Failed to generate DH params"; ((ERRORS++)); }

info "Certificates written, keys decrypted, DH generated."

###############################################################################
#  STEP 5: RADIUS config (OpenVPN)
###############################################################################
step 5 "RADIUS (OpenVPN)"

RADIUS_CONF="/etc/openvpn/server/radiusplugin.cnf"
if [[ -f "$RADIUS_CONF" ]]; then
    info "RADIUS config already exists."
else
    cat > "$RADIUS_CONF" << 'RADEOF'
NAS-Identifier=OpenVPN
Service-Type=5
Framed-Protocol=1
NAS-Port-Type=5
NAS-IP-Address=127.0.0.1
OpenVPNConfig=/etc/openvpn/server/server-tcp.conf
overwriteccfiles=true

server
{
    acctport=1813
    authport=1812
    name=185.141.168.2
    retry=1
    wait=5
    sharedsecret=11041104
}
RADEOF
    info "RADIUS config written."
fi

###############################################################################
#  STEP 6: OpenVPN configs (TCP + UDP with management sockets)
###############################################################################
step 6 "OpenVPN server configs"

# TCP
if [[ -f /etc/openvpn/server/server-tcp.conf ]]; then
    info "server-tcp.conf exists."
    # Ensure management socket is present
    if ! grep -q "management.*tcp-mgmt.sock" /etc/openvpn/server/server-tcp.conf; then
        echo "management /run/openvpn-server/tcp-mgmt.sock unix" >> /etc/openvpn/server/server-tcp.conf
        info "Added management socket to TCP config."
    fi
else
    cat > /etc/openvpn/server/server-tcp.conf << 'TCPEOF'
port 11041
proto tcp
dev tun0
topology subnet
server 10.2.0.0 255.255.0.0

ca /etc/openvpn/server/certs/ca.crt
cert /etc/openvpn/server/certs/server.crt
key /etc/openvpn/server/certs/server.key
dh /etc/openvpn/server/certs/dh2048.pem

plugin /usr/lib/openvpn/radiusplugin.so /etc/openvpn/server/radiusplugin.cnf
username-as-common-name
verify-client-cert none

keepalive 10 120
cipher AES-256-GCM
persist-key
persist-tun
verb 3
status /var/log/openvpn-tcp-status.log 10
status-version 1
log-append /var/log/openvpn-tcp.log
duplicate-cn
management /run/openvpn-server/tcp-mgmt.sock unix
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
TCPEOF
    info "server-tcp.conf written."
fi

# UDP
if [[ -f /etc/openvpn/server/server-udp.conf ]]; then
    info "server-udp.conf exists."
    if ! grep -q "management.*udp-mgmt.sock" /etc/openvpn/server/server-udp.conf; then
        echo "management /run/openvpn-server/udp-mgmt.sock unix" >> /etc/openvpn/server/server-udp.conf
        info "Added management socket to UDP config."
    fi
else
    cat > /etc/openvpn/server/server-udp.conf << 'UDPEOF'
port 11041
proto udp
dev tun1
topology subnet
server 10.3.0.0 255.255.0.0

ca /etc/openvpn/server/certs/ca.crt
cert /etc/openvpn/server/certs/server.crt
key /etc/openvpn/server/certs/server.key
dh /etc/openvpn/server/certs/dh2048.pem

plugin /usr/lib/openvpn/radiusplugin.so /etc/openvpn/server/radiusplugin.cnf
username-as-common-name
verify-client-cert none

keepalive 10 120
cipher AES-256-GCM
persist-key
persist-tun
verb 3
status /var/log/openvpn-udp-status.log 10
status-version 1
log-append /var/log/openvpn-udp.log
duplicate-cn
management /run/openvpn-server/udp-mgmt.sock unix
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
UDPEOF
    info "server-udp.conf written."
fi

###############################################################################
#  STEP 7: Let's Encrypt certificate (shared by IKEv2 + ocserv)
###############################################################################
step 7 "Let's Encrypt certificate"

# Read domain from vroute.conf
DOMAIN=$(python3 -c "import json; c=json.load(open('/opt/vroute.conf')); print(c.get('ikev2_domain', c.get('ocserv_domain', '')))")
[[ -z "$DOMAIN" ]] && fatal "No domain configured in vroute.conf"

CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

if [[ -d "$CERT_DIR" ]]; then
    # Check if cert is RSA (required for strongSwan Windows compatibility)
    KEY_TYPE=$(openssl pkey -in "$CERT_DIR/privkey.pem" -noout -text 2>/dev/null | head -1 || true)
    if echo "$KEY_TYPE" | grep -qi "RSA"; then
        info "RSA certificate already exists for $DOMAIN"
    else
        warn "Existing cert is not RSA. Renewing as RSA..."
        certbot certonly --standalone -d "$DOMAIN" \
            --key-type rsa --rsa-key-size 2048 --force-renewal \
            --non-interactive --agree-tos --register-unsafely-without-email || {
            error "Certbot failed"; ((ERRORS++))
        }
    fi
else
    info "Requesting Let's Encrypt RSA certificate for $DOMAIN..."
    info "NOTE: Port 80 must be free for HTTP validation."

    certbot certonly --standalone -d "$DOMAIN" \
        --key-type rsa --rsa-key-size 2048 \
        --non-interactive --agree-tos --register-unsafely-without-email || {
        error "Certbot failed — ensure DNS A record points to this server and port 80 is free"
        ((ERRORS++))
    }
fi

###############################################################################
#  STEP 8: IKEv2 (strongSwan)
###############################################################################
step 8 "IKEv2 (strongSwan)"

# ── Install certs for strongSwan ──
mkdir -p /etc/ipsec.d/certs /etc/ipsec.d/private /etc/ipsec.d/cacerts

if [[ -f "$CERT_DIR/fullchain.pem" ]]; then
    openssl x509 -in "$CERT_DIR/fullchain.pem" -out /etc/ipsec.d/certs/server.crt 2>/dev/null
    info "Server cert installed."
else
    error "fullchain.pem not found!"; ((ERRORS++))
fi

if [[ -f "$CERT_DIR/privkey.pem" ]]; then
    openssl rsa -in "$CERT_DIR/privkey.pem" -out /etc/ipsec.d/private/server.pem 2>/dev/null
    chmod 600 /etc/ipsec.d/private/server.pem
    info "Private key installed."
else
    error "privkey.pem not found!"; ((ERRORS++))
fi

if [[ -f "$CERT_DIR/chain.pem" ]]; then
    cp "$CERT_DIR/chain.pem" /etc/ipsec.d/cacerts/lets-encrypt-chain.pem
    info "CA chain installed."
else
    error "chain.pem not found!"; ((ERRORS++))
fi

# ── Disable competing strongswan.service (use strongswan-starter instead) ──
if systemctl is-enabled strongswan.service &>/dev/null 2>&1; then
    systemctl stop strongswan.service &>/dev/null 2>&1 || true
    systemctl disable strongswan.service &>/dev/null 2>&1 || true
    systemctl mask strongswan.service &>/dev/null 2>&1 || true
    info "Disabled competing strongswan.service (using strongswan-starter)."
fi

# ── ipsec.conf (IKEv2 base — L2TP appends in Step 9) ──
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
    leftid=@$DOMAIN
    leftcert=server.crt
    leftsubnet=0.0.0.0/0
    leftsendcert=always

    # Client side
    right=%any
    rightid=%any
    rightsourceip=10.4.0.0/16
    rightdns=$DNS1,$DNS2

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
info "ipsec.conf written (IKEv2 conn)."

# ── ipsec.secrets (RSA key — L2TP appends PSK in Step 9) ──
echo ": RSA /etc/ipsec.d/private/server.pem" > /etc/ipsec.secrets
info "ipsec.secrets written (RSA key)."

# ── EAP-RADIUS plugin ──
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

# ── strongswan.conf (explicit — the default package config can break IKEv2 on some devices) ──
cat > /etc/strongswan.conf << 'SWANEOF'
charon {
    load_modular = yes
    plugins {
        include strongswan.d/charon/*.conf
    }
}
include strongswan.d/*.conf
SWANEOF
info "strongswan.conf written."

# ── Suppress charon debug logging ──
# Disable syslog noise, no filelog (keep it simple — avoid empty filelog{} blocks
# which can override filelog settings if added later for debugging)
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
}
LOGEOF
info "Charon logging suppressed (syslog disabled, no filelog)."

###############################################################################
#  STEP 9: L2TP/IPsec
###############################################################################
step 9 "L2TP/IPsec"

# ── Append L2TP conn to ipsec.conf ──
# Remove old l2tp-psk block if present (from previous run)
if grep -q "conn l2tp-psk" /etc/ipsec.conf; then
    python3 -c "
import re
with open('/etc/ipsec.conf') as f:
    content = f.read()
content = re.sub(r'\nconn l2tp-psk\n(?:[ \t]+[^\n]*\n)*', '\n', content)
with open('/etc/ipsec.conf', 'w') as f:
    f.write(content.rstrip() + '\n')
"
    info "Removed old l2tp-psk block."
fi

cat >> /etc/ipsec.conf << 'IPSECEOF'

conn l2tp-psk
    keyexchange=ikev1
    authby=secret
    auto=add
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    rekey=no
    dpddelay=30
    dpdtimeout=300
    dpdaction=clear
    ike=aes256-sha256-modp2048,aes256-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha256-modp2048,aes128-sha256-modp1024,aes128-sha1-modp2048,aes128-sha1-modp1024,3des-sha1-modp1024,3des-sha1-modp768!
    esp=aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,3des-sha1!
IPSECEOF
info "L2TP conn block appended to ipsec.conf."

# ── Append PSK to ipsec.secrets ──
if ! grep -q "# L2TP PSK" /etc/ipsec.secrets; then
    echo "# L2TP PSK" >> /etc/ipsec.secrets
    echo ": PSK \"$IPSEC_PSK\"" >> /etc/ipsec.secrets
    info "L2TP PSK appended to ipsec.secrets."
fi
chmod 600 /etc/ipsec.secrets

# ── xl2tpd.conf ──
mkdir -p /etc/xl2tpd
cat > /etc/xl2tpd/xl2tpd.conf << XLEOF
[global]
port = 1701
access control = no

[lns default]
ip range = $L2TP_POOL_START-$L2TP_POOL_END
local ip = $L2TP_LOCAL_IP
require authentication = yes
name = l2tp-server
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
XLEOF
info "xl2tpd.conf written."

# ── PPP options ──
cat > /etc/ppp/options.xl2tpd << PPPEOF
require-mschap-v2
ms-dns $DNS1
ms-dns $DNS2
asyncmap 0
auth
idle 1800
mtu 1400
mru 1400
hide-password
nodefaultroute
logfile /var/log/ppp-l2tp.log
proxyarp
noaccomp
nopcomp
noccp
lcp-echo-failure 4
lcp-echo-interval 30
ipcp-accept-local
ipcp-accept-remote
PPPEOF

# ── Detect pppd version for plugin path ──
PPPD_VERSION=$(pppd --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "2.4.9")
RADIUS_PLUGIN_DIR="/usr/lib/pppd/$PPPD_VERSION"

if [[ -f "$RADIUS_PLUGIN_DIR/radius.so" ]]; then
    info "RADIUS plugin found: $RADIUS_PLUGIN_DIR/radius.so"
    cat >> /etc/ppp/options.xl2tpd << RADPPPEOF

# RADIUS authentication
plugin $RADIUS_PLUGIN_DIR/radius.so
plugin $RADIUS_PLUGIN_DIR/radattr.so
radius-config-file /etc/ppp/radius/radiusclient.conf
RADPPPEOF
    info "PPP options written with RADIUS plugin."

    # ── RADIUS client config (PPP) ──
    mkdir -p /etc/ppp/radius

    cat > /etc/ppp/radius/radiusclient.conf << RADCEOF
auth_order radius
login_tries 4
login_timeout 60
nologin /etc/nologin
issue /etc/radiusclient/issue
authserver $RADIUS_IP:$RADIUS_AUTH_PORT
acctserver $RADIUS_IP:$RADIUS_ACCT_PORT
servers /etc/ppp/radius/servers
dictionary /etc/ppp/radius/dictionary
login_radius /usr/sbin/login.radius
seqfile /var/run/radius.seq
mapfile /etc/ppp/radius/port-id-map
default_realm
radius_timeout 10
radius_retries 3
RADCEOF
    info "PPP radiusclient.conf written."

    cat > /etc/ppp/radius/servers << SRVEOF
$RADIUS_IP    $RADIUS_SECRET
SRVEOF
    chmod 600 /etc/ppp/radius/servers

    # ── Dictionary ──
    cat > /etc/ppp/radius/dictionary << 'DICTEOF'
#
# RADIUS dictionary for pppd radius.so plugin
# Only uses types understood by pppd: string, ipaddr, integer, date
#

# Standard RADIUS attributes (RFC 2865/2866)
ATTRIBUTE   User-Name               1   string
ATTRIBUTE   Password                2   string
ATTRIBUTE   CHAP-Password           3   string
ATTRIBUTE   NAS-IP-Address          4   ipaddr
ATTRIBUTE   NAS-Port-Id             5   integer
ATTRIBUTE   Service-Type            6   integer
ATTRIBUTE   Framed-Protocol         7   integer
ATTRIBUTE   Framed-IP-Address       8   ipaddr
ATTRIBUTE   Framed-IP-Netmask       9   ipaddr
ATTRIBUTE   Framed-Routing          10  integer
ATTRIBUTE   Filter-Id               11  string
ATTRIBUTE   Framed-MTU              12  integer
ATTRIBUTE   Framed-Compression      13  integer
ATTRIBUTE   Login-IP-Host           14  ipaddr
ATTRIBUTE   Login-Service           15  integer
ATTRIBUTE   Login-TCP-Port          16  integer
ATTRIBUTE   Reply-Message           18  string
ATTRIBUTE   Callback-Number         19  string
ATTRIBUTE   Callback-Id             20  string
ATTRIBUTE   Session-Timeout         27  integer
ATTRIBUTE   Idle-Timeout            28  integer
ATTRIBUTE   Termination-Action      29  integer
ATTRIBUTE   Called-Station-Id       30  string
ATTRIBUTE   Calling-Station-Id      31  string
ATTRIBUTE   NAS-Identifier          32  string
ATTRIBUTE   Proxy-State             33  string
ATTRIBUTE   Acct-Status-Type        40  integer
ATTRIBUTE   Acct-Delay-Time         41  integer
ATTRIBUTE   Acct-Input-Octets       42  integer
ATTRIBUTE   Acct-Output-Octets      43  integer
ATTRIBUTE   Acct-Session-Id         44  string
ATTRIBUTE   Acct-Authentic          45  integer
ATTRIBUTE   Acct-Session-Time       46  integer
ATTRIBUTE   Acct-Input-Packets      47  integer
ATTRIBUTE   Acct-Output-Packets     48  integer
ATTRIBUTE   Acct-Terminate-Cause    49  integer
ATTRIBUTE   NAS-Port-Type           61  integer
ATTRIBUTE   Port-Limit              62  integer
ATTRIBUTE   Connect-Info            77  string
ATTRIBUTE   Vendor-Specific         26  string

# Standard values
VALUE   Service-Type        Login-User          1
VALUE   Service-Type        Framed-User         2
VALUE   Framed-Protocol     PPP                 1
VALUE   Framed-Routing      None                0
VALUE   Framed-Compression  Van-Jacobson-TCP-IP 1
VALUE   Acct-Status-Type    Start               1
VALUE   Acct-Status-Type    Stop                2
VALUE   Acct-Status-Type    Alive               3
VALUE   Acct-Terminate-Cause User-Request       1
VALUE   NAS-Port-Type       Virtual             5
VALUE   NAS-Port-Type       Async               0

# Microsoft vendor-specific attributes (Vendor ID 311)
# Required for MS-CHAPv2 authentication
VENDOR      Microsoft       311     Microsoft

ATTRIBUTE   MS-CHAP-Response        1   string  Microsoft
ATTRIBUTE   MS-CHAP-Error           2   string  Microsoft
ATTRIBUTE   MS-CHAP-CPW-1           3   string  Microsoft
ATTRIBUTE   MS-CHAP-CPW-2           4   string  Microsoft
ATTRIBUTE   MS-CHAP-LM-Enc-PW      5   string  Microsoft
ATTRIBUTE   MS-CHAP-NT-Enc-PW      6   string  Microsoft
ATTRIBUTE   MS-MPPE-Encryption-Policy 7 string  Microsoft
ATTRIBUTE   MS-MPPE-Encryption-Type 8   string  Microsoft
ATTRIBUTE   MS-RAS-Vendor           9   integer Microsoft
ATTRIBUTE   MS-CHAP-Domain          10  string  Microsoft
ATTRIBUTE   MS-CHAP-Challenge       11  string  Microsoft
ATTRIBUTE   MS-CHAP-MPPE-Keys      12  string  Microsoft
ATTRIBUTE   MS-BAP-Usage            13  integer Microsoft
ATTRIBUTE   MS-Link-Utilization-Threshold 14 integer Microsoft
ATTRIBUTE   MS-Link-Drop-Time-Limit 15  integer Microsoft
ATTRIBUTE   MS-MPPE-Send-Key       16  string  Microsoft
ATTRIBUTE   MS-MPPE-Recv-Key       17  string  Microsoft
ATTRIBUTE   MS-RAS-Version          18  string  Microsoft
ATTRIBUTE   MS-Old-ARAP-Password   19  string  Microsoft
ATTRIBUTE   MS-New-ARAP-Password   20  string  Microsoft
ATTRIBUTE   MS-CHAP2-Response       25  string  Microsoft
ATTRIBUTE   MS-CHAP2-Success        26  string  Microsoft
ATTRIBUTE   MS-CHAP2-CPW           27  string  Microsoft
ATTRIBUTE   MS-Primary-DNS-Server   28  ipaddr  Microsoft
ATTRIBUTE   MS-Secondary-DNS-Server 29  ipaddr  Microsoft
ATTRIBUTE   MS-Primary-NBNS-Server  30  ipaddr  Microsoft
ATTRIBUTE   MS-Secondary-NBNS-Server 31 ipaddr  Microsoft
DICTEOF
    info "RADIUS dictionary written."

    if [[ ! -f /etc/ppp/radius/port-id-map ]]; then
        touch /etc/ppp/radius/port-id-map
    fi
else
    warn "radius.so not found — PPP written WITHOUT RADIUS (using local chap-secrets)."
    if [[ ! -f /etc/ppp/chap-secrets ]]; then
        cat > /etc/ppp/chap-secrets << 'CHAPEOF'
# Secrets for authentication using CHAP
# client    server    secret    IP addresses
CHAPEOF
        chmod 600 /etc/ppp/chap-secrets
    fi
fi

# ── ICMP redirects (required for L2TP) ──
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > "$f"; done
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > "$f"; done
cat > /etc/sysctl.d/99-l2tp.conf << 'SYSEOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
SYSEOF
sysctl -p /etc/sysctl.d/99-l2tp.conf >/dev/null 2>&1
info "ICMP redirects disabled."

# ── PPP ip-up hook for L2TP session tracking ──
cat > /etc/ppp/ip-up.d/l2tp-session << 'HOOKEOF'
#!/usr/bin/env python3
"""PPP ip-up hook: write L2TP session info to /var/run/l2tp-sessions.json"""
import json, os, re, subprocess, sys

iface = sys.argv[1] if len(sys.argv) > 1 else ""
if not iface.startswith("ppp"):
    sys.exit(0)

local_ip = sys.argv[4] if len(sys.argv) > 4 else ""
remote_ip = sys.argv[5] if len(sys.argv) > 5 else ""
username = os.environ.get("PEERNAME", "")

# Get pppd PID from pidfile (not getppid — may be intermediate shell)
pppd_pid = ""
try:
    with open(f"/var/run/{iface}.pid") as f:
        pppd_pid = f.read().strip()
except Exception:
    pass

# Get tunnel_id from pppd's cmdline
tunnel_id = ""
if pppd_pid:
    try:
        with open(f"/proc/{pppd_pid}/cmdline", "rb") as f:
            args = f.read().decode("utf-8", errors="replace").split("\x00")
        for i, arg in enumerate(args):
            if arg == "pppol2tp_tunnel_id" and i + 1 < len(args):
                tunnel_id = args[i + 1]
                break
    except Exception:
        pass

# Look up client real IP from L2TP tunnel
real_ip = ""
if tunnel_id:
    try:
        out = subprocess.run(["ip", "l2tp", "show", "tunnel"],
                             capture_output=True, text=True, timeout=3).stdout
        tid = None
        for line in out.split("\n"):
            m = re.match(r"Tunnel\s+(\d+)", line)
            if m:
                tid = m.group(1)
            elif tid == tunnel_id:
                m = re.search(r"to\s+(\S+)", line)
                if m:
                    real_ip = m.group(1)
                    break
    except Exception:
        pass

# Read existing cache
cache_path = "/var/run/l2tp-sessions.json"
data = {}
if os.path.exists(cache_path):
    try:
        with open(cache_path) as f:
            data = json.load(f)
    except Exception:
        pass

# Update and write
data[iface] = {
    "username": username,
    "pid": int(pppd_pid) if pppd_pid else 0,
    "local_ip": local_ip,
    "remote_ip": remote_ip,
    "real_ip": real_ip,
}
with open(cache_path, "w") as f:
    json.dump(data, f)
HOOKEOF
chmod +x /etc/ppp/ip-up.d/l2tp-session
info "PPP ip-up hook installed."

# ── PPP ip-down hook ──
cat > /etc/ppp/ip-down.d/l2tp-session << 'HOOKEOF'
#!/usr/bin/env python3
"""PPP ip-down hook: remove L2TP session from /var/run/l2tp-sessions.json"""
import json, os, sys

iface = sys.argv[1] if len(sys.argv) > 1 else ""
if not iface.startswith("ppp"):
    sys.exit(0)

cache_path = "/var/run/l2tp-sessions.json"
if not os.path.exists(cache_path):
    sys.exit(0)

try:
    with open(cache_path) as f:
        data = json.load(f)
    data.pop(iface, None)
    with open(cache_path, "w") as f:
        json.dump(data, f)
except Exception:
    pass
HOOKEOF
chmod +x /etc/ppp/ip-down.d/l2tp-session
info "PPP ip-down hook installed."

###############################################################################
#  STEP 10: ocserv (OpenConnect / AnyConnect)
###############################################################################
step 10 "ocserv (OpenConnect)"

# ── radcli RADIUS config ──
mkdir -p /etc/radcli

cat > /etc/radcli/radiusclient.conf << 'RADCLIEOF'
# radcli configuration for ocserv RADIUS auth
nas-identifier ocserv
authserver 185.141.168.2:1812
acctserver 185.141.168.2:1813
servers /etc/radcli/servers
dictionary /etc/radcli/dictionary
default_realm
radius_timeout 10
radius_retries 3
bindaddr *
RADCLIEOF
info "radcli config written."

cat > /etc/radcli/servers << 'SRVEOF'
185.141.168.2    11041104
SRVEOF
chmod 600 /etc/radcli/servers
info "radcli servers written."

# Ensure dictionary exists
if [[ ! -f /etc/radcli/dictionary ]]; then
    if [[ -f /usr/share/radcli/dictionary ]]; then
        ln -sf /usr/share/radcli/dictionary /etc/radcli/dictionary
        info "Symlinked dictionary."
    elif [[ -f /usr/share/freeradius/dictionary ]]; then
        ln -sf /usr/share/freeradius/dictionary /etc/radcli/dictionary
        info "Symlinked dictionary (freeradius)."
    else
        warn "No dictionary found — RADIUS may fail."
    fi
fi

# ── ocserv.conf ──
cat > /etc/ocserv/ocserv.conf << OCEOF
# VRoute ocserv configuration
# Generated by deploy.sh — $(date)

# Authentication via RADIUS
auth = "radius[config=/etc/radcli/radiusclient.conf,groupconfig=true]"

# Socket file for IPC
socket-file = /var/run/ocserv-socket

# Enable occtl control tool
use-occtl = true
pid-file = /var/run/ocserv.pid

# TCP and UDP (DTLS) on port 443
tcp-port = 443
udp-port = 443

# TLS certificate (Let's Encrypt)
server-cert = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
server-key = /etc/letsencrypt/live/$DOMAIN/privkey.pem

# VPN subnet
ipv4-network = 10.5.0.0
ipv4-netmask = 255.255.0.0

# DNS
dns = $DNS1
dns = $DNS2

# Routing — push default route to clients
route = default

# Device prefix
device = vpns

# Limits
max-clients = 0
max-same-clients = 4

# Keepalive
keepalive = 300
dpd = 90
mobile-dpd = 1800

# Timeouts
cookie-timeout = 300
rekey-time = 172800

# Compression
compression = true

# Cisco AnyConnect compatibility
cisco-client-compat = true
dtls-legacy = true

# Logging
log-level = 1

# TLS priorities
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-SSL3.0:-ARCFOUR-128"
OCEOF
info "ocserv.conf written."

###############################################################################
#  STEP 11: Certificate renewal hooks
###############################################################################
step 11 "Certificate renewal hooks"

mkdir -p /etc/letsencrypt/renewal-hooks/deploy

# strongSwan hook
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
info "strongSwan renewal hook installed."

# ocserv hook
cat > /etc/letsencrypt/renewal-hooks/deploy/ocserv.sh << 'HOOKEOF'
#!/bin/bash
# Restart ocserv after Let's Encrypt renewal
systemctl restart ocserv 2>/dev/null || true
echo "[ocserv-hook] ocserv restarted after cert renewal"
HOOKEOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/ocserv.sh
info "ocserv renewal hook installed."

###############################################################################
#  STEP 12: Deploy Python scripts
###############################################################################
step 12 "Python scripts"

for f in vroute_conf.py wg_sync.py wg_online.py ovpn_online.py sync_online.py \
         ikev2_online.py ocserv_online.py l2tp_online.py bw_monitor.py \
         v2ray_sync.py v2ray_online.py; do
    if [[ -f "$SCRIPT_DIR/$f" ]]; then
        cp "$SCRIPT_DIR/$f" "/opt/$f"
        chmod +x "/opt/$f"
        info "Installed /opt/$f"
    else
        warn "Missing $f in package — skipping."
    fi
done

###############################################################################
#  STEP 13: IP forwarding + NAT + Firewall
###############################################################################
step 13 "Networking (forwarding + NAT + firewall)"

if [[ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]]; then
    info "IP forwarding already enabled."
else
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    info "IP forwarding enabled."
fi

add_forward_rule() {
    local dir="$1" iface="$2"
    if ! iptables -C FORWARD -"$dir" "$iface" -j ACCEPT &>/dev/null; then
        iptables -I FORWARD -"$dir" "$iface" -j ACCEPT
        info "  Added FORWARD -$dir $iface"
    fi
}
add_nat_rule() {
    local subnet="$1"
    if ! iptables -t nat -C POSTROUTING -s "$subnet" -o "$IFACE" -j MASQUERADE &>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$subnet" -o "$IFACE" -j MASQUERADE
        info "  Added NAT for $subnet via $IFACE"
    fi
}
add_port_rule() {
    local proto="$1" port="$2"
    if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT &>/dev/null; then
        iptables -A INPUT -p "$proto" --dport "$port" -j ACCEPT
        info "  Opened $proto port $port"
    fi
}

# FORWARD rules
add_forward_rule i wg0;   add_forward_rule o wg0     # WireGuard
add_forward_rule i tun0;  add_forward_rule o tun0    # OpenVPN TCP
add_forward_rule i tun1;  add_forward_rule o tun1    # OpenVPN UDP
add_forward_rule i vpns+; add_forward_rule o vpns+   # ocserv
add_forward_rule i ppp+;  add_forward_rule o ppp+    # L2TP

# NAT rules
add_nat_rule "10.1.0.0/16"    # WireGuard
add_nat_rule "10.2.0.0/16"    # OpenVPN TCP
add_nat_rule "10.3.0.0/16"    # OpenVPN UDP
add_nat_rule "10.5.0.0/16"    # ocserv
add_nat_rule "10.6.0.0/24"    # L2TP
# IKEv2 (10.4.0.0/16) uses XFRM — NAT handled by strongSwan's updown plugin

# Firewall ports
add_port_rule tcp 443    # ocserv
add_port_rule udp 443    # ocserv DTLS
add_port_rule udp 500    # IPsec IKE
add_port_rule udp 4500   # IPsec NAT-T
add_port_rule udp 1701   # L2TP
add_port_rule tcp 11042  # V2RAY (VLESS)

# Allow ESP protocol (IPsec)
if ! iptables -C INPUT -p esp -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p esp -j ACCEPT
    info "  Allowed ESP protocol"
fi

netfilter-persistent save &>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null
info "Networking configured."

###############################################################################
#  STEP 14: Start VPN services
###############################################################################
step 14 "VPN services"

# ── WireGuard ──
systemctl enable wg-quick@wg0 &>/dev/null

# ── OpenVPN ──
for svc in openvpn-server@server-tcp openvpn-server@server-udp; do
    systemctl enable "$svc" &>/dev/null
    if systemctl is-active --quiet "$svc"; then
        systemctl restart "$svc"
        info "$svc restarted."
    else
        systemctl start "$svc" || { error "$svc failed — check: journalctl -u $svc"; ((ERRORS++)); }
        info "$svc started."
    fi
done

# ── strongSwan (IKEv2 + L2TP IPsec) ──
systemctl enable strongswan-starter &>/dev/null
ipsec restart || { error "strongSwan failed to start"; ((ERRORS++)); }

# Wait for strongSwan to fully load
for i in 1 2 3 4 5; do
    sleep 1
    CONN_COUNT=$(ipsec statusall 2>/dev/null | grep -c "conn\b" || true)
    [[ "$CONN_COUNT" -ge 2 ]] && break
done
if ipsec statusall 2>/dev/null | grep -q "ikev2:"; then
    info "strongSwan: ikev2 connection loaded."
else
    warn "strongSwan: ikev2 connection not loaded. Check: ipsec statusall"
fi
if ipsec statusall 2>/dev/null | grep -q "l2tp-psk:"; then
    info "strongSwan: l2tp-psk connection loaded."
else
    warn "strongSwan: l2tp-psk connection not loaded. Check: ipsec statusall"
fi

# Disable local FreeRADIUS if installed (we use remote RADIUS)
if systemctl is-active --quiet freeradius 2>/dev/null; then
    systemctl stop freeradius
    systemctl disable freeradius
    info "Disabled local FreeRADIUS."
fi

# ── xl2tpd ──
systemctl enable xl2tpd &>/dev/null
if systemctl is-active --quiet xl2tpd; then
    systemctl restart xl2tpd
    info "xl2tpd restarted."
else
    systemctl start xl2tpd || { error "xl2tpd failed — check: journalctl -u xl2tpd"; ((ERRORS++)); }
    info "xl2tpd started."
fi

# ── ocserv ──
systemctl enable ocserv &>/dev/null
systemctl restart ocserv || { error "ocserv failed to start"; ((ERRORS++)); }
sleep 1
if systemctl is-active --quiet ocserv; then
    info "ocserv is running."
else
    error "ocserv is NOT running. Check: journalctl -u ocserv -n 50"
    ((ERRORS++))
fi

###############################################################################
#  STEP 15: V2RAY (VLESS via Xray)
###############################################################################
step 15 "V2RAY (VLESS via Xray)"

# Install Xray-core
if [[ -f /usr/local/bin/xray ]]; then
    XRAY_VER=$(/usr/local/bin/xray version 2>/dev/null | head -1 || echo "unknown")
    info "Xray already installed: $XRAY_VER"
else
    info "Installing Xray-core..."
    bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || {
        error "Xray install failed"; ((ERRORS++))
    }
fi

# Xray log directory + logrotate
mkdir -p /var/log/xray /usr/local/etc/xray
chmod 755 /var/log/xray

if [[ ! -f /etc/logrotate.d/xray ]]; then
    cat > /etc/logrotate.d/xray << 'LOGEOF'
/var/log/xray/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
LOGEOF
    info "Xray logrotate configured."
fi

# Ensure python3-mysql.connector (needed by v2ray_sync.py)
if ! python3 -c "import mysql.connector" &>/dev/null; then
    apt install -y python3-mysql.connector || { error "python3-mysql.connector install failed"; ((ERRORS++)); }
fi

# Initial user sync (generates /usr/local/etc/xray/config.json)
info "Running v2ray_sync.py to generate Xray config..."
if python3 /opt/v2ray_sync.py; then
    USER_COUNT=$(python3 -c "
import json
try:
    c = json.load(open('/usr/local/etc/xray/config.json'))
    print(len(c.get('inbounds', [{}])[0].get('settings', {}).get('clients', [])))
except:
    print('?')
" 2>/dev/null || echo "?")
    info "Xray config generated: $USER_COUNT users loaded."
else
    error "v2ray_sync.py failed — check DB connection"
    ((ERRORS++))
fi

# v2ray-sync systemd service
cat > /etc/systemd/system/v2ray-sync.service << 'SVCEOF'
[Unit]
Description=VRoute V2Ray User Sync
After=network.target xray.service
Wants=xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /opt/v2ray_sync.py --loop --poll=5
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=v2ray-sync

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable xray v2ray-sync &>/dev/null

# Start Xray + v2ray-sync
systemctl restart xray || { error "Xray failed to start"; ((ERRORS++)); }
sleep 1
if systemctl is-active --quiet xray; then
    info "Xray is running (VLESS on port 11042/TCP)."
else
    error "Xray is NOT running! Check: journalctl -u xray -n 20"
    ((ERRORS++))
fi

systemctl restart v2ray-sync || { error "v2ray-sync failed to start"; ((ERRORS++)); }
info "v2ray-sync service started (poll=5s, hot-reload via API)."

###############################################################################
#  STEP 16: WG sync service
###############################################################################
step 16 "WireGuard sync service"

cat > /etc/systemd/system/wg-sync.service << 'SVCEOF'
[Unit]
Description=VRoute WireGuard Peer Sync
After=network.target wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /opt/wg_sync.py --loop --poll=5
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wg-sync

[Install]
WantedBy=multi-user.target
SVCEOF

# Remove old cron if present
rm -f /etc/cron.d/wg-sync

info "Running initial WireGuard sync..."
python3 /opt/wg_sync.py || warn "Initial sync failed — check DB connectivity"

systemctl daemon-reload
systemctl enable wg-sync &>/dev/null
systemctl restart wg-sync
info "wg-sync service started (poll=5s)."

###############################################################################
#  STEP 17: sync-online systemd service
###############################################################################
step 17 "Online sync service"

cat > /etc/systemd/system/sync-online.service << 'SVCEOF'
[Unit]
Description=VRoute VPN Online Sync
After=network.target openvpn-server@server-tcp.service openvpn-server@server-udp.service wg-quick@wg0.service strongswan-starter.service xl2tpd.service ocserv.service xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /opt/sync_online.py --loop --poll=1
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sync-online

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable sync-online &>/dev/null
systemctl restart sync-online
info "sync-online service started."

###############################################################################
#  STEP 18: Log retention (1 day only)
###############################################################################
step 18 "Log retention"

# Journald: cap VRoute service logs to 1 day
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/vroute.conf << 'JEOF'
[Journal]
MaxRetentionSec=1day
MaxFileSec=1day
SystemMaxUse=200M
JEOF

systemctl restart systemd-journald
info "Journald configured: 1-day retention, 200M max."

# Logrotate for VPN logs
cat > /etc/logrotate.d/vroute << 'LREOF'
/var/log/openvpn-tcp.log
/var/log/openvpn-udp.log
/var/log/ppp-l2tp.log
{
    daily
    rotate 1
    maxage 1
    missingok
    notifempty
    copytruncate
    compress
}
LREOF
info "Logrotate configured (1 day)."

###############################################################################
#  DONE
###############################################################################
echo ""
echo "============================================================"
if [[ $ERRORS -eq 0 ]]; then
    info "VRoute deploy complete! (0 errors)"
else
    warn "VRoute deploy complete with $ERRORS error(s)"
fi
echo "============================================================"
echo ""
echo "  Server:        $SERVER_NAME"
echo "  Domain:        $DOMAIN"
echo "  Config:        /opt/vroute.conf"
echo ""
echo "  WireGuard:     wg0  — 10.1.0.0/16  — port 11040/UDP"
echo "  OpenVPN TCP:   tun0 — 10.2.0.0/16  — port 11041/TCP"
echo "  OpenVPN UDP:   tun1 — 10.3.0.0/16  — port 11041/UDP"
echo "  IKEv2:         xfrm — 10.4.0.0/16  — ports 500+4500/UDP"
echo "  ocserv:        vpns — 10.5.0.0/16  — port 443 TCP+UDP"
echo "  L2TP/IPsec:    ppp  — 10.6.0.0/24  — port 1701/UDP"
echo "  V2RAY/VLESS:   xray — proxy        — port 11042/TCP"
echo "  RADIUS:        $RADIUS_IP:$RADIUS_AUTH_PORT"
echo "  Interface:     $IFACE"
echo ""
echo "  Services:"
echo "    systemctl status strongswan-starter  # IPsec (IKEv2 + L2TP)"
echo "    systemctl status xl2tpd              # L2TP"
echo "    systemctl status ocserv              # OpenConnect/AnyConnect"
echo "    systemctl status xray                # V2RAY (VLESS)"
echo "    systemctl status wg-sync             # WG peer sync (5s loop)"
echo "    systemctl status v2ray-sync          # V2RAY user sync (5s, hot-reload)"
echo "    systemctl status sync-online         # Redis online sync (1s loop)"
echo ""
echo "  Monitoring:"
echo "    python3 /opt/wg_online.py              # WG online users"
echo "    python3 /opt/ovpn_online.py            # OVPN online users"
echo "    python3 /opt/ikev2_online.py           # IKEv2 online users"
echo "    python3 /opt/ocserv_online.py          # ocserv online users"
echo "    python3 /opt/l2tp_online.py            # L2TP online users"
echo "    python3 /opt/v2ray_online.py           # V2RAY online users"
echo "    python3 /opt/bw_monitor.py             # Bandwidth monitor"
echo "    python3 /opt/sync_online.py -n         # Dry-run Redis sync"
echo ""
echo "  Logs:"
echo "    journalctl -u strongswan-starter -f    # IPsec log"
echo "    journalctl -u xl2tpd -f                # L2TP log"
echo "    journalctl -u ocserv -f                # ocserv log"
echo "    journalctl -u xray -f                  # Xray log"
echo "    journalctl -u v2ray-sync -f            # V2RAY user sync log"
echo "    journalctl -u sync-online -f           # Redis online sync log"
echo "    tail -f /var/log/openvpn-tcp.log       # OpenVPN TCP"
echo "    tail -f /var/log/openvpn-udp.log       # OpenVPN UDP"
echo "    tail -f /var/log/ppp-l2tp.log          # PPP log"
echo "    tail -f /var/log/xray/access.log       # V2RAY connections"
echo ""
echo "  IPsec status:"
echo "    ipsec statusall                        # Full SA details"
echo "    swanctl --list-sas                     # Active sessions"
echo ""
echo "  Certificate renewal:"
echo "    certbot renew --dry-run                # Test renewal"
echo "    # Auto-renewal via systemd timer (certbot)"
echo "    # strongSwan + ocserv reload via deploy hooks"
echo "============================================================"
