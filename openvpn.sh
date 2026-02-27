#!/bin/bash
###############################################################################
#  OpenVPN Deploy
#
#  Usage:  bash openvpn.sh
#
#  Installs and configures:
#    - OpenVPN TCP (tun0, 10.2.0.0/16) + UDP (tun1, 10.3.0.0/16)
#    - RADIUS authentication (openvpn-auth-radius plugin)
#    - TLS-auth (static key for HMAC firewall)
#    - All certs/keys embedded — no file prompts needed
#    - Management sockets for monitoring
#    - NAT + forwarding rules
#
#  Compatible with .ovpn clients:
#    cipher AES-256-CBC, auth SHA256, tls-auth, auth-user-pass
#
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

IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
[[ -z "$IFACE" ]] && fatal "Cannot detect default network interface"

info "Interface: $IFACE"

ERRORS=0

# ── Defaults (all hardcoded) ──
OVPN_PORT=443
RADIUS_IP="85.133.237.35"
RADIUS_AUTH_PORT=1812
RADIUS_ACCT_PORT=1813
RADIUS_SECRET="alireza"
INSTALL_TCP=1
INSTALL_UDP=1

info "Protocol: TCP + UDP | Port: $OVPN_PORT | RADIUS: $RADIUS_IP:$RADIUS_AUTH_PORT"

###############################################################################
#  STEP 1: Install packages
###############################################################################
step 1 "Packages"

NEED_INSTALL=0
for pkg in openvpn openvpn-auth-radius; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        NEED_INSTALL=1
        break
    fi
done

if [[ $NEED_INSTALL -eq 1 ]]; then
    info "Installing OpenVPN + RADIUS plugin..."
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    apt update -qq
    apt install -y openvpn libradcli4 libradcli-dev openvpn-auth-radius || {
        error "Package install failed"; ((ERRORS++))
    }
else
    info "All packages already installed."
fi

###############################################################################
#  STEP 2: Embedded certificates + keys
###############################################################################
step 2 "Certificates"

CERT_DIR="/etc/openvpn/server/certs"
mkdir -p "$CERT_DIR"

# ── CA certificate ──
cat > "$CERT_DIR/ca.crt" << 'CERTEOF'
-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIJAIMk8N6hlDVYMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCENoYW5nZU1lMB4XDTIzMTExNzEyMTYzOFoXDTMzMTExNDEyMTYzOFowEzER
MA8GA1UEAwwIQ2hhbmdlTWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDDu2lKQEE+FNZUPdGSO5/DdBJTwI8gLZ7etk7uoOxul6e7kv3oqOckdBYQHRkV
zVll+4IntaFlrh/T8p38Gu6ujCselDnbXr+Q9mcAE6dAZw9zShqEzHx6W5+xBc3p
O5dkQSRO0fe+J8xccx0QlFYnrd5FKpodMb0MJ+RNgs9vBP2AEzAwVSb+ZjeA3Hnu
crBP5ZLswfOr+ls/tM6HIppywUz3MUsCzSooZ3MG1daPvjVGo8hzku3eubWX+L9k
v7jpQvUzqVYqtpQsxVrNe654mz+YdeNnqhxRo6ytPJh2jbF0w2jCobA6pY5ZY4kw
IuGrzB2PvC2BOYYtUTT0q9vTAgMBAAGjgYEwfzAdBgNVHQ4EFgQUmmWbwgRB3rzj
4ufwaHRzfUREfAswQwYDVR0jBDwwOoAUmmWbwgRB3rzj4ufwaHRzfUREfAuhF6QV
MBMxETAPBgNVBAMMCENoYW5nZU1lggkAgyTw3qGUNVgwDAYDVR0TBAUwAwEB/zAL
BgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAHlqVlf/4R1Ex/ESBoZzvxjn
SklUlRPRpSK2U02fm57U/FBv45N76i44d+iPdIvm2UZ27bgkuRLPDvQgT3CEccNh
TTuUAhJInHCZJYggBGjY50fkEpSzBrO3PXv0gtmi3QvQSkviW7InRHyqIiBWTGO4
Br/5F+Gb57e1t78uOW8TQyHLh0ivM0DHHb2NmqryN8SFtpWvXedya8KZaW1h/dJp
z+xjvxBPjbCF2x+Fo7tm0wCdOyryk3qFhaFUNSZfkNa22CkQiNOyogZTuwbyKwQn
OkOHdmUiHYFFjSenp9UnohAgHhEdoeqs1A6PzFqDPmJIbtHR1on2mgwHK2MAQYw=
-----END CERTIFICATE-----
CERTEOF
info "CA certificate written."

# ── Server certificate ──
cat > "$CERT_DIR/server.crt" << 'CERTEOF'
-----BEGIN CERTIFICATE-----
MIIDVjCCAj6gAwIBAgIQKG24q9MYBzuGNWqM8ztYSjANBgkqhkiG9w0BAQsFADAT
MREwDwYDVQQDDAhDaGFuZ2VNZTAeFw0yMzExMTcxMjE2MzhaFw0zMzExMTQxMjE2
MzhaMBExDzANBgNVBAMMBnNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAJnRB3uVkCJdCC2HnhaUlmkXwmetPh+t+NHk7og+PBlUe8WfaaLKKUvZ
qjTtEG/5+diZunAlMNx64BwBoYE/7ZbeCH6F9jeiFFmoatV/Lv3tRIWpeexUPlDS
ty121KHECYo02E5kHIEp4z3TnwdMXr2UbMuEiohKByzEDwmpL6yTRDSJY1tTQVSx
WqeWZ+BX4UcUFARZ9FeuTO/5uQm+B6oa9J2mGfsQo3i16hFV/EaqImQCM/5uscro
1Cw8FECOv2cyLt/CgWqJalxeHKo68My0zAylHLgAacS87Df7uSjxDKmfp39DsMDp
bM7e1UlU8vcx/soEg3JjJqft0I1lB4MCAwEAAaOBpzCBpDAJBgNVHRMEAjAAMB0G
A1UdDgQWBBTck0Rg2iJtcHQQFQ4nlyydPsUFczBDBgNVHSMEPDA6gBSaZZvCBEHe
vOPi5/BodHN9RER8C6EXpBUwEzERMA8GA1UEAwwIQ2hhbmdlTWWCCQCDJPDeoZQ1
WDATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAwEQYDVR0RBAowCIIG
c2VydmVyMA0GCSqGSIb3DQEBCwUAA4IBAQCVkYubT/QIfk+xJJfz0E0pJOsAQMt7
OFiYk/8HL5YzYvsTt8yr3Ll91HDZElywFiQzXTv95sZUFJiKaBjyJ5pPjsSn7iOT
ImP/WYELS9FgomsDMhAxs5innMov0r5g++ybTCuOgivTsykZuK8E63JbElLUyOfS
W7kOjxYCwSI6yHebiVJwN3DqM9V/q2ehQcbCoFzyvhTHQFNvvmWtPwhtRn6t4JYy
k7h/FJtZhf+Fai8usJVwDx9Ive+OcEZXS9oA85R3f5GRI9XXx7+EsAUi59cLWDmK
t39+ZGbWbn7omH5Fe11D0aP4iB4FEpuIhcfdyv1MYQrBK5kvkiNqZMly
-----END CERTIFICATE-----
CERTEOF
info "Server certificate written."

# ── Server private key ──
cat > "$CERT_DIR/server.key" << 'CERTEOF'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZ0Qd7lZAiXQgt
h54WlJZpF8JnrT4frfjR5O6IPjwZVHvFn2miyilL2ao07RBv+fnYmbpwJTDceuAc
AaGBP+2W3gh+hfY3ohRZqGrVfy797USFqXnsVD5Q0rctdtShxAmKNNhOZByBKeM9
058HTF69lGzLhIqISgcsxA8JqS+sk0Q0iWNbU0FUsVqnlmfgV+FHFBQEWfRXrkzv
+bkJvgeqGvSdphn7EKN4teoRVfxGqiJkAjP+brHK6NQsPBRAjr9nMi7fwoFqiWpc
XhyqOvDMtMwMpRy4AGnEvOw3+7ko8Qypn6d/Q7DA6WzO3tVJVPL3Mf7KBINyYyan
7dCNZQeDAgMBAAECggEBAIL2ruBSn74iZ+wcJEYljUs9p5COuO5QOiK8QTxPgOww
OpIxAMhSSIcEdR9LGUu+EzSQ72S8xbV0CYzO9qwNukVSFvljJhiIL7uG4i+VcnVR
p54GhoDp2YUHZF+ZZcG2IElEZUeZhYuUFp91p1mXdLMFxPwjhbA1F5bN99/J5YWR
K+oDUFrQ4NZZ2WTOunLfDaty2vNGsdwoRVWacNATNn0rZXNtsU5ehRqs/BRdRnQ6
g6a6IUd6kugZ4lq9vTlSB2X961ZVG9CdlvOGppA+vcMKPQoelTbl7zl/6DMNlFaN
Oyu3rHSRm7pEVKRceSAJfH2UV1CLdG+u/y0NwKMcOMECgYEAyunCb6rlL4BUcefH
0iO6WNIuGh2XxABEu/RorcEYrm5JcVJTrjyYDhuKsCeEHJ5C3rIYQ8zd9WMrEZ8O
2NgfHofz3kmuqc0Qlh6X6HtHJpi7i/b8TE/35AqFUCQHgqmSE7Ps2J4LXwyfznmb
XR1V08/R235WvXkS0fGY0qaX6G8CgYEAwg7+CBFRpSgt25RG+PkYHe85s7K0885R
l77l+x+FRvQ9Z/4yEHI9n4/PCQT5NLDNxmxyNvLcHKnk1j1PxO/C+fxS+OJqq6fs
/pdEFXft49At9Gu1z1Ed0YVL0zEIVCJcEKpMaEbbrkAM6uQtkc5kqCHBmOeddF6r
nYLtBjE/lC0CgYBE6Uh4RhCZpjqHiJDLJAkYOyEfC2fMT88ICgQ25josmxXkH3J9
3ORC/kWGd5UdZv4MxW0KMZw7xxcMX/lZ2WQQKVm/50QjNJpqcS9j6+IJEJu4+ANN
I2drkcseoW3PiSkr+dH46wuvlwj6xT/nSpwoWA7MPUbWCDVFCYi+GYfDjwKBgACK
uCzfl4HFjfM6A8S4NVgIDfoxeo3fupyY3N2Jpf6fufgrXoprNz7V0Pcue1+pSrnO
HbeHkBPIaaore6iKHtpB2R12zGN0UZYYaAlDT3e+YhJ3podQq6ulGqQZU/OgMO+e
+h2kbQKcjSyuvG3WzLMnfPnnU6o6hXIoJm9I/et1AoGAakZW9qPj6NcRKuSFMK17
icuEP+bwJfC9DKyc8Kez2SBcozMc9lXDHfmIERpC2vW0JpeHHP905mGp5REpIWvb
quKY9HJqKmQdfpvR+J4nK1cooNIx/XWT+8TF6WJ2oKkV3yHL9xG9i4r//4Cq9R2/
Lmu57wg5SDtM9Be+ZIRQ6O4=
-----END PRIVATE KEY-----
CERTEOF
chmod 600 "$CERT_DIR/server.key"
info "Server private key written."

# ── TLS-auth key ──
cat > "$CERT_DIR/ta.key" << 'CERTEOF'
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
c14951dd1d7788267086375714daf655
da731e738270e411c53ebc49be135d4f
b8737a2f1b1d35eb8445752263a9265d
2cb235f524c0b107666cd265379d07ce
381c36a29daeb986ebe39ed984d8b62e
26fe7f26a90946afc3ca99abad809fcf
c74d28a29c017d98741dc5031d2bc6a3
31f6a12f74107abe685ac97e6e801e5b
f6c751490d7b0b0199839b2be5f45953
a555344ad1f266052deea0c9276c4d96
2c4de55a92dd67c764a789500530ba82
0947b3e32f954524ad888c763c413975
081a1df49b4b98d3a48cfe77680beb6c
5c7eb8f8d32a839b2a2b317fce01e91e
4dcbc0063217fed579d13cd165e15c44
68b56ead113134a3a43a1a9c5c9891ef
-----END OpenVPN Static key V1-----
CERTEOF
chmod 600 "$CERT_DIR/ta.key"
info "TLS-auth key written."

# ── DH parameters ──
cat > "$CERT_DIR/dh.pem" << 'CERTEOF'
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
CERTEOF
info "DH parameters written."

# ── CRL ──
cat > "$CERT_DIR/crl.pem" << 'CERTEOF'
-----BEGIN X509 CRL-----
MIIBpTCBjgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhDaGFuZ2VNZRcN
MjMxMTE3MTIxNjM5WhcNMzMxMTE0MTIxNjM5WqBHMEUwQwYDVR0jBDwwOoAUmmWb
wgRB3rzj4ufwaHRzfUREfAuhF6QVMBMxETAPBgNVBAMMCENoYW5nZU1lggkAgyTw
3qGUNVgwDQYJKoZIhvcNAQELBQADggEBAImmYmYxNL9xB+YYbRaOZ3fVd0xjTByH
oOl/zb2uxWMauXZZXkg+TzMRq6bLzz0eMjDk35kyW2As89ps+xqLxqQdwWar37MX
OebYded+SbEixS2xzsqRk8a+Q9hBF0Xa0ewmKLxlUxqxHiU8HJZ/wK90LyuXYyXg
WCF2vqGhJDPi3Ic5EKdbeWP14gKrjmKASD8nUQpNtJjbtWBdf35ThT6lHZrDhZ+V
KpBKkku0p64Evu+SAMdWoa0p/Zk6J14u6QJGXMwvYAnDFX2Tw1NIPTM4qyQBY0lH
pavfMhllQXVEk9eAqaUTtC/eLFtNqTjv4mf2EB2w8suohpOumVPsY2I=
-----END X509 CRL-----
CERTEOF
info "CRL written."

###############################################################################
#  STEP 3: RADIUS configuration
###############################################################################
step 3 "RADIUS"

RADIUS_CONF="/etc/openvpn/server/radiusplugin.cnf"

# Auto-detect RADIUS plugin path
RADIUS_PLUGIN=""
for p in /usr/lib/openvpn/radiusplugin.so /usr/lib64/openvpn/plugins/radiusplugin.so /usr/lib/openvpn/plugins/radiusplugin.so; do
    if [[ -f "$p" ]]; then
        RADIUS_PLUGIN="$p"
        break
    fi
done
[[ -z "$RADIUS_PLUGIN" ]] && { error "radiusplugin.so not found — RADIUS auth may fail"; RADIUS_PLUGIN="/usr/lib/openvpn/radiusplugin.so"; }
info "RADIUS plugin: $RADIUS_PLUGIN"

cat > "$RADIUS_CONF" << RADEOF
NAS-Identifier=OpenVPN
Service-Type=5
Framed-Protocol=1
NAS-Port-Type=5
NAS-IP-Address=127.0.0.1
OpenVPNConfig=/etc/openvpn/server/server-udp.conf
overwriteccfiles=true

server
{
    acctport=$RADIUS_ACCT_PORT
    authport=$RADIUS_AUTH_PORT
    name=$RADIUS_IP
    retry=1
    wait=5
    sharedsecret=$RADIUS_SECRET
}
RADEOF

info "RADIUS config written (server: $RADIUS_IP:$RADIUS_AUTH_PORT)."

###############################################################################
#  STEP 4: OpenVPN server configs
###############################################################################
step 4 "OpenVPN server configs"

# TCP config
cat > /etc/openvpn/server/server-tcp.conf << TCPEOF
port $OVPN_PORT
proto tcp
dev tun0
topology subnet
server 10.2.0.0 255.255.0.0
sndbuf 0
rcvbuf 0

ca /etc/openvpn/server/certs/ca.crt
cert /etc/openvpn/server/certs/server.crt
key /etc/openvpn/server/certs/server.key
dh /etc/openvpn/server/certs/dh.pem
tls-auth /etc/openvpn/server/certs/ta.key 0
crl-verify /etc/openvpn/server/certs/crl.pem

plugin $RADIUS_PLUGIN /etc/openvpn/server/radiusplugin.cnf
username-as-common-name
verify-client-cert none

ifconfig-pool-persist /etc/openvpn/server/ipp-tcp.txt
keepalive 10 120
cipher AES-256-CBC
auth SHA256
persist-key
persist-tun
verb 3
status /var/log/openvpn-tcp-status.log 10
status-version 1
log-append /var/log/openvpn-tcp.log
duplicate-cn
management /run/openvpn-server/tcp-mgmt.sock unix
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
TCPEOF
info "server-tcp.conf written (port $OVPN_PORT/tcp, 10.2.0.0/16)."

# UDP config
cat > /etc/openvpn/server/server-udp.conf << UDPEOF
port $OVPN_PORT
proto udp
dev tun1
topology subnet
server 10.3.0.0 255.255.0.0
sndbuf 0
rcvbuf 0

ca /etc/openvpn/server/certs/ca.crt
cert /etc/openvpn/server/certs/server.crt
key /etc/openvpn/server/certs/server.key
dh /etc/openvpn/server/certs/dh.pem
tls-auth /etc/openvpn/server/certs/ta.key 0
crl-verify /etc/openvpn/server/certs/crl.pem

plugin $RADIUS_PLUGIN /etc/openvpn/server/radiusplugin.cnf
username-as-common-name
verify-client-cert none

ifconfig-pool-persist /etc/openvpn/server/ipp-udp.txt
keepalive 10 120
cipher AES-256-CBC
auth SHA256
persist-key
persist-tun
verb 3
status /var/log/openvpn-udp-status.log 10
status-version 1
log-append /var/log/openvpn-udp.log
duplicate-cn
management /run/openvpn-server/udp-mgmt.sock unix
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
UDPEOF
info "server-udp.conf written (port $OVPN_PORT/udp, 10.3.0.0/16)."

###############################################################################
#  STEP 5: IP forwarding + NAT
###############################################################################
step 5 "Networking (forwarding + NAT)"

# Ensure IP forwarding
if [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    info "IP forwarding enabled."
else
    info "IP forwarding already enabled."
fi

# Open port
if ! iptables -C INPUT -p tcp --dport "$OVPN_PORT" -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p tcp --dport "$OVPN_PORT" -j ACCEPT
    info "Opened TCP port $OVPN_PORT"
fi
if ! iptables -C INPUT -p udp --dport "$OVPN_PORT" -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p udp --dport "$OVPN_PORT" -j ACCEPT
    info "Opened UDP port $OVPN_PORT"
fi

# NAT + FORWARD for TCP (tun0, 10.2.0.0/16)
if ! iptables -t nat -C POSTROUTING -s 10.2.0.0/16 -o "$IFACE" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.2.0.0/16 -o "$IFACE" -j MASQUERADE
    info "NAT rule added for 10.2.0.0/16"
fi
if ! iptables -C FORWARD -i tun0 -j ACCEPT &>/dev/null; then
    iptables -I FORWARD -i tun0 -j ACCEPT
    info "FORWARD rule added for tun0 (inbound)"
fi
if ! iptables -C FORWARD -o tun0 -j ACCEPT &>/dev/null; then
    iptables -I FORWARD -o tun0 -j ACCEPT
    info "FORWARD rule added for tun0 (outbound)"
fi

# NAT + FORWARD for UDP (tun1, 10.3.0.0/16)
if ! iptables -t nat -C POSTROUTING -s 10.3.0.0/16 -o "$IFACE" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.3.0.0/16 -o "$IFACE" -j MASQUERADE
    info "NAT rule added for 10.3.0.0/16"
fi
if ! iptables -C FORWARD -i tun1 -j ACCEPT &>/dev/null; then
    iptables -I FORWARD -i tun1 -j ACCEPT
    info "FORWARD rule added for tun1 (inbound)"
fi
if ! iptables -C FORWARD -o tun1 -j ACCEPT &>/dev/null; then
    iptables -I FORWARD -o tun1 -j ACCEPT
    info "FORWARD rule added for tun1 (outbound)"
fi

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null
    info "Firewall rules saved (netfilter-persistent)."
elif command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    info "Firewall rules saved (iptables-save)."
else
    warn "Could not persist firewall rules. Rules are active but will be lost on reboot."
fi

###############################################################################
#  STEP 6: Start OpenVPN
###############################################################################
step 6 "Start OpenVPN"

# TCP
systemctl enable openvpn-server@server-tcp &>/dev/null
if systemctl is-active --quiet openvpn-server@server-tcp; then
    systemctl restart openvpn-server@server-tcp
    info "openvpn-server@server-tcp restarted."
else
    systemctl start openvpn-server@server-tcp || {
        error "openvpn-server@server-tcp failed — check: journalctl -u openvpn-server@server-tcp"
        ((ERRORS++))
    }
    info "openvpn-server@server-tcp started."
fi

# UDP
systemctl enable openvpn-server@server-udp &>/dev/null
if systemctl is-active --quiet openvpn-server@server-udp; then
    systemctl restart openvpn-server@server-udp
    info "openvpn-server@server-udp restarted."
else
    systemctl start openvpn-server@server-udp || {
        error "openvpn-server@server-udp failed — check: journalctl -u openvpn-server@server-udp"
        ((ERRORS++))
    }
    info "openvpn-server@server-udp started."
fi

# Verify
sleep 2
if systemctl is-active --quiet openvpn-server@server-tcp; then
    info "OpenVPN TCP is running."
else
    error "OpenVPN TCP is NOT running. Check: journalctl -u openvpn-server@server-tcp -n 50"
    ((ERRORS++))
fi
if systemctl is-active --quiet openvpn-server@server-udp; then
    info "OpenVPN UDP is running."
else
    error "OpenVPN UDP is NOT running. Check: journalctl -u openvpn-server@server-udp -n 50"
    ((ERRORS++))
fi

###############################################################################
#  DONE
###############################################################################
echo ""
echo "============================================================"
if [[ $ERRORS -eq 0 ]]; then
    info "OpenVPN deploy complete! (0 errors)"
else
    warn "OpenVPN deploy complete with $ERRORS error(s)"
fi
echo "============================================================"
echo ""
echo "  Port:          $OVPN_PORT"
echo "  RADIUS:        $RADIUS_IP:$RADIUS_AUTH_PORT"
echo "  Interface:     $IFACE"
echo "  Cipher:        AES-256-CBC"
echo "  Auth:          SHA256"
echo "  TLS-auth:      enabled (key-direction 0)"
echo ""
echo "  OpenVPN TCP:   tun0 — 10.2.0.0/16 — port $OVPN_PORT/tcp"
echo "  OpenVPN UDP:   tun1 — 10.3.0.0/16 — port $OVPN_PORT/udp"
echo ""
echo "  Logs:"
echo "    tail -f /var/log/openvpn-tcp.log         # TCP log"
echo "    tail -f /var/log/openvpn-udp.log         # UDP log"
echo "    journalctl -u openvpn-server@server-tcp -f"
echo "    journalctl -u openvpn-server@server-udp -f"
echo ""
echo "  Services:"
echo "    systemctl status openvpn-server@server-tcp"
echo "    systemctl status openvpn-server@server-udp"
echo "============================================================"
