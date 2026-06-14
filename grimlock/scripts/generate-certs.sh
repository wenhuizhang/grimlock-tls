#!/bin/bash
# Generate mTLS certificates for Grimlock agents
# Creates a CA and agent certificates for testing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../certs"

# Certificate validity (days)
CA_DAYS=3650
CERT_DAYS=365

# Default agent names
AGENTS=("agent-a" "agent-b")

log_info() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate CA
generate_ca() {
    log_info "Generating Certificate Authority..."
    
    # CA private key
    openssl genrsa -out ca.key 4096
    
    # CA certificate
    openssl req -new -x509 -days $CA_DAYS -key ca.key -out ca.crt \
        -subj "/C=US/ST=California/L=San Francisco/O=Grimlock/OU=Security/CN=Grimlock CA"
    
    log_info "✓ CA created: ca.crt, ca.key"
}

# Generate agent certificate
generate_agent_cert() {
    local agent_name="$1"
    local agent_ip="${2:-}"
    
    log_info "Generating certificate for: $agent_name"
    
    # Generate private key
    openssl genrsa -out "${agent_name}.key" 2048
    
    # Create CSR config with SAN
    cat > "${agent_name}.cnf" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = California
L = San Francisco
O = Grimlock
OU = Agents
CN = ${agent_name}

[req_ext]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = ${agent_name}
DNS.2 = ${agent_name}.local
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

    # Add custom IP if provided
    if [[ -n "$agent_ip" ]]; then
        echo "IP.2 = ${agent_ip}" >> "${agent_name}.cnf"
    fi

    # Generate CSR
    openssl req -new -key "${agent_name}.key" -out "${agent_name}.csr" \
        -config "${agent_name}.cnf"
    
    # Sign with CA
    openssl x509 -req -in "${agent_name}.csr" -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out "${agent_name}.crt" -days $CERT_DAYS \
        -extensions req_ext -extfile "${agent_name}.cnf"
    
    # Cleanup CSR and config
    rm -f "${agent_name}.csr" "${agent_name}.cnf"
    
    log_info "✓ Agent cert created: ${agent_name}.crt, ${agent_name}.key"
}

# Verify certificate
verify_cert() {
    local agent_name="$1"
    
    log_info "Verifying ${agent_name} certificate..."
    openssl verify -CAfile ca.crt "${agent_name}.crt"
}

# Print certificate info
print_cert_info() {
    local agent_name="$1"
    
    echo ""
    echo "Certificate: ${agent_name}.crt"
    echo "---"
    openssl x509 -in "${agent_name}.crt" -noout -subject -issuer -dates
    echo ""
}

# Generate combined PEM (key + cert) for convenience
generate_combined() {
    local agent_name="$1"
    
    cat "${agent_name}.key" "${agent_name}.crt" > "${agent_name}.pem"
    chmod 600 "${agent_name}.pem"
    log_info "✓ Combined PEM: ${agent_name}.pem"
}

# Main
main() {
    echo "=============================================="
    echo "     Grimlock Certificate Generator"
    echo "=============================================="
    echo ""
    echo "Output directory: $CERT_DIR"
    echo ""
    
    # Parse arguments
    local custom_agents=()
    local custom_ips=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --agent)
                custom_agents+=("$2")
                shift 2
                ;;
            --ip)
                custom_ips+=("$2")
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Usage: $0 [--agent name [--ip ip]]..."
                exit 1
                ;;
        esac
    done
    
    # Use custom agents if provided, otherwise defaults
    if [[ ${#custom_agents[@]} -gt 0 ]]; then
        AGENTS=("${custom_agents[@]}")
    fi
    
    # Generate CA if it doesn't exist
    if [[ ! -f ca.crt ]]; then
        generate_ca
    else
        log_info "CA already exists, skipping..."
    fi
    
    echo ""
    
    # Generate agent certificates
    for i in "${!AGENTS[@]}"; do
        agent="${AGENTS[$i]}"
        ip="${custom_ips[$i]:-}"
        generate_agent_cert "$agent" "$ip"
        verify_cert "$agent"
        generate_combined "$agent"
    done
    
    echo ""
    echo "=============================================="
    echo "         Certificates Generated"
    echo "=============================================="
    echo ""
    echo "Files created in: $CERT_DIR"
    ls -la "$CERT_DIR"
    echo ""
    echo "To use these certificates:"
    echo "  1. Copy ca.crt to all agents (for verification)"
    echo "  2. Copy agent-specific .key and .crt to each agent"
    echo ""
    echo "Example deployment:"
    echo "  Host A: ca.crt, agent-a.key, agent-a.crt"
    echo "  Host B: ca.crt, agent-b.key, agent-b.crt"
    echo ""
}

main "$@"
