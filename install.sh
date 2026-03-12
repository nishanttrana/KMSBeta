#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SOURCE_DIR}"
DEPLOY_DIR=""
COMPOSE_FILE=""
OVERRIDE_FILE=""
ENV_FILE=""
PARSER_SCRIPT=""

DEPLOYMENT_FILE=""
NETWORK_FILE=""
FIPS_FILE=""
FDE_FILE=""
AUTH_FILE=""

SUDO=""
DOCKER_BIN=(docker)
HOST_OS="linux"
STEP_INDEX=0
STEP_TOTAL=19
INSTALL_WARNINGS=()
INSTALL_MODE="interactive"

FEATURE_KEYS=(
  secrets
  certs
  governance
  cloud_byok
  hyok_proxy
  kmip_server
  qkd_interface
  qrng_generator
  ekm_database
  payment_crypto
  compliance_dashboard
  sbom_cbom
  reporting_alerting
  posture_management
  ai_llm
  pqc_migration
  crypto_discovery
  mpc_engine
  data_protection
  clustering
)

log() { printf "\n[%s] %s\n" "$1" "$2"; }
info() { log "INFO" "$1"; }
warn() { log "WARN" "$1"; }
die() { log "ERROR" "$1"; exit 1; }
add_warning() {
  local msg="$1"
  INSTALL_WARNINGS+=("${msg}")
  warn "${msg}"
}
step() {
  STEP_INDEX=$((STEP_INDEX + 1))
  info "Step ${STEP_INDEX}/${STEP_TOTAL}: $1"
}

require_modern_bash() {
  if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    die "Bash 4+ is required. On macOS install a newer bash (for example via Homebrew). On Windows use Git Bash or WSL."
  fi
}

detect_cpu_count() {
  local cpus="2"
  if command -v nproc >/dev/null 2>&1; then
    cpus="$(nproc 2>/dev/null || echo 2)"
  elif command -v getconf >/dev/null 2>&1; then
    cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
  fi
  [[ "${cpus}" =~ ^[0-9]+$ ]] || cpus="2"
  (( cpus < 1 )) && cpus=1
  printf "%s" "${cpus}"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf "%s" "$value"
}

yaml_quote() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf "\"%s\"" "$s"
}

emit_yaml_list() {
  local indent="$1"
  shift
  local pad
  pad="$(printf "%*s" "${indent}" "")"
  if [[ "$#" -eq 0 ]]; then
    printf "%s[]\n" "${pad}"
    return
  fi
  local item
  for item in "$@"; do
    printf "%s- %s\n" "${pad}" "$(yaml_quote "${item}")"
  done
}

as_root() {
  if [[ -n "${SUDO}" ]]; then
    "${SUDO}" "$@"
  else
    "$@"
  fi
}

set_project_paths() {
  ROOT_DIR="$1"
  DEPLOY_DIR="${ROOT_DIR}/infra/deployment"
  COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
  OVERRIDE_FILE="${ROOT_DIR}/docker-compose.override.yml"
  ENV_FILE="${ROOT_DIR}/.env"
  PARSER_SCRIPT="${ROOT_DIR}/infra/scripts/parse-deployment.sh"
  DEPLOYMENT_FILE="${DEPLOY_DIR}/deployment.yaml"
  NETWORK_FILE="${DEPLOY_DIR}/network.yaml"
  FIPS_FILE="${DEPLOY_DIR}/fips.yaml"
  FDE_FILE="${DEPLOY_DIR}/fde.yaml"
  AUTH_FILE="${DEPLOY_DIR}/auth-bootstrap.yaml"
}

prompt_default() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="$3"
  local current_value="${!var_name-}"
  if [[ -n "${current_value}" ]]; then
    printf -v "${var_name}" "%s" "$(trim "${current_value}")"
    return
  fi
  local input_value=""
  read -r -p "${prompt_text} [${default_value}]: " input_value || true
  input_value="$(trim "${input_value}")"
  if [[ -z "${input_value}" ]]; then
    printf -v "${var_name}" "%s" "${default_value}"
  else
    printf -v "${var_name}" "%s" "${input_value}"
  fi
}

prompt_secret() {
  local var_name="$1"
  local prompt_text="$2"
  local current_value="${!var_name-}"
  if [[ -n "${current_value}" ]]; then
    if [[ "${#current_value}" -lt 12 ]]; then
      die "${var_name} must be at least 12 characters when pre-set."
    fi
    printf -v "${var_name}" "%s" "${current_value}"
    return
  fi
  local first=""
  local second=""
  while true; do
    read -r -s -p "${prompt_text}: " first
    echo
    read -r -s -p "Confirm ${prompt_text}: " second
    echo
    if [[ "${first}" != "${second}" ]]; then
      warn "Values do not match. Try again."
      continue
    fi
    if [[ "${#first}" -lt 12 ]]; then
      warn "Password must be at least 12 characters."
      continue
    fi
    printf -v "${var_name}" "%s" "${first}"
    break
  done
}

prompt_yes_no() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="$3"
  local current_value="${!var_name-}"
  if [[ -n "${current_value}" ]]; then
    current_value="${current_value,,}"
    case "${current_value}" in
      y|yes|true|n|no|false|1|0|on|off)
        if [[ "${current_value}" == "y" || "${current_value}" == "yes" || "${current_value}" == "true" || "${current_value}" == "1" || "${current_value}" == "on" ]]; then
          printf -v "${var_name}" "true"
        else
          printf -v "${var_name}" "false"
        fi
        return
        ;;
      *)
        die "Invalid pre-set boolean for ${var_name}: ${current_value}"
        ;;
    esac
  fi
  local default_hint="Y/n"
  local input=""
  local normalized_default="true"

  if [[ "${default_value}" == "false" ]]; then
    default_hint="y/N"
    normalized_default="false"
  fi

  while true; do
    read -r -p "${prompt_text} (${default_hint}): " input || true
    input="$(trim "${input}")"
    input="${input,,}"
    if [[ -z "${input}" ]]; then
      printf -v "${var_name}" "%s" "${normalized_default}"
      return
    fi
    case "${input}" in
      y|yes|true)
        printf -v "${var_name}" "true"
        return
        ;;
      n|no|false)
        printf -v "${var_name}" "false"
        return
        ;;
      *)
        warn "Please answer yes or no."
        ;;
    esac
  done
}

generate_random_secret() {
  local length="${1:-48}"
  local secret=""
  if command -v openssl >/dev/null 2>&1; then
    secret="$(openssl rand -base64 96 2>/dev/null | tr -d '\r\n' | cut -c1-"${length}")"
  fi
  if [[ -z "${secret}" ]]; then
    if [[ -r /dev/urandom ]]; then
      secret="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${length}" || true)"
    fi
  fi
  if [[ -z "${secret}" ]]; then
    die "Unable to auto-generate secure secret. Install openssl or provide a manual bootstrap passphrase."
  fi
  printf "%s" "${secret}"
}

split_csv_to_array() {
  local csv="$1"
  local arr_name="$2"
  local -a parsed=()
  local raw
  IFS=',' read -r -a raw <<< "${csv}"
  local entry
  for entry in "${raw[@]}"; do
    entry="$(trim "${entry}")"
    [[ -n "${entry}" ]] && parsed+=("${entry}")
  done
  if [[ "${#parsed[@]}" -eq 0 ]]; then
    parsed=("pool.ntp.org")
  fi
  eval "${arr_name}"='("${parsed[@]}")'
}

validate_ipv4_cidr() {
  local value="$1"
  [[ "${value}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]
}

validate_ipv4() {
  local value="$1"
  [[ "${value}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

ensure_linux() {
  local forced
  forced="$(trim "${INSTALLER_FORCE_HOST_OS:-}")"
  case "${forced}" in
    linux|macos|windows)
      HOST_OS="${forced}"
      return
      ;;
    "")
      ;;
    *)
      die "Invalid INSTALLER_FORCE_HOST_OS value: ${forced}. Expected linux, macos, or windows."
      ;;
  esac

  local os
  os="$(uname -s 2>/dev/null || echo "")"
  case "${os}" in
    Linux)
      HOST_OS="linux"
      ;;
    Darwin)
      HOST_OS="macos"
      ;;
    MINGW*|MSYS*|CYGWIN*)
      HOST_OS="windows"
      ;;
    *)
      die "Unsupported host OS: ${os}. Supported installers are Linux (install.sh), macOS (install-macos.sh), or Windows via install-windows.ps1."
      ;;
  esac
}

setup_sudo() {
  if [[ "${HOST_OS}" != "linux" ]]; then
    SUDO=""
    return
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "sudo is required when running as non-root user."
    SUDO="sudo"
  fi
}

check_workspace_permissions() {
  [[ -r "${COMPOSE_FILE}" ]] || die "Cannot read ${COMPOSE_FILE}."
  [[ -w "${ROOT_DIR}" ]] || die "No write permission on ${ROOT_DIR}. Run with a writable user."
  mkdir -p "${DEPLOY_DIR}"
  local probe_file="${DEPLOY_DIR}/.install-perm-check"
  : > "${probe_file}" || die "No write permission on ${DEPLOY_DIR}."
  rm -f "${probe_file}" || true
}

ensure_dockerignore_safety() {
  local ignore_file="${ROOT_DIR}/.dockerignore"
  touch "${ignore_file}" || die "Cannot update ${ignore_file}"

  local -a default_excludes=(
    "lost+found"
    "*/lost+found"
    ".Trash-*"
    "System Volume Information"
  )
  local entry
  for entry in "${default_excludes[@]}"; do
    if ! grep -Fxq "${entry}" "${ignore_file}" 2>/dev/null; then
      echo "${entry}" >> "${ignore_file}"
    fi
  done

  # Exclude unreadable top-level paths so docker build context packaging does not fail.
  local p rel
  while IFS= read -r p; do
    rel="${p#${ROOT_DIR}/}"
    [[ -z "${rel}" || "${rel}" == "." ]] && continue
    if ! grep -Fxq "${rel}" "${ignore_file}" 2>/dev/null; then
      echo "${rel}" >> "${ignore_file}"
      add_warning "Added unreadable path '${rel}' to .dockerignore."
    fi
  done < <(find "${ROOT_DIR}" -mindepth 1 -maxdepth 1 ! -readable -print 2>/dev/null || true)
}

port_conflicts_for_bind() {
  local bind_ip="$1"
  local port="$2"
  local proto="$3"

  if [[ "${HOST_OS}" == "windows" ]]; then
    command -v powershell.exe >/dev/null 2>&1 || return 1
    local ps_script out
    ps_script=$(cat <<EOF
\$port = ${port}
\$bind = '${bind_ip//\'/''}'
\$hits = @()
if ('${proto}' -eq 'udp') {
  \$hits = @(Get-NetUDPEndpoint -LocalPort \$port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalAddress)
} else {
  \$hits = @(Get-NetTCPConnection -State Listen -LocalPort \$port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalAddress)
}
foreach (\$ip in \$hits) {
  if ([string]::IsNullOrWhiteSpace(\$ip)) { continue }
  if (\$bind -eq '0.0.0.0' -or \$bind -eq '::' -or \$ip -eq '0.0.0.0' -or \$ip -eq '::' -or \$ip -eq '*' -or \$ip -eq \$bind) {
    'conflict'
    break
  }
}
EOF
)
    out="$(powershell.exe -NoProfile -NonInteractive -Command "${ps_script}" 2>/dev/null | tr -d '\r' || true)"
    [[ "${out}" == *conflict* ]] && return 0
    return 1
  fi

  if [[ "${HOST_OS}" == "macos" ]]; then
    command -v lsof >/dev/null 2>&1 || return 1
    local out=""
    if [[ "${proto}" == "udp" ]]; then
      out="$(lsof -nP -iUDP:${port} -Fn 2>/dev/null | sed -n 's/^n//p' || true)"
    else
      out="$(lsof -nP -iTCP:${port} -sTCP:LISTEN -Fn 2>/dev/null | sed -n 's/^n//p' || true)"
    fi
    [[ -z "${out}" ]] && return 1

    if [[ "${bind_ip}" == "0.0.0.0" || "${bind_ip}" == "::" ]]; then
      return 0
    fi

    local entry addr
    while IFS= read -r entry; do
      [[ -z "${entry}" ]] && continue
      addr="${entry%%:*}"
      addr="${addr#[}"
      addr="${addr%]}"
      case "${addr}" in
        "*"|"0.0.0.0"|"::")
          return 0
          ;;
      esac
      if [[ "${addr}" == "${bind_ip}" ]]; then
        return 0
      fi
    done <<< "${out}"
    return 1
  fi

  command -v ss >/dev/null 2>&1 || return 1

  local out=""
  if [[ "${proto}" == "udp" ]]; then
    out="$(ss -H -lun "( sport = :${port} )" 2>/dev/null || true)"
  else
    out="$(ss -H -ltn "( sport = :${port} )" 2>/dev/null || true)"
  fi
  [[ -z "${out}" ]] && return 1

  if [[ "${bind_ip}" == "0.0.0.0" || "${bind_ip}" == "::" ]]; then
    return 0
  fi

  local line local_field addr
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    local_field="$(awk '{print $4}' <<< "${line}")"
    [[ -z "${local_field}" ]] && continue
    addr="${local_field%:*}"
    addr="${addr#[}"
    addr="${addr%]}"
    addr="${addr%%\%*}"
    case "${addr}" in
      "*"|"0.0.0.0"|"::")
        return 0
        ;;
    esac
    if [[ "${addr}" == "${bind_ip}" ]]; then
      return 0
    fi
  done <<< "${out}"

  return 1
}

install_prerequisites() {
  info "Checking dependencies (Docker + Compose + basic tools)..."

  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    info "Docker and Docker Compose plugin already present."
    return
  fi
  if [[ "${HOST_OS}" == "windows" ]] && command -v docker.exe >/dev/null 2>&1 && docker.exe compose version >/dev/null 2>&1; then
    info "Docker Desktop CLI already present."
    return
  fi

  if [[ "${HOST_OS}" == "macos" ]]; then
    die "Docker is not available. Install Docker Desktop for macOS, then re-run this installer."
  fi
  if [[ "${HOST_OS}" == "windows" ]]; then
    die "Docker is not available. Install Docker Desktop for Windows and ensure docker compose works in your shell."
  fi

  if command -v apt-get >/dev/null 2>&1; then
    info "Installing Docker on Debian/Ubuntu..."
    as_root apt-get update
    as_root apt-get install -y ca-certificates curl gnupg lsb-release jq openssl
    as_root install -m 0755 -d /etc/apt/keyrings
    if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
      local distro_id
      distro_id="$(. /etc/os-release; echo "${ID}")"
      if [[ "${distro_id}" != "ubuntu" && "${distro_id}" != "debian" ]]; then
        distro_id="ubuntu"
      fi
      curl -fsSL "https://download.docker.com/linux/${distro_id}/gpg" \
        | as_root gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      as_root chmod a+r /etc/apt/keyrings/docker.gpg
    fi
    local arch codename repo_id
    arch="$(dpkg --print-architecture)"
    codename="$(. /etc/os-release; echo "${VERSION_CODENAME}")"
    repo_id="$(. /etc/os-release; echo "${ID}")"
    if [[ "${repo_id}" != "ubuntu" && "${repo_id}" != "debian" ]]; then
      repo_id="ubuntu"
    fi
    cat <<EOF | as_root tee /etc/apt/sources.list.d/docker.list >/dev/null
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${repo_id} ${codename} stable
EOF
    as_root apt-get update
    as_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    as_root systemctl enable --now docker
  elif command -v dnf >/dev/null 2>&1; then
    info "Installing Docker on RHEL-compatible Linux (dnf)..."
    as_root dnf -y install dnf-plugins-core curl jq openssl
    local repo_os
    repo_os="$(. /etc/os-release; echo "${ID}")"
    case "${repo_os}" in
      rocky|almalinux|centos|rhel|ol) repo_os="centos" ;;
    esac
    as_root dnf config-manager --add-repo "https://download.docker.com/linux/${repo_os}/docker-ce.repo"
    as_root dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    as_root systemctl enable --now docker
  elif command -v yum >/dev/null 2>&1; then
    info "Installing Docker on RHEL-compatible Linux (yum)..."
    as_root yum -y install yum-utils curl jq openssl
    local repo_os
    repo_os="$(. /etc/os-release; echo "${ID}")"
    case "${repo_os}" in
      rocky|almalinux|centos|rhel|ol) repo_os="centos" ;;
    esac
    as_root yum-config-manager --add-repo "https://download.docker.com/linux/${repo_os}/docker-ce.repo"
    as_root yum -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    as_root systemctl enable --now docker
  else
    die "Unsupported package manager. Supported: apt, dnf, yum."
  fi

  if [[ "${EUID}" -ne 0 ]]; then
    as_root usermod -aG docker "${USER}" || true
  fi
}

setup_docker_command() {
  if docker info >/dev/null 2>&1; then
    DOCKER_BIN=(docker)
    return
  fi
  if [[ "${HOST_OS}" == "windows" ]] && command -v docker.exe >/dev/null 2>&1 && docker.exe info >/dev/null 2>&1; then
    DOCKER_BIN=(docker.exe)
    return
  fi
  if [[ -n "${SUDO}" ]] && sudo docker info >/dev/null 2>&1; then
    DOCKER_BIN=(sudo docker)
    return
  fi
  die "Docker daemon is not reachable. Re-run after Docker starts."
}

wait_for_docker() {
  local max_wait=90
  local start
  start="$(date +%s)"
  until "${DOCKER_BIN[@]}" info >/dev/null 2>&1; do
    if (( "$(date +%s)" - start > max_wait )); then
      die "Docker daemon was not reachable after ${max_wait}s."
    fi
    sleep 2
  done
}

compose_exec() {
  "${DOCKER_BIN[@]}" compose -f "${COMPOSE_FILE}" -f "${OVERRIDE_FILE}" "$@"
}

docker_image_exists() {
  local image_ref="$1"
  "${DOCKER_BIN[@]}" image inspect "${image_ref}" >/dev/null 2>&1
}

adjust_unsupported_profiles() {
  if [[ "${CLUSTER_DEPLOYMENT_MODE:-standalone}" != "standalone" ]]; then
    FEATURE_clustering="true"
  fi

  if [[ "${FEATURE_clustering:-false}" == "true" ]]; then
    if [[ "${BUILD_MODE:-build-missing}" == "no-build" ]] && ! docker_image_exists "vecta/cluster:latest"; then
      add_warning "clustering requested but image vecta/cluster:latest is unavailable. Disabling clustering and mpc_engine."
      FEATURE_clustering="false"
      FEATURE_mpc_engine="false"
    fi
  fi

  # hardware connector is also image-only. Fall back to software mode if unavailable.
  if [[ "${HSM_MODE}" == "hardware" || "${HSM_MODE}" == "auto" ]]; then
    if ! docker_image_exists "vecta/hsm-connector:latest"; then
      add_warning "hardware HSM connector image (vecta/hsm-connector:latest) unavailable. Falling back to software HSM mode."
      HSM_MODE="software"
    fi
  fi
}

configure_build_runtime() {
  export COMPOSE_DOCKER_CLI_BUILD=1
  export DOCKER_BUILDKIT=1
  export COMPOSE_PARALLEL_LIMIT="${BUILD_PARALLEL_LIMIT}"
  info "Build runtime: mode=${BUILD_MODE}, parallel_limit=${COMPOSE_PARALLEL_LIMIT}, buildkit=${DOCKER_BUILDKIT}"
}

load_image_bundle_if_requested() {
  if [[ -z "${IMAGE_BUNDLE_PATH}" ]]; then
    return
  fi
  local bundle="${IMAGE_BUNDLE_PATH}"
  if [[ "${bundle}" != /* ]]; then
    bundle="${ROOT_DIR}/${bundle}"
  fi
  [[ -f "${bundle}" ]] || die "Image bundle file not found: ${bundle}"
  info "Loading prebuilt images from ${bundle} ..."
  "${DOCKER_BIN[@]}" load -i "${bundle}"
}

detect_default_route_interface() {
  case "${HOST_OS}" in
    linux)
      if ! command -v ip >/dev/null 2>&1; then
        return 0
      fi
      ip -o -4 route show default 2>/dev/null \
        | awk '{for (i=1;i<=NF;i++) if ($i=="dev" && i+1<=NF) {print $(i+1); exit}}' \
        || true
      ;;
    macos)
      route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}' || true
      ;;
    windows)
      powershell.exe -NoProfile -NonInteractive -Command "(Get-NetIPConfiguration | Where-Object { \$_.IPv4DefaultGateway -ne \$null -and \$_.IPv4Address -ne \$null } | Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias)" 2>/dev/null | tr -d '\r'
      ;;
  esac
}

detect_default_gateway() {
  local iface="${1:-}"
  case "${HOST_OS}" in
    linux)
      if ! command -v ip >/dev/null 2>&1; then
        return 0
      fi
      if [[ -n "${iface}" ]]; then
        ip -o -4 route show default dev "${iface}" 2>/dev/null \
          | awk '{for (i=1;i<=NF;i++) if ($i=="via" && i+1<=NF) {print $(i+1); exit}}' \
          || true
        return 0
      fi
      ip -o -4 route show default 2>/dev/null \
        | awk '{for (i=1;i<=NF;i++) if ($i=="via" && i+1<=NF) {print $(i+1); exit}}' \
        || true
      ;;
    macos)
      route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}' || true
      ;;
    windows)
      if [[ -n "${iface}" ]]; then
        powershell.exe -NoProfile -NonInteractive -Command "\$cfg = Get-NetIPConfiguration -InterfaceAlias '${iface//\'/''}' -ErrorAction SilentlyContinue; if (\$cfg -and \$cfg.IPv4DefaultGateway) { \$cfg.IPv4DefaultGateway.NextHop }" 2>/dev/null | tr -d '\r'
      else
        powershell.exe -NoProfile -NonInteractive -Command "(Get-NetIPConfiguration | Where-Object { \$_.IPv4DefaultGateway -ne \$null -and \$_.IPv4Address -ne \$null } | Sort-Object InterfaceMetric | Select-Object -First 1).IPv4DefaultGateway.NextHop" 2>/dev/null | tr -d '\r'
      fi
      ;;
  esac
}

hex_netmask_to_cidr() {
  local mask="$1"
  mask="${mask#0x}"
  local value=0
  if [[ "${mask}" =~ ^[0-9A-Fa-f]{8}$ ]]; then
    value=$((16#${mask}))
  elif [[ "${mask}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    local IFS='.'
    local octet
    for octet in ${mask}; do
      value=$(( (value << 8) + octet ))
    done
  else
    printf "%s" "24"
    return
  fi

  local bits=0
  while (( value > 0 )); do
    (( bits += value & 1 ))
    (( value >>= 1 ))
  done
  printf "%s" "${bits}"
}

detect_interface_ipv4_cidr() {
  local iface="$1"
  local out=""
  case "${HOST_OS}" in
    linux)
      if ! command -v ip >/dev/null 2>&1 || [[ -z "${iface}" ]]; then
        return 0
      fi
      out="$(ip -o -4 addr show dev "${iface}" scope global 2>/dev/null | awk '{print $4; exit}')" || true
      if [[ -z "${out}" ]]; then
        out="$(ip -o -4 addr show dev "${iface}" 2>/dev/null | awk '{print $4; exit}')" || true
      fi
      printf "%s" "${out}"
      ;;
    macos)
      [[ -n "${iface}" ]] || return 0
      local ip_addr netmask prefix
      ip_addr="$(ipconfig getifaddr "${iface}" 2>/dev/null || true)"
      [[ -n "${ip_addr}" ]] || return 0
      netmask="$(ifconfig "${iface}" 2>/dev/null | awk '/inet /{for(i=1;i<=NF;i++) if($i=="netmask") {print $(i+1); exit}}' || true)"
      prefix="$(hex_netmask_to_cidr "${netmask}")"
      printf "%s/%s" "${ip_addr}" "${prefix}"
      ;;
    windows)
      [[ -n "${iface}" ]] || return 0
      powershell.exe -NoProfile -NonInteractive -Command "\$cfg = Get-NetIPConfiguration -InterfaceAlias '${iface//\'/''}' -ErrorAction SilentlyContinue; if (\$cfg -and \$cfg.IPv4Address) { \$addr = \$cfg.IPv4Address | Select-Object -First 1; '\{0}/\{1}' -f \$addr.IPAddress, \$addr.PrefixLength }" 2>/dev/null | tr -d '\r'
      ;;
  esac
}

detect_primary_ip_cidr() {
  local iface=""
  iface="$(detect_default_route_interface)"
  detect_interface_ipv4_cidr "${iface}"
}

is_valid_ipv4() {
  local ip="$1"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

detect_default_dns_csv() {
  local -A seen=()
  local -a dns=()
  local candidate=""

  if [[ "${HOST_OS}" == "windows" ]]; then
    powershell.exe -NoProfile -NonInteractive -Command "\$cfg = Get-NetIPConfiguration | Where-Object { \$_.IPv4DefaultGateway -ne \$null -and \$_.IPv4Address -ne \$null } | Sort-Object InterfaceMetric | Select-Object -First 1; if (\$cfg -and \$cfg.DNSServer) { (\$cfg.DNSServer.ServerAddresses | Where-Object { \$_ -match '^[0-9]+\.' }) -join ',' }" 2>/dev/null | tr -d '\r'
    return 0
  fi

  if [[ "${HOST_OS}" == "macos" ]]; then
    while read -r candidate; do
      candidate="$(trim "${candidate}")"
      if is_valid_ipv4 "${candidate}" && [[ -z "${seen[${candidate}]:-}" ]]; then
        seen["${candidate}"]=1
        dns+=("${candidate}")
      fi
    done < <(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\] :/ {print $3}')
  fi

  if command -v resolvectl >/dev/null 2>&1; then
    while read -r candidate; do
      candidate="$(trim "${candidate}")"
      if is_valid_ipv4 "${candidate}" && [[ -z "${seen[${candidate}]:-}" ]]; then
        seen["${candidate}"]=1
        dns+=("${candidate}")
      fi
    done < <(resolvectl dns 2>/dev/null | awk '{for (i=2; i<=NF; i++) print $i}')
  fi

  if [[ "${#dns[@]}" -eq 0 && -r /etc/resolv.conf ]]; then
    while read -r candidate; do
      candidate="$(trim "${candidate}")"
      if is_valid_ipv4 "${candidate}" && [[ "${candidate}" != 127.* ]] && [[ -z "${seen[${candidate}]:-}" ]]; then
        seen["${candidate}"]=1
        dns+=("${candidate}")
      fi
    done < <(awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null)
  fi

  if [[ "${#dns[@]}" -eq 0 ]]; then
    printf "%s" ""
    return 0
  fi

  local csv=""
  local idx
  for idx in "${!dns[@]}"; do
    if [[ "${idx}" -eq 0 ]]; then
      csv="${dns[$idx]}"
    else
      csv="${csv},${dns[$idx]}"
    fi
  done
  printf "%s" "${csv}"
}

normalize_host_path() {
  local path="$1"
  case "${HOST_OS}" in
    windows)
      if [[ "${path}" =~ ^[A-Za-z]:[\\/].* ]]; then
        if command -v cygpath >/dev/null 2>&1; then
          cygpath -u "${path}"
          return
        fi
        if command -v wslpath >/dev/null 2>&1; then
          wslpath -a "${path}"
          return
        fi
      fi
      ;;
  esac
  printf "%s" "${path}"
}

docker_mount_source_path() {
  local path="$1"
  case "${HOST_OS}" in
    windows)
      if command -v cygpath >/dev/null 2>&1; then
        cygpath -aw "${path}"
        return
      fi
      ;;
  esac
  printf "%s" "${path}"
}

feature_default_from_template() {
  local key="$1"
  local default_value="$2"
  if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
    printf "%s" "${default_value}"
    return
  fi
  local val
  val="$(awk -v f="${key}" '
    /^[[:space:]]*features:[[:space:]]*$/ {in_features=1; next}
    in_features==1 && $0 !~ /^[[:space:]]{8,}[a-z0-9_]+:/ {in_features=0}
    in_features==1 && $0 ~ "^[[:space:]]{8,}" f ":[[:space:]]*(true|false)[[:space:]]*$" {
      split($0, a, ":")
      gsub(/[[:space:]]/, "", a[2])
      print a[2]
      exit
    }
  ' "${DEPLOYMENT_FILE}")"
  if [[ "${val}" == "true" || "${val}" == "false" ]]; then
    printf "%s" "${val}"
  else
    printf "%s" "${default_value}"
  fi
}

requested_feature_enabled() {
  local key="$1"
  if [[ "${FEATURE_ALL:-false}" == "true" ]]; then
    printf "%s" "true"
    return
  fi
  feature_default_from_template "${key}" "false"
}

suggest_cluster_profile_id() {
  local has_standard="false"
  local has_security="false"
  local has_specialized="false"
  local key enabled

  for key in secrets certs cloud_byok ekm_database data_protection; do
    enabled="$(requested_feature_enabled "${key}")"
    if [[ "${enabled}" == "true" ]]; then
      has_standard="true"
      break
    fi
  done

  for key in compliance_dashboard posture_management crypto_discovery sbom_cbom reporting_alerting; do
    enabled="$(requested_feature_enabled "${key}")"
    if [[ "${enabled}" == "true" ]]; then
      has_security="true"
      break
    fi
  done

  for key in payment_crypto hyok_proxy kmip_server pqc_migration qkd_interface qrng_generator mpc_engine ai_llm; do
    enabled="$(requested_feature_enabled "${key}")"
    if [[ "${enabled}" == "true" ]]; then
      has_specialized="true"
      break
    fi
  done

  if [[ "${has_specialized}" == "true" ]]; then
    printf "%s" "cluster-profile-full"
  elif [[ "${has_security}" == "true" ]]; then
    printf "%s" "cluster-profile-security"
  elif [[ "${has_standard}" == "true" ]]; then
    printf "%s" "cluster-profile-standard"
  else
    printf "%s" "cluster-profile-base"
  fi
}

is_builtin_cluster_profile_id() {
  case "$(trim "$1")" in
    cluster-profile-base|cluster-profile-standard|cluster-profile-security|cluster-profile-full)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

collect_inputs() {
  info "Collecting deployment parameters..."

  local detected_iface detected_ip_cidr detected_gw detected_dns_csv detected_hostname detected_domain

  prompt_default INSTALL_DIR "Directory where KMS files should be placed" "${ROOT_DIR}"
  INSTALL_DIR="$(trim "${INSTALL_DIR}")"
  INSTALL_DIR="$(normalize_host_path "${INSTALL_DIR}")"
  [[ "${INSTALL_DIR}" == /* ]] || INSTALL_DIR="$(pwd)/${INSTALL_DIR}"
  INSTALL_DIR="${INSTALL_DIR%/}"

  prompt_default APPLIANCE_ID "Appliance ID" "kms-prod-01"
  prompt_default TENANT_ID "Default tenant ID" "root"
  prompt_default TENANT_NAME "Default tenant name" "Root"

  detected_iface="$(detect_default_route_interface)"
  if [[ -z "${detected_iface}" ]]; then
    case "${HOST_OS}" in
      macos) detected_iface="en0" ;;
      windows) detected_iface="Ethernet" ;;
      *) detected_iface="eth0" ;;
    esac
  fi
  prompt_default MGMT_INTERFACE "Management interface" "${detected_iface}"
  prompt_default MGMT_MODE "Management mode (static/dhcp)" "static"
  MGMT_MODE="${MGMT_MODE,,}"
  [[ "${MGMT_MODE}" == "static" || "${MGMT_MODE}" == "dhcp" ]] || die "Management mode must be static or dhcp."

  detected_ip_cidr="$(detect_interface_ipv4_cidr "${MGMT_INTERFACE}")"
  [[ -z "${detected_ip_cidr}" ]] && detected_ip_cidr="10.0.1.100/24"
  if [[ -n "${CLI_MGMT_IP:-}" ]]; then
    detected_ip_cidr="${CLI_MGMT_IP}"
  fi
  detected_gw="$(detect_default_gateway "${MGMT_INTERFACE}")"
  [[ -z "${detected_gw}" ]] && detected_gw="$(detect_default_gateway)"
  [[ -z "${detected_gw}" ]] && detected_gw="10.0.1.1"
  detected_dns_csv="$(detect_default_dns_csv)"
  [[ -z "${detected_dns_csv}" ]] && detected_dns_csv="10.0.1.2,8.8.8.8"

  if [[ "${MGMT_MODE}" == "static" ]]; then
    prompt_default MGMT_ADDRESS "Management IPv4/CIDR" "${detected_ip_cidr}"
    validate_ipv4_cidr "${MGMT_ADDRESS}" || die "Management IPv4/CIDR must look like 10.0.1.100/24."
    prompt_default MGMT_GATEWAY "Management gateway IPv4" "${detected_gw}"
    validate_ipv4 "${MGMT_GATEWAY}" || die "Management gateway must be an IPv4 address."
  else
    MGMT_ADDRESS=""
    MGMT_GATEWAY=""
  fi

  prompt_default MGMT_DNS_CSV "Management DNS servers (comma-separated)" "${detected_dns_csv}"
  split_csv_to_array "${MGMT_DNS_CSV}" MGMT_DNS

  detected_hostname="$(hostname -s 2>/dev/null || true)"
  [[ -z "${detected_hostname}" ]] && detected_hostname="vecta-kms-prod-01"
  detected_domain="$(hostname -d 2>/dev/null || true)"
  [[ -z "${detected_domain}" ]] && detected_domain="local"
  prompt_default HOSTNAME_VALUE "Hostname" "${detected_hostname}"
  prompt_default DOMAIN_VALUE "Domain" "${detected_domain}"
  prompt_yes_no MGMT_IPV6_ENABLED "Enable IPv6 on management interface" "false"
  if [[ "${MGMT_IPV6_ENABLED}" == "true" ]]; then
    prompt_default MGMT_IPV6_ADDRESS "Management IPv6 address/CIDR" ""
  else
    MGMT_IPV6_ADDRESS=""
  fi

  prompt_yes_no CLUSTER_ENABLED "Enable cluster network" "false"
  CLUSTER_DEPLOYMENT_MODE="standalone"
  CLUSTER_REPLICATION_PROFILE="cluster-profile-base"
  CLUSTER_JOIN_ENDPOINT=""
  CLUSTER_JOIN_TOKEN=""
  CLUSTER_NODE_ROLE="leader"
  if [[ "${CLUSTER_ENABLED}" == "true" ]]; then
    local cluster_iface_default="${MGMT_INTERFACE}"
    if [[ "${HOST_OS}" == "linux" ]]; then
      cluster_iface_default="eth1"
    fi
    prompt_default CLUSTER_INTERFACE "Cluster interface" "${cluster_iface_default}"
    prompt_default CLUSTER_ADDRESS "Cluster IPv4/CIDR" "172.16.0.100/24"
    validate_ipv4_cidr "${CLUSTER_ADDRESS}" || die "Cluster IPv4/CIDR must look like 172.16.0.100/24."
    prompt_default CLUSTER_MTU "Cluster MTU" "9000"
    echo
    echo "Cluster deployment mode:"
    echo "  1) new installation (leader / seed node)"
    echo "  2) join existing cluster (follower)"
    read -r -p "Choose cluster mode [1/2] (default 1): " CLUSTER_MODE_CHOICE || true
    CLUSTER_MODE_CHOICE="$(trim "${CLUSTER_MODE_CHOICE}")"
    case "${CLUSTER_MODE_CHOICE:-1}" in
      1) CLUSTER_DEPLOYMENT_MODE="new-install"; CLUSTER_NODE_ROLE="leader" ;;
      2) CLUSTER_DEPLOYMENT_MODE="join-existing"; CLUSTER_NODE_ROLE="follower" ;;
      *) die "Invalid cluster mode choice." ;;
    esac
    if [[ "${CLUSTER_DEPLOYMENT_MODE}" == "join-existing" ]]; then
      prompt_default CLUSTER_JOIN_ENDPOINT "Existing cluster manager endpoint (http://host:8210)" "http://10.0.1.100:8210"
      prompt_default CLUSTER_JOIN_TOKEN "Cluster join credential (bundle JSON/file or token_id:join_secret)" ""
      [[ -n "$(trim "${CLUSTER_JOIN_TOKEN}")" ]] || die "Cluster join credential is required for join-existing mode."
    fi
  else
    CLUSTER_INTERFACE="eth1"
    CLUSTER_ADDRESS=""
    CLUSTER_MTU="9000"
    CLUSTER_NODE_ROLE="leader"
  fi

  prompt_default NTP_SERVERS_CSV "NTP servers (comma-separated)" "pool.ntp.org"
  split_csv_to_array "${NTP_SERVERS_CSV}" NTP_SERVERS

  prompt_default TLS_MODE "TLS mode (self-signed/custom/acme)" "self-signed"
  TLS_MODE="${TLS_MODE,,}"
  [[ "${TLS_MODE}" == "self-signed" || "${TLS_MODE}" == "custom" || "${TLS_MODE}" == "acme" ]] || die "TLS mode must be self-signed, custom, or acme."
  if [[ "${TLS_MODE}" == "custom" ]]; then
    prompt_default TLS_CERT_PATH "TLS cert path" "/etc/vecta/tls/server.crt"
    prompt_default TLS_KEY_PATH "TLS key path" "/etc/vecta/tls/server.key"
    prompt_default TLS_CA_PATH "TLS CA path" "/etc/vecta/tls/ca.crt"
  else
    TLS_CERT_PATH="/etc/vecta/tls/server.crt"
    TLS_KEY_PATH="/etc/vecta/tls/server.key"
    TLS_CA_PATH="/etc/vecta/tls/ca.crt"
  fi

  prompt_yes_no SYSLOG_ENABLED "Enable syslog forwarding" "true"
  if [[ "${SYSLOG_ENABLED}" == "true" ]]; then
    prompt_default SYSLOG_SERVER "Syslog server" "syslog.local:514"
    prompt_default SYSLOG_PROTOCOL "Syslog protocol (tcp+tls/udp)" "tcp+tls"
  else
    SYSLOG_SERVER=""
    SYSLOG_PROTOCOL="tcp+tls"
  fi

  prompt_default HSM_MODE "HSM mode (software/hardware/auto)" "software"
  HSM_MODE="${HSM_MODE,,}"
  [[ "${HSM_MODE}" == "software" || "${HSM_MODE}" == "hardware" || "${HSM_MODE}" == "auto" ]] || die "HSM mode must be software, hardware, or auto."

  prompt_default FIPS_MODE "FIPS mode (standard/strict)" "standard"
  FIPS_MODE="${FIPS_MODE,,}"
  [[ "${FIPS_MODE}" == "standard" || "${FIPS_MODE}" == "strict" ]] || die "FIPS mode must be standard or strict."

  CERT_STORAGE_MODE="db_encrypted"
  local root_key_mode_default="software"
  if [[ "${HSM_MODE}" == "hardware" ]]; then
    root_key_mode_default="hsm"
  fi
  prompt_default ROOT_KEY_MODE "Certificate root key mode (software/hsm)" "${root_key_mode_default}"
  ROOT_KEY_MODE="${ROOT_KEY_MODE,,}"
  [[ "${ROOT_KEY_MODE}" == "software" || "${ROOT_KEY_MODE}" == "hsm" ]] || die "Certificate root key mode must be software or hsm."
  if [[ "${ROOT_KEY_MODE}" == "hsm" ]]; then
    add_warning "Root key mode is set to hsm; cert root-key provider remains pending until UI-driven HSM integration is configured."
  fi
  prompt_default CERTS_SEALED_KEY_PATH "CRWK sealed key path" "/var/lib/vecta/certs/crwk.sealed"
  prompt_default CERTS_PASSPHRASE_FILE_PATH "CRWK passphrase file path" "/var/lib/vecta/certs/bootstrap.passphrase"
  prompt_yes_no CERTS_USE_TPM_SEAL "Use TPM sealing for CRWK blob" "false"

  CERTS_BOOTSTRAP_PASSPHRASE=""
  CERTS_BOOTSTRAP_AUTOGEN="false"
  if [[ "${ROOT_KEY_MODE}" == "software" ]]; then
    prompt_yes_no CERTS_BOOTSTRAP_AUTOGEN "Auto-generate certificate bootstrap passphrase" "true"
    if [[ "${CERTS_BOOTSTRAP_AUTOGEN}" == "true" ]]; then
      CERTS_BOOTSTRAP_PASSPHRASE="$(generate_random_secret 48)"
      info "Generated certificate bootstrap passphrase and will seed it into Docker certs volume."
    else
      prompt_secret CERTS_BOOTSTRAP_PASSPHRASE "Certificate bootstrap passphrase"
    fi
    if [[ "${CERTS_PASSPHRASE_FILE_PATH}" != /var/lib/vecta/certs/* ]]; then
      die "For software root key mode, CRWK passphrase file path must be under /var/lib/vecta/certs/ to persist safely in Docker volume."
    fi
  fi

  prompt_default ADMIN_USERNAME "Admin username" "admin"
  prompt_default ADMIN_EMAIL "Admin email" "admin@vecta.local"
  prompt_secret ADMIN_PASSWORD "Admin password"
  prompt_yes_no FORCE_PASSWORD_CHANGE "Force password change at first login" "true"

  prompt_default LICENSE_KEY "License key" "SEC-KMS-ENT-2026-ABCD"
  prompt_default MAX_KEYS "License max keys" "5000000"
  prompt_default MAX_TENANTS "License max tenants" "50"

  echo
  echo "Feature profile:"
  echo "  1) recommended (current template defaults)"
  echo "  2) all (enable every feature profile)"
  read -r -p "Choose feature profile [1/2] (default 1): " FEATURE_PROFILE || true
  FEATURE_PROFILE="$(trim "${FEATURE_PROFILE}")"
  FEATURE_PROFILE="${FEATURE_PROFILE:-1}"
  if [[ "${FEATURE_PROFILE}" == "2" ]]; then
    FEATURE_ALL="true"
  else
    FEATURE_ALL="false"
  fi

  if [[ "${CLUSTER_ENABLED}" == "true" ]]; then
    local suggested_cluster_profile
    suggested_cluster_profile="$(suggest_cluster_profile_id)"
    echo
    echo "Cluster replication profile presets:"
    echo "  - cluster-profile-base      : auth, keycore, policy, governance"
    echo "  - cluster-profile-standard  : base + secrets, certs, BYOK, EKM, data protection"
    echo "  - cluster-profile-security  : standard + compliance, posture, discovery, SBOM, reporting"
    echo "  - cluster-profile-full      : all cluster-aware services including AI, KMIP, QKD, QRNG, MPC, PQC"
    prompt_default CLUSTER_REPLICATION_PROFILE "Cluster replication profile ID" "${suggested_cluster_profile}"
    if ! is_builtin_cluster_profile_id "${CLUSTER_REPLICATION_PROFILE}"; then
      add_warning "Custom cluster replication profile '${CLUSTER_REPLICATION_PROFILE}' must already exist in cluster-manager before follower nodes join."
    fi
  fi

  local bind_ip_default
  if [[ "${MGMT_MODE}" == "static" ]]; then
    bind_ip_default="${MGMT_ADDRESS%%/*}"
  else
    bind_ip_default="${detected_ip_cidr%%/*}"
    [[ -z "${bind_ip_default}" ]] && bind_ip_default="0.0.0.0"
  fi
  if [[ -n "${CLI_BIND_IP:-}" ]]; then
    bind_ip_default="${CLI_BIND_IP}"
  fi
  prompt_default BIND_IP "Docker published bind IP" "${bind_ip_default}"
  validate_ipv4 "${BIND_IP}" || die "Bind IP must be a valid IPv4 address."
  CLUSTER_NODE_ENDPOINT="${MGMT_ADDRESS%%/*}"
  CLUSTER_NODE_ENDPOINT="$(trim "${CLUSTER_NODE_ENDPOINT}")"
  [[ -z "${CLUSTER_NODE_ENDPOINT}" ]] && CLUSTER_NODE_ENDPOINT="${BIND_IP}"

  prompt_default HTTP_PORT "Public HTTP port" "80"
  prompt_default HTTPS_PORT "Public HTTPS port" "443"
  prompt_default DASHBOARD_PORT "Dashboard port" "5173"
  prompt_default FIRSTBOOT_PORT "First-boot wizard port" "9443"

  local detected_cpus
  detected_cpus="$(detect_cpu_count)"
  prompt_default BUILD_PARALLEL_LIMIT "Build parallel limit (recommended: ${detected_cpus})" "${detected_cpus}"
  [[ "${BUILD_PARALLEL_LIMIT}" =~ ^[0-9]+$ ]] || die "Build parallel limit must be a number."
  (( BUILD_PARALLEL_LIMIT >= 1 )) || die "Build parallel limit must be at least 1."

  echo
  echo "Build mode:"
  echo "  1) Fast start (no build, requires preloaded images)"
  echo "  2) Build missing images only (recommended)"
  echo "  3) Rebuild all images (slow)"
  read -r -p "Choose build mode [1/2/3] (default 2): " BUILD_MODE_CHOICE || true
  BUILD_MODE_CHOICE="$(trim "${BUILD_MODE_CHOICE}")"
  case "${BUILD_MODE_CHOICE:-2}" in
    1) BUILD_MODE="no-build" ;;
    2) BUILD_MODE="build-missing" ;;
    3) BUILD_MODE="rebuild-all" ;;
    *) die "Invalid build mode choice." ;;
  esac

  prompt_default IMAGE_BUNDLE_PATH "Optional prebuilt image bundle (.tar) path (blank to skip)" ""
  IMAGE_BUNDLE_PATH="$(trim "${IMAGE_BUNDLE_PATH}")"

  prompt_yes_no ENABLE_FIRSTBOOT_UI "Start optional first-boot wizard container as well" "false"
  prompt_yes_no ENABLE_FDE "Enable FDE configuration in fde.yaml" "false"

  if [[ "${ENABLE_FDE}" == "true" ]]; then
    prompt_secret FDE_PASSPHRASE "FDE passphrase"
    prompt_default FDE_DEVICE "FDE LUKS device" "/dev/sda3"
    prompt_default FDE_RECOVERY_SHARES "FDE recovery shares (N)" "5"
    prompt_default FDE_RECOVERY_THRESHOLD "FDE recovery threshold (M)" "3"
    FDE_PASS_HASH="$(printf "%s" "${FDE_PASSPHRASE}" | sha256sum | awk '{print $1}')"
  else
    FDE_DEVICE="/dev/sda3"
    FDE_RECOVERY_SHARES="5"
    FDE_RECOVERY_THRESHOLD="3"
    FDE_PASS_HASH=""
  fi

  split_csv_to_array "*" LICENSE_FEATURES
}

prepare_install_directory() {
  if [[ "${INSTALL_DIR}" == "${SOURCE_DIR}" ]]; then
    info "Using existing directory: ${SOURCE_DIR}"
    set_project_paths "${SOURCE_DIR}"
    return
  fi

  [[ "${INSTALL_DIR}" == "${SOURCE_DIR}"/* ]] && die "Install directory cannot be inside the source directory."

  if [[ -e "${INSTALL_DIR}" && ! -d "${INSTALL_DIR}" ]]; then
    die "Install directory path exists but is not a directory: ${INSTALL_DIR}"
  fi

  mkdir -p "${INSTALL_DIR}" || die "Cannot create install directory: ${INSTALL_DIR}"

  if [[ -n "$(ls -A "${INSTALL_DIR}" 2>/dev/null || true)" ]]; then
    local continue_non_empty="false"
    prompt_yes_no continue_non_empty "Install directory is not empty. Continue and merge files" "false"
    [[ "${continue_non_empty}" == "true" ]] || die "Aborted due to non-empty install directory."
  fi

  info "Copying project files to ${INSTALL_DIR} ..."
  if command -v rsync >/dev/null 2>&1; then
    rsync -a \
      --exclude ".git" \
      --exclude "packer_cache" \
      --exclude "*.iso" \
      "${SOURCE_DIR}/" "${INSTALL_DIR}/"
  else
    (cd "${SOURCE_DIR}" && tar --exclude=".git" --exclude="packer_cache" --exclude="*.iso" -cf - .) | (cd "${INSTALL_DIR}" && tar -xf -)
  fi

  set_project_paths "${INSTALL_DIR}"
  chmod +x "${ROOT_DIR}/install.sh" || true
}

populate_feature_values() {
  local default_true
  if [[ "${INSTALL_MODE}" == "fast" ]]; then
    for feature in "${FEATURE_KEYS[@]}"; do
      printf -v "FEATURE_${feature}" "%s" "false"
    done
    FEATURE_certs="true"
    return
  fi
  for feature in "${FEATURE_KEYS[@]}"; do
    if [[ "${FEATURE_ALL}" == "true" ]]; then
      printf -v "FEATURE_${feature}" "%s" "true"
      continue
    fi
    default_true="$(feature_default_from_template "${feature}" "false")"
    printf -v "FEATURE_${feature}" "%s" "${default_true}"
  done
}

write_deployment_yaml() {
  mkdir -p "${DEPLOY_DIR}"
  cat > "${DEPLOYMENT_FILE}" <<EOF
apiVersion: kms.vecta.io/v1
kind: DeploymentConfig
metadata:
    appliance_id: ${APPLIANCE_ID}
    install_mode: ${INSTALL_MODE}
    created_at: "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
spec:
    core:
        audit: true
        auth: true
        keycore: true
        policy: true
    features:
        ai_llm: ${FEATURE_ai_llm}
        certs: ${FEATURE_certs}
        cloud_byok: ${FEATURE_cloud_byok}
        clustering: ${FEATURE_clustering}
        compliance_dashboard: ${FEATURE_compliance_dashboard}
        crypto_discovery: ${FEATURE_crypto_discovery}
        data_protection: ${FEATURE_data_protection}
        ekm_database: ${FEATURE_ekm_database}
        governance: ${FEATURE_governance}
        hyok_proxy: ${FEATURE_hyok_proxy}
        kmip_server: ${FEATURE_kmip_server}
        mpc_engine: ${FEATURE_mpc_engine}
        posture_management: ${FEATURE_posture_management}
        payment_crypto: ${FEATURE_payment_crypto}
        pqc_migration: ${FEATURE_pqc_migration}
        qkd_interface: ${FEATURE_qkd_interface}
        qrng_generator: ${FEATURE_qrng_generator}
        reporting_alerting: ${FEATURE_reporting_alerting}
        sbom_cbom: ${FEATURE_sbom_cbom}
        secrets: ${FEATURE_secrets}
    cluster_bootstrap:
        mode: ${CLUSTER_DEPLOYMENT_MODE}
        replication_profile_id: ${CLUSTER_REPLICATION_PROFILE}
        join_endpoint: ${CLUSTER_JOIN_ENDPOINT}
        join_token: ${CLUSTER_JOIN_TOKEN}
    hsm_mode: ${HSM_MODE}
    cert_security:
        cert_storage_mode: ${CERT_STORAGE_MODE}
        root_key_mode: ${ROOT_KEY_MODE}
        sealed_key_path: ${CERTS_SEALED_KEY_PATH}
        passphrase_file_path: ${CERTS_PASSPHRASE_FILE_PATH}
        use_tpm_seal: ${CERTS_USE_TPM_SEAL}
    license:
        activated_at: "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        features_allowed:
            - "*"
        key: ${LICENSE_KEY}
        max_keys: ${MAX_KEYS}
        max_tenants: ${MAX_TENANTS}
        status: active
EOF
}

write_network_yaml() {
  {
    cat <<EOF
cluster:
    enabled: ${CLUSTER_ENABLED}
    interface: ${CLUSTER_INTERFACE}
    ipv4:
        address: ${CLUSTER_ADDRESS}
        gateway: ""
        dns: []
    mtu: ${CLUSTER_MTU}
firewall:
    enabled: true
    allowedports:
        cluster:
            - 2379
            - 2380
            - 5432
            - 4222
            - 8160
        hsm:
            - 2300
            - 2310
        management:
            - ${HTTPS_PORT}
            - 5696
            - ${FIRSTBOOT_PORT}
    metadata: {}
    overrides: {}
hsm:
    enabled: false
    interface: eth2
    ipv4:
        address: ""
        gateway: ""
        dns: []
management:
    interface: ${MGMT_INTERFACE}
    mode: ${MGMT_MODE}
    ipv4:
        address: ${MGMT_ADDRESS}
        gateway: ${MGMT_GATEWAY}
        dns:
EOF
    emit_yaml_list 12 "${MGMT_DNS[@]}"
    cat <<EOF
    ipv6:
        enabled: ${MGMT_IPV6_ENABLED}
        address: ${MGMT_IPV6_ADDRESS}
    hostname: ${HOSTNAME_VALUE}
    domain: ${DOMAIN_VALUE}
ntp:
    servers:
EOF
    emit_yaml_list 8 "${NTP_SERVERS[@]}"
    cat <<EOF
syslog:
    enabled: ${SYSLOG_ENABLED}
    server: ${SYSLOG_SERVER}
    protocol: ${SYSLOG_PROTOCOL}
tls:
    mode: ${TLS_MODE}
    certpath: ${TLS_CERT_PATH}
    keypath: ${TLS_KEY_PATH}
    capath: ${TLS_CA_PATH}
EOF
  } > "${NETWORK_FILE}"
}

write_fips_yaml() {
  cat > "${FIPS_FILE}" <<EOF
mode: ${FIPS_MODE}
standard:
    allow_legacy_algorithms: true
    default_tls_version: "1.2"
    tag_non_fips_keys: true
    warn_non_fips_algorithms: true
strict:
    allowed_hashes:
        - SHA-224
        - SHA-256
        - SHA-384
        - SHA-512
        - SHA3-224
        - SHA3-256
        - SHA3-384
        - SHA3-512
        - SHAKE128
        - SHAKE256
    allowed_symmetric:
        - AES-128
        - AES-192
        - AES-256
        - 3DES
    allowed_tls_ciphers:
        - TLS_AES_128_GCM_SHA256
        - TLS_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    block_non_fips_algorithms: true
    go_boringcrypto: true
    min_ec_bits: 224
    min_rsa_bits: 2048
    reject_non_fips_imports: true
    require_drbg: true
    require_fips_tls: true
EOF
}

write_fde_yaml() {
  if [[ "${ENABLE_FDE}" == "true" ]]; then
    cat > "${FDE_FILE}" <<EOF
algorithm: AES-256-XTS
boot_unlock_listener_port: 9444
boot_unlock_listener_protocol: https
device: ${FDE_DEVICE}
enabled: true
key_derivation: Argon2id
luks_version: LUKS2
operator_passphrase_sha256: ${FDE_PASS_HASH}
operator_public_key: ""
recovery_passphrase_sha256: ${FDE_PASS_HASH}
recovery_share_encoding: hex
recovery_share_generation: shamir
recovery_share_verification: required
recovery_shares: ${FDE_RECOVERY_SHARES}
recovery_threshold: ${FDE_RECOVERY_THRESHOLD}
tang_server: ""
unlock_method: rest_api
EOF
  else
    cat > "${FDE_FILE}" <<EOF
enabled: false
EOF
  fi
}

write_auth_yaml() {
  cat > "${AUTH_FILE}" <<EOF
admin_email: ${ADMIN_EMAIL}
admin_password: ${ADMIN_PASSWORD}
admin_username: ${ADMIN_USERNAME}
force_password_change: ${FORCE_PASSWORD_CHANGE}
tenant_id: ${TENANT_ID}
EOF
}

write_env_file() {
  local profiles
  local compose_project_name
  profiles="$(bash "${PARSER_SCRIPT}" "${DEPLOYMENT_FILE}")"
  compose_project_name="${COMPOSE_PROJECT_NAME:-vecta-kms}"
  cat > "${ENV_FILE}" <<EOF
COMPOSE_PROJECT_NAME=${compose_project_name}
COMPOSE_PROFILES=${profiles}
CBOM_SCHEDULE_TENANTS=${TENANT_ID}
HSM_MODE=${HSM_MODE}
CERTS_STORAGE_MODE=${CERT_STORAGE_MODE}
CERTS_ROOT_KEY_MODE=${ROOT_KEY_MODE}
CERTS_CRWK_SEALED_PATH=${CERTS_SEALED_KEY_PATH}
CERTS_CRWK_PASSPHRASE_FILE=${CERTS_PASSPHRASE_FILE_PATH}
CERTS_CRWK_USE_TPM_SEAL=${CERTS_USE_TPM_SEAL}
AUTH_BOOTSTRAP_TENANT_ID=${TENANT_ID}
AUTH_BOOTSTRAP_TENANT_NAME=${TENANT_NAME}
AUTH_BOOTSTRAP_ADMIN_USERNAME=${ADMIN_USERNAME}
AUTH_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASSWORD}
AUTH_BOOTSTRAP_ADMIN_EMAIL=${ADMIN_EMAIL}
AUTH_BOOTSTRAP_FORCE_PASSWORD_CHANGE=${FORCE_PASSWORD_CHANGE}
CLUSTER_NODE_ID=${APPLIANCE_ID}
CLUSTER_NODE_NAME=${APPLIANCE_ID}
CLUSTER_NODE_ROLE=${CLUSTER_NODE_ROLE}
CLUSTER_NODE_ENDPOINT=${CLUSTER_NODE_ENDPOINT}
CLUSTER_BOOTSTRAP_PROFILE_ID=${CLUSTER_REPLICATION_PROFILE}
CLUSTER_JOIN_ENDPOINT=${CLUSTER_JOIN_ENDPOINT}
CLUSTER_JOIN_TOKEN=${CLUSTER_JOIN_TOKEN}
CLUSTER_SYNC_SHARED_SECRET=${CLUSTER_SYNC_SHARED_SECRET:-}
CLUSTER_SYNC_ANTI_REPLAY_SEC=${CLUSTER_SYNC_ANTI_REPLAY_SEC:-120}
CLUSTER_SYNC_REQUIRE_MTLS=${CLUSTER_SYNC_REQUIRE_MTLS:-false}
CLUSTER_SYNC_TLS_CA_FILE=${CLUSTER_SYNC_TLS_CA_FILE:-}
CLUSTER_SYNC_TLS_CERT_FILE=${CLUSTER_SYNC_TLS_CERT_FILE:-}
CLUSTER_SYNC_TLS_KEY_FILE=${CLUSTER_SYNC_TLS_KEY_FILE:-}
CLUSTER_SYNC_TLS_SERVER_NAME=${CLUSTER_SYNC_TLS_SERVER_NAME:-}
CLUSTER_SYNC_TLS_INSECURE_SKIP_VERIFY=${CLUSTER_SYNC_TLS_INSECURE_SKIP_VERIFY:-false}
CLUSTER_HTTP_TLS_ENABLE=${CLUSTER_HTTP_TLS_ENABLE:-false}
CLUSTER_HTTP_TLS_CERT_FILE=${CLUSTER_HTTP_TLS_CERT_FILE:-}
CLUSTER_HTTP_TLS_KEY_FILE=${CLUSTER_HTTP_TLS_KEY_FILE:-}
CLUSTER_HTTP_TLS_CLIENT_CA_FILE=${CLUSTER_HTTP_TLS_CLIENT_CA_FILE:-}
CLUSTER_HTTP_REQUIRE_CLIENT_CERT=${CLUSTER_HTTP_REQUIRE_CLIENT_CERT:-true}
CLUSTER_HSM_PARTITION_LABEL=${CLUSTER_HSM_PARTITION_LABEL:-}
CLUSTER_HSM_KEY_REPLICATION_ENABLED=${CLUSTER_HSM_KEY_REPLICATION_ENABLED:-false}
CLUSTER_MEK_IN_HSM=${CLUSTER_MEK_IN_HSM:-false}
CLUSTER_MEK_LOGICAL_ID=${CLUSTER_MEK_LOGICAL_ID:-}
KEYCORE_MEK_IN_HSM=${KEYCORE_MEK_IN_HSM:-false}
KEYCORE_MEK_LOGICAL_ID=${KEYCORE_MEK_LOGICAL_ID:-}
FIRSTBOOT_CONFIG_DIR=./infra/deployment
FIRSTBOOT_PORT=${FIRSTBOOT_PORT}
FIRSTBOOT_PROJECT_ROOT=${ROOT_DIR}
FIRSTBOOT_RUNTIME_APPLY_ENABLED=true
EOF
}

generate_override_file() {
  declare -A ports_by_service
  declare -A assigned_host_ports
  local -a override_warnings=()
  local parse_output
  parse_output="$(awk '
    /^[[:space:]]{2}[a-z0-9-]+:[[:space:]]*$/ {
      svc=$1
      sub(":","",svc)
      in_ports=0
      next
    }
    /^[[:space:]]{4}ports:[[:space:]]*$/ {
      if (svc!="") in_ports=1
      next
    }
    in_ports==1 && /^[[:space:]]{6}-[[:space:]]*"/ {
      line=$0
      sub(/^[[:space:]]{6}-[[:space:]]*"/,"",line)
      sub(/".*$/,"",line)
      if (line ~ /^[0-9]+:[0-9]+(\/[a-z]+)?$/) {
        print svc "|" line
      }
      next
    }
    in_ports==1 && $0 !~ /^[[:space:]]{6}-/ {
      in_ports=0
    }
  ' "${COMPOSE_FILE}")" || die "Failed to parse ${COMPOSE_FILE} for published ports."

  while IFS='|' read -r svc mapping; do
    [[ -z "${svc}" || -z "${mapping}" ]] && continue
    ports_by_service["${svc}"]+="${mapping}"$'\n'
  done <<< "${parse_output}"

  if [[ "${#ports_by_service[@]}" -eq 0 ]]; then
    die "No published ports found in ${COMPOSE_FILE}; cannot generate ${OVERRIDE_FILE}."
  fi

  local tmp_override
  tmp_override="$(mktemp)"
  {
    echo "services:"
    local svc mapping
    for svc in $(printf "%s\n" "${!ports_by_service[@]}" | sort); do
      echo "  ${svc}:"
      echo "    ports: !override"
      while IFS= read -r mapping; do
        [[ -z "${mapping}" ]] && continue
        local proto=""
        local raw="${mapping}"
        if [[ "${raw}" == */* ]]; then
          proto="/${raw#*/}"
          raw="${raw%%/*}"
        fi
        local host_port="${raw%%:*}"
        local container_port="${raw##*:}"
        local proto_name="tcp"
        [[ -n "${proto}" ]] && proto_name="${proto#/}"
        local pinned_port="false"
        case "${svc}:${container_port}" in
          envoy:80) host_port="${HTTP_PORT}"; pinned_port="true" ;;
          envoy:443) host_port="${HTTPS_PORT}"; pinned_port="true" ;;
          dashboard:5173) host_port="${DASHBOARD_PORT}"; pinned_port="true" ;;
          firstboot:9443) host_port="${FIRSTBOOT_PORT}"; pinned_port="true" ;;
        esac

        local assignment_key="${proto_name}:${host_port}"
        if [[ -n "${assigned_host_ports[${assignment_key}]:-}" ]]; then
          if [[ "${pinned_port}" == "true" ]]; then
            die "Required pinned host port collision in generated override: ${host_port}/${proto_name} used by multiple services."
          fi
          local next_port=$((host_port + 10000))
          while [[ -n "${assigned_host_ports[${proto_name}:${next_port}]:-}" ]] || port_conflicts_for_bind "${BIND_IP}" "${next_port}" "${proto_name}"; do
            next_port=$((next_port + 1))
            (( next_port <= 65535 )) || die "Unable to allocate a free host port for ${svc}:${container_port}/${proto_name}"
          done
          override_warnings+=("Remapped ${svc}:${container_port}/${proto_name} host port ${host_port} -> ${next_port} (duplicate mapping).")
          host_port="${next_port}"
          assignment_key="${proto_name}:${host_port}"
        fi

        if port_conflicts_for_bind "${BIND_IP}" "${host_port}" "${proto_name}"; then
          if [[ "${pinned_port}" == "true" ]]; then
            die "Pinned host port ${host_port}/${proto_name} is already in use on ${BIND_IP}. Choose another value in installer prompts."
          fi
          local remap_port=$((host_port + 10000))
          while [[ -n "${assigned_host_ports[${proto_name}:${remap_port}]:-}" ]] || port_conflicts_for_bind "${BIND_IP}" "${remap_port}" "${proto_name}"; do
            remap_port=$((remap_port + 1))
            (( remap_port <= 65535 )) || die "Unable to allocate a free host port for ${svc}:${container_port}/${proto_name}"
          done
          override_warnings+=("Remapped ${svc}:${container_port}/${proto_name} host port ${host_port} -> ${remap_port} (port in use).")
          host_port="${remap_port}"
          assignment_key="${proto_name}:${host_port}"
        fi

        assigned_host_ports["${assignment_key}"]=1
        echo "      - \"${BIND_IP}:${host_port}:${container_port}${proto}\""
      done <<< "${ports_by_service[${svc}]}"
    done
  } > "${tmp_override}"

  mv "${tmp_override}" "${OVERRIDE_FILE}"

  local override_warning
  for override_warning in "${override_warnings[@]}"; do
    add_warning "${override_warning}"
  done
}

seed_cert_bootstrap_secret() {
  if [[ "${CERT_STORAGE_MODE}" != "db_encrypted" || "${ROOT_KEY_MODE}" != "software" ]]; then
    return
  fi
  if [[ -z "${CERTS_BOOTSTRAP_PASSPHRASE:-}" ]]; then
    die "Certificate bootstrap passphrase is empty in software root key mode."
  fi

  local project_name="${COMPOSE_PROJECT_NAME:-vecta-kms}"
  if [[ -f "${ENV_FILE}" ]]; then
    local env_project
    env_project="$(awk -F= '/^COMPOSE_PROJECT_NAME=/ {print $2; exit}' "${ENV_FILE}" | tr -d '\r' || true)"
    env_project="$(trim "${env_project}")"
    [[ -n "${env_project}" ]] && project_name="${env_project}"
  fi

  local volume_name="${project_name}_certs-key-data"
  local target_path="${CERTS_PASSPHRASE_FILE_PATH}"
  info "Seeding certificate bootstrap secret into Docker volume ${volume_name} ..."
  "${DOCKER_BIN[@]}" volume create "${volume_name}" >/dev/null

  local seeded="false"
  local image
  for image in alpine:3.20 busybox:1.36; do
    if "${DOCKER_BIN[@]}" run --rm \
      -v "${volume_name}:/var/lib/vecta/certs" \
      -e BOOTSTRAP_SECRET="${CERTS_BOOTSTRAP_PASSPHRASE}" \
      "${image}" \
      sh -c 'set -eu; target="'"${target_path}"'"; umask 077; mkdir -p "$(dirname "$target")"; chown -R 100:101 /var/lib/vecta/certs; printf "%s\n" "$BOOTSTRAP_SECRET" > "$target"; chown 100:101 "$target"; chmod 700 /var/lib/vecta/certs; chmod 640 "$target"' >/dev/null 2>&1; then
      seeded="true"
      break
    fi
  done

  if [[ "${seeded}" != "true" ]]; then
    die "Unable to seed certificate bootstrap secret into Docker volume ${volume_name}."
  fi
  CERTS_BOOTSTRAP_PASSPHRASE=""
}

apply_mandatory_clean_reset() {
  info "Resetting docker volumes for clean empty KMS data..."
  compose_exec down -v --remove-orphans || true
}

start_stack() {
  export COMPOSE_PROFILES
  COMPOSE_PROFILES="$(bash "${PARSER_SCRIPT}" "${DEPLOYMENT_FILE}")"
  export HSM_MODE

  info "Starting KMS stack with COMPOSE_PROFILES=${COMPOSE_PROFILES}"
  case "${BUILD_MODE}" in
    no-build)
      if ! compose_exec up -d --no-build --remove-orphans; then
        die "No-build start failed. Missing images detected. Use build mode 2/3 or provide image bundle."
      fi
      ;;
    build-missing)
      compose_exec up -d --remove-orphans
      ;;
    rebuild-all)
      compose_exec up -d --build --remove-orphans
      ;;
    *)
      die "Unknown BUILD_MODE value: ${BUILD_MODE}"
      ;;
  esac

  if [[ "${ENABLE_FIRSTBOOT_UI}" == "true" ]]; then
    info "Starting first-boot wizard service..."
    case "${BUILD_MODE}" in
      no-build)
        compose_exec up -d --no-deps --no-build firstboot || warn "First-boot container not started in no-build mode (image missing)."
        ;;
      build-missing)
        compose_exec up -d --no-deps firstboot
        ;;
      rebuild-all)
        compose_exec up -d --build --no-deps firstboot
        ;;
    esac
  fi
}

extract_join_credential_payload() {
  local raw
  raw="$(trim "${CLUSTER_JOIN_TOKEN:-}")"
  if [[ -z "${raw}" ]]; then
    printf "%s" ""
    return
  fi
  if [[ -f "${raw}" ]]; then
    cat "${raw}"
    return
  fi
  printf "%s" "${raw}"
}

parse_join_bundle_json() {
  local raw="$1"
  local parsed=""
  if command -v jq >/dev/null 2>&1; then
    parsed="$(printf "%s" "${raw}" | jq -r '[.id // .token_id // "", .issued_secret // .join_secret // "", .endpoint // "", .profile_id // ""] | @tsv' 2>/dev/null || true)"
    if [[ -n "${parsed}" ]]; then
      printf "%s" "${parsed}"
      return 0
    fi
  fi

  if command -v python3 >/dev/null 2>&1; then
    parsed="$(
      python3 - "$raw" <<'PY' 2>/dev/null || true
import json, sys
raw = sys.argv[1]
obj = json.loads(raw)
token_id = str(obj.get("id") or obj.get("token_id") or "").strip()
secret = str(obj.get("issued_secret") or obj.get("join_secret") or "").strip()
endpoint = str(obj.get("endpoint") or "").strip()
profile = str(obj.get("profile_id") or "").strip()
print("\t".join([token_id, secret, endpoint, profile]))
PY
    )"
    if [[ -n "${parsed}" ]]; then
      printf "%s" "${parsed}"
      return 0
    fi
  fi

  return 1
}

resolve_join_credentials() {
  local raw="$1"
  CLUSTER_JOIN_TOKEN_ID=""
  CLUSTER_JOIN_SECRET=""

  raw="$(trim "${raw}")"
  if [[ -z "${raw}" ]]; then
    return 1
  fi

  if [[ "${raw}" == *:* && "${raw}" != \{* ]]; then
    CLUSTER_JOIN_TOKEN_ID="$(trim "${raw%%:*}")"
    CLUSTER_JOIN_SECRET="$(trim "${raw#*:}")"
    [[ -n "${CLUSTER_JOIN_TOKEN_ID}" && -n "${CLUSTER_JOIN_SECRET}" ]] && return 0
  fi

  if [[ "${raw}" == \{* ]]; then
    local parsed=""
    if parsed="$(parse_join_bundle_json "${raw}")"; then
      CLUSTER_JOIN_TOKEN_ID="$(trim "$(printf "%s" "${parsed}" | awk -F'\t' '{print $1}')")"
      CLUSTER_JOIN_SECRET="$(trim "$(printf "%s" "${parsed}" | awk -F'\t' '{print $2}')")"
      local parsed_endpoint parsed_profile
      parsed_endpoint="$(trim "$(printf "%s" "${parsed}" | awk -F'\t' '{print $3}')")"
      parsed_profile="$(trim "$(printf "%s" "${parsed}" | awk -F'\t' '{print $4}')")"
      if [[ -n "${parsed_endpoint}" && -z "$(trim "${CLUSTER_JOIN_ENDPOINT}")" ]]; then
        CLUSTER_JOIN_ENDPOINT="${parsed_endpoint}"
      fi
      if [[ -n "${parsed_profile}" && -z "$(trim "${CLUSTER_REPLICATION_PROFILE}")" ]]; then
        CLUSTER_REPLICATION_PROFILE="${parsed_profile}"
      fi
      [[ -n "${CLUSTER_JOIN_TOKEN_ID}" && -n "${CLUSTER_JOIN_SECRET}" ]] && return 0
    fi
  fi

  return 1
}

build_join_complete_url() {
  local endpoint="$1"
  endpoint="$(trim "${endpoint}")"
  endpoint="${endpoint%/}"
  if [[ "${endpoint}" != */cluster ]]; then
    endpoint="${endpoint}/cluster"
  fi
  printf "%s/join/complete" "${endpoint}"
}

attempt_cluster_join() {
  if [[ "${CLUSTER_ENABLED}" != "true" || "${CLUSTER_DEPLOYMENT_MODE}" != "join-existing" ]]; then
    return
  fi

  info "Finalizing cluster join through installer flow..."

  local raw_credential
  raw_credential="$(extract_join_credential_payload)"
  if ! resolve_join_credentials "${raw_credential}"; then
    add_warning "Cluster join credential format invalid. Expected bundle JSON/file or token_id:join_secret."
    return
  fi

  local join_url
  join_url="$(build_join_complete_url "${CLUSTER_JOIN_ENDPOINT}")"
  if [[ -z "${join_url}" ]]; then
    add_warning "Cluster join endpoint is empty; cannot complete join."
    return
  fi

  local payload_file response_file http_code curl_insecure
  payload_file="$(mktemp)"
  response_file="$(mktemp)"
  curl_insecure=()
  if [[ "${join_url}" == https:* && "${CLUSTER_SYNC_TLS_INSECURE_SKIP_VERIFY:-false}" == "true" ]]; then
    curl_insecure=(-k)
  fi

  cat > "${payload_file}" <<EOF
{
  "tenant_id": "${TENANT_ID}",
  "token_id": "${CLUSTER_JOIN_TOKEN_ID}",
  "join_secret": "${CLUSTER_JOIN_SECRET}",
  "node_id": "${APPLIANCE_ID}",
  "node_name": "${APPLIANCE_ID}",
  "endpoint": "${CLUSTER_NODE_ENDPOINT}",
  "components": []
}
EOF

  http_code="$(
    curl "${curl_insecure[@]}" -sS -o "${response_file}" -w "%{http_code}" \
      -X POST "${join_url}" \
      -H "Content-Type: application/json" \
      --data-binary "@${payload_file}" || true
  )"

  if [[ "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
    info "Cluster join completed successfully for follower ${APPLIANCE_ID}."
  else
    local body
    body="$(tr '\n' ' ' < "${response_file}" | tr -s ' ' | cut -c1-500)"
    add_warning "Cluster join complete call failed (HTTP ${http_code:-000}). Response: ${body}"
  fi

  rm -f "${payload_file}" "${response_file}" || true
}

wait_for_stack_ready() {
  local timeout_seconds=600
  local poll_seconds=5
  local start_epoch
  start_epoch="$(date +%s)"

  info "Waiting for containers to reach running state..."
  while true; do
    local -a all_services=()
    local -a running_services=()
    mapfile -t all_services < <(compose_exec ps --services 2>/dev/null | sed '/^[[:space:]]*$/d')
    mapfile -t running_services < <(compose_exec ps --status running --services 2>/dev/null | sed '/^[[:space:]]*$/d')

    local total="${#all_services[@]}"
    local running="${#running_services[@]}"
    info "Container status: ${running}/${total} running"

    if [[ "${total}" -gt 0 && "${running}" -eq "${total}" ]]; then
      info "All started containers are running."
      return
    fi

    if (( "$(date +%s)" - start_epoch > timeout_seconds )); then
      warn "Timeout while waiting for all containers to become running."
      warn "Check status with: docker compose -f ${COMPOSE_FILE} -f ${OVERRIDE_FILE} ps"
      return
    fi
    sleep "${poll_seconds}"
  done
}

print_summary() {
  local display_ip="${BIND_IP}"
  if [[ "${display_ip}" == "0.0.0.0" || "${display_ip}" == "::" ]]; then
    display_ip="${MGMT_ADDRESS%%/*}"
    [[ -z "${display_ip}" ]] && display_ip="127.0.0.1"
  fi
  echo
  echo "------------------------------------------------------------"
  echo "Vecta KMS deployment complete on this VM."
  echo
  echo "Project directory : ${ROOT_DIR}"
  echo "Deployment config : ${DEPLOYMENT_FILE}"
  echo "Network config    : ${NETWORK_FILE}"
  echo "Compose override  : ${OVERRIDE_FILE}"
  echo "Bind IP           : ${BIND_IP}"
  echo "Build mode        : ${BUILD_MODE}"
  echo "Build parallel    : ${BUILD_PARALLEL_LIMIT}"
  echo "Cert security     : ${CERT_STORAGE_MODE}/${ROOT_KEY_MODE}"
  echo "CRWK sealed path  : ${CERTS_SEALED_KEY_PATH}"
  if [[ "${CLUSTER_ENABLED}" == "true" ]]; then
    echo "Cluster mode      : ${CLUSTER_DEPLOYMENT_MODE}"
    echo "Cluster role      : ${CLUSTER_NODE_ROLE}"
    echo "Cluster profile   : ${CLUSTER_REPLICATION_PROFILE}"
    if [[ "${CLUSTER_DEPLOYMENT_MODE}" == "join-existing" ]]; then
      echo "Cluster join URL  : ${CLUSTER_JOIN_ENDPOINT}"
    fi
  fi
  echo
  echo "Access URLs:"
  echo "  Dashboard : http://${display_ip}:${DASHBOARD_PORT}"
  echo "  HTTPS Edge: https://${display_ip}:${HTTPS_PORT}"
  if [[ "${ENABLE_FIRSTBOOT_UI}" == "true" ]]; then
    echo "  First boot: http://${display_ip}:${FIRSTBOOT_PORT}/wizard"
  fi
  echo
  echo "Default admin credentials:"
  echo "  Username : ${ADMIN_USERNAME}"
  echo "  Email    : ${ADMIN_EMAIL}"
  echo "  Password : ${ADMIN_PASSWORD}"
  if [[ "${HOST_OS}" == "linux" && "${EUID}" -ne 0 ]]; then
    echo
    echo "Note: If this is your first Docker install, run:"
    echo "  newgrp docker"
    echo "or log out/in once before manual docker commands."
  fi
  echo "------------------------------------------------------------"
  if [[ "${#INSTALL_WARNINGS[@]}" -gt 0 ]]; then
    echo
    echo "Installer warnings:"
    local w
    for w in "${INSTALL_WARNINGS[@]}"; do
      echo "  - ${w}"
    done
  fi
  echo
}

collect_fast_inputs() {
  info "Fast installation mode: deploying the base KMS stack and first-boot UI"
  info "Additional features can be enabled later via the dashboard onboarding wizard."
  FEATURE_ALL="false"
  prompt_default INSTALL_DIR "Install directory" "${SOURCE_DIR}"
  INSTALL_DIR="$(trim "$(normalize_host_path "${INSTALL_DIR}")")"
  prompt_default APPLIANCE_ID "Appliance ID" "vecta-$(hostname -s 2>/dev/null || echo kms)"
  prompt_default TENANT_ID "Primary tenant ID" "root"
  TENANT_NAME="Root Tenant"
  prompt_default ADMIN_USERNAME "Admin username" "admin"
  prompt_default ADMIN_EMAIL "Admin email" "admin@vecta.local"
  prompt_secret ADMIN_PASSWORD "Admin password"
  FORCE_PASSWORD_CHANGE="true"
  local detected_iface detected_gw detected_dns_csv detected_hostname detected_domain
  LICENSE_KEY="SEC-KMS-ENT-2026-ABCD"
  MAX_KEYS="5000000"
  MAX_TENANTS="50"
  HTTP_PORT="80"
  HTTPS_PORT="443"
  DASHBOARD_PORT="5173"
  FIRSTBOOT_PORT="9443"
  ENABLE_FIRSTBOOT_UI="true"
  BUILD_MODE="${BUILD_MODE:-build-missing}"
  BUILD_PARALLEL_LIMIT="$(nproc 2>/dev/null || echo 4)"
  ENABLE_FDE="false"
  FDE_DEVICE="/dev/sda3"
  FDE_RECOVERY_SHARES="5"
  FDE_RECOVERY_THRESHOLD="3"
  FDE_PASS_HASH=""
  HSM_MODE="software"
  CERT_STORAGE_MODE="db_encrypted"
  ROOT_KEY_MODE="software"
  CERTS_SEALED_KEY_PATH="/var/lib/vecta/certs/crwk.sealed"
  CERTS_PASSPHRASE_FILE_PATH="/var/lib/vecta/certs/bootstrap.passphrase"
  CERTS_USE_TPM_SEAL="false"
  CERTS_BOOTSTRAP_PASSPHRASE="$(generate_random_secret 48)"
  FIPS_MODE="standard"
  detected_iface="$(detect_default_route_interface)"
  if [[ -z "${detected_iface}" ]]; then
    case "${HOST_OS}" in
      macos) detected_iface="en0" ;;
      windows) detected_iface="Ethernet" ;;
      *) detected_iface="eth0" ;;
    esac
  fi
  MGMT_INTERFACE="${detected_iface}"
  MGMT_MODE="static"
  CLUSTER_ENABLED="false"
  CLUSTER_DEPLOYMENT_MODE="standalone"
  CLUSTER_REPLICATION_PROFILE="cluster-profile-base"
  CLUSTER_NODE_ROLE="leader"
  CLUSTER_NODE_NAME="${APPLIANCE_ID}"
  CLUSTER_NODE_ENDPOINT=""
  CLUSTER_JOIN_TOKEN=""
  CLUSTER_JOIN_ENDPOINT=""
  CLUSTER_BOOTSTRAP=""
  CLUSTER_SEED_ENDPOINT=""
  CLUSTER_TLS_PROFILE="mtls_ecdsa_p256"
  CLUSTER_RAFT_DATA_DIR="/var/lib/vecta/raft"
  CLUSTER_INTERFACE="${MGMT_INTERFACE}"
  CLUSTER_ADDRESS=""
  CLUSTER_MTU="9000"
  split_csv_to_array "*" LICENSE_FEATURES
  IMAGE_BUNDLE_PATH=""
  local detected_ip_cidr
  detected_ip_cidr="$(detect_primary_ip_cidr 2>/dev/null || echo "10.0.1.100/24")"
  if [[ -n "${CLI_MGMT_IP:-}" ]]; then
    detected_ip_cidr="${CLI_MGMT_IP}"
  fi
  MGMT_ADDRESS="${detected_ip_cidr}"
  detected_gw="$(detect_default_gateway "${MGMT_INTERFACE}")"
  [[ -z "${detected_gw}" ]] && detected_gw="$(detect_default_gateway)"
  [[ -z "${detected_gw}" ]] && detected_gw="10.0.1.1"
  MGMT_GATEWAY="${detected_gw}"
  detected_dns_csv="$(detect_default_dns_csv)"
  [[ -z "${detected_dns_csv}" ]] && detected_dns_csv="8.8.8.8,1.1.1.1"
  MGMT_DNS_CSV="${detected_dns_csv}"
  split_csv_to_array "${MGMT_DNS_CSV}" MGMT_DNS
  detected_hostname="$(hostname -s 2>/dev/null || true)"
  [[ -z "${detected_hostname}" ]] && detected_hostname="vecta-kms"
  detected_domain="$(hostname -d 2>/dev/null || true)"
  [[ -z "${detected_domain}" ]] && detected_domain="local"
  HOSTNAME_VALUE="${detected_hostname}"
  DOMAIN_VALUE="${detected_domain}"
  MGMT_IPV6_ENABLED="false"
  MGMT_IPV6_ADDRESS=""
  split_csv_to_array "pool.ntp.org" NTP_SERVERS
  TLS_MODE="self-signed"
  TLS_CERT_PATH="/etc/vecta/tls/server.crt"
  TLS_KEY_PATH="/etc/vecta/tls/server.key"
  TLS_CA_PATH="/etc/vecta/tls/ca.crt"
  SYSLOG_ENABLED="true"
  SYSLOG_SERVER="syslog.local:514"
  SYSLOG_PROTOCOL="tcp+tls"
  local bind_ip_default
  bind_ip_default="${detected_ip_cidr%%/*}"
  [[ -z "${bind_ip_default}" ]] && bind_ip_default="10.0.1.100"
  if [[ -n "${CLI_BIND_IP:-}" ]]; then
    bind_ip_default="${CLI_BIND_IP}"
  fi
  prompt_default BIND_IP "Docker published bind IP" "${bind_ip_default}"
  validate_ipv4 "${BIND_IP}" || die "Bind IP must be a valid IPv4 address."
  CLUSTER_NODE_ENDPOINT="${MGMT_ADDRESS%%/*}"
  CLUSTER_NODE_ENDPOINT="$(trim "${CLUSTER_NODE_ENDPOINT}")"
  [[ -z "${CLUSTER_NODE_ENDPOINT}" ]] && CLUSTER_NODE_ENDPOINT="${BIND_IP}"
  return 0
}

main() {
  # Parse CLI arguments
  for arg in "$@"; do
    case "${arg}" in
      --fast|fast) INSTALL_MODE="fast" ;;
      --interactive) INSTALL_MODE="interactive" ;;
      --mgmt-ip=*) CLI_MGMT_IP="${arg#*=}" ;;
      --cluster-ip=*) CLI_CLUSTER_IP="${arg#*=}" ;;
      --bind-ip=*) CLI_BIND_IP="${arg#*=}" ;;
    esac
  done

  set_project_paths "${ROOT_DIR}"
  require_modern_bash

  step "Validate target OS and local permissions"
  ensure_linux
  setup_sudo
  check_workspace_permissions

  [[ -f "${COMPOSE_FILE}" ]] || die "docker-compose.yml not found in ${ROOT_DIR}"
  [[ -f "${PARSER_SCRIPT}" ]] || die "Missing parser script: ${PARSER_SCRIPT}"

  info "Installer target: ${ROOT_DIR}"
  info "Required permissions:"
  info "  - write access to ${ROOT_DIR}"
  if [[ "${HOST_OS}" == "linux" ]]; then
    info "  - root/sudo for package install and Docker service management"
    info "  - Docker socket access (script uses sudo docker automatically if needed)"
  else
    info "  - Docker Desktop installed and running"
    info "  - docker compose available in shell path"
  fi

  step "Install or verify Docker runtime dependencies"
  install_prerequisites

  step "Validate Docker daemon availability"
  setup_docker_command
  wait_for_docker

  if [[ "${INSTALL_MODE}" == "fast" ]]; then
    step "Collect fast-mode deployment configuration"
    collect_fast_inputs
  else
    step "Collect deployment configuration inputs"
    collect_inputs
  fi

  step "Place KMS files in target install directory"
  prepare_install_directory
  check_workspace_permissions
  step "Harden Docker build-context excludes"
  ensure_dockerignore_safety

  step "Resolve feature profile settings"
  populate_feature_values
  adjust_unsupported_profiles

  step "Generate deployment.yaml"
  write_deployment_yaml
  step "Generate network.yaml"
  write_network_yaml
  step "Generate fips.yaml"
  write_fips_yaml
  step "Generate fde.yaml"
  write_fde_yaml
  step "Generate auth-bootstrap.yaml"
  write_auth_yaml
  step "Generate .env and compose override for bind IP/ports"
  write_env_file
  generate_override_file

  step "Apply mandatory clean reset (empty DB and no historical data)"
  apply_mandatory_clean_reset
  step "Seed certificate bootstrap secret for CRWK (software mode)"
  seed_cert_bootstrap_secret
  step "Configure build runtime and preload image bundle"
  configure_build_runtime
  load_image_bundle_if_requested
  step "Start docker services"
  start_stack
  step "Wait for stack readiness"
  wait_for_stack_ready
  step "Finalize installer-managed cluster enrollment"
  attempt_cluster_join

  print_summary
}

main "$@"
