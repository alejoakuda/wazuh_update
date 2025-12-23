#!/bin/bash

# WAZUH_ACT.SH - Orquestador de Actualización Segura
# Autor: Alejandro Fernandes (aka Vernizus)
#
# Herramienta de mantenimiento para entornos Wazuh sobre Docker Multi-Node.
# Automatiza el ciclo de vida de actualización (Backup -> Git Sync ->
# Config Restore -> Agent Upgrade) garantizando la persistencia de usuarios,
# certificados y configuraciones críticas de red.

set -euo pipefail

# --- CONFIGURACIÓN ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WAZUH_DIR="$PARENT_DIR/wazuh-docker"
MULTI_NODE="$WAZUH_DIR/multi-node"
BACKUP_NAME="wazuh-docker.backup.$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$PARENT_DIR/$BACKUP_NAME"
TARGET_VERSION="Buscando..."

# --- COLORES Y ESTÉTICA ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
HR="----------------------------------------------------------------"

# --- FUNCIONES DE LOGGING ----
log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# --- CORE FUNCTIONS

get_target_version() {
    cd "$WAZUH_DIR"
    log_info "Sincronizando tags del repositorio..."
    git fetch --all --tags --quiet
    echo "----------------------------------------------------------------"
    # Detectar versión actual
    local CURRENT_V=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    log_info "Versión actual detectada: ${YELLOW}$CURRENT_V${NC}"

    # Buscar versiones superiores
    local UPGRADES=$(git tag -l "v4.*" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | { cat; echo "$CURRENT_V"; } | sort -uV | sed -n "/^$CURRENT_V$/,\$p" | grep -v "^$CURRENT_V$")

    if [ -z "$UPGRADES" ]; then
        log_warn "No se encontraron versiones superiores a la $CURRENT_V."
        read -p "¿Deseas reinstalar la versión actual? (s/n): " confirm
        if [[ $confirm == "s" || $confirm == "S" ]]; then
            TARGET_VERSION="$CURRENT_V"
        else
            log_info "Saliendo sin realizar cambios."
            exit 0
        fi
    else
        log_info "Versiones superiores disponibles:"
        echo -e "${YELLOW}$UPGRADES${NC}"
        echo ""
        read -p "Introduce la versión objetivo: " SELECTED
        
        if echo "$UPGRADES" | grep -q "^$SELECTED$"; then
            TARGET_VERSION="$SELECTED"
        else
            log_error "Selección no válida o intento de downgrade."
            exit 1
        fi
    fi
}



check_prerequisites() {
    echo "$HR"
    log_info "Verificando prerrequisitos..."
    [[ ! -d "$WAZUH_DIR" ]] && { log_error "No existe $WAZUH_DIR"; exit 1; }
    
    for cmd in docker git; do
        command -v $cmd &> /dev/null || { log_error "$cmd no instalado"; exit 1; }
    done
    log_info "Prerrequisitos OK ✓"
}

backup_critical_files() {
    echo "$HR"
    log_info "Iniciando Backup completo..."
    log_info "Destino: $BACKUP_DIR"
    cp -ra "$WAZUH_DIR" "$BACKUP_DIR"
    log_info "Backup completado ✓"
}

restore_critical_files() {
    echo "$HR"
    log_info "Sincronizando configuración existente..."

    local src_config="$BACKUP_DIR/multi-node/config"
    local dest_config="$WAZUH_DIR/multi-node/config"
    local nv_reference_dir="$SCRIPT_DIR/new_version_reference"
    local user_file="wazuh_indexer/internal_users.yml"

    if [ -d "$src_config" ]; then
        rm -rf "$nv_reference_dir" && mkdir -p "$nv_reference_dir"
        cp -rp "$dest_config/." "$nv_reference_dir/"

        log_info "Validando integridad de usuarios..."
        local old_count=$(grep -c "hash:" "$src_config/$user_file" || echo "0")
        local new_count=$(grep -c "hash:" "$nv_reference_dir/$user_file" || echo "0")

        if [ "$old_count" -lt "$new_count" ]; then
            log_warn "Discrepancia detectada: Tu backup ($old_count) vs Fábrica ($new_count)"
            read -p "¿Continuar? (s/n): " user_confirm
            [[ $user_confirm =~ ^[sS]$ ]] || exit 1
        fi

        log_info "Generando reporte de diferencias..."
        diff -r --brief "$src_config" "$nv_reference_dir" > "$SCRIPT_DIR/upgrade_diff.log" || true
        cp -rp "$src_config/." "$dest_config/"
    else
        log_error "Carpeta config no encontrada en backup"; exit 1
    fi
    update_docker_compose "$BACKUP_DIR"
}

stop_services() {
    echo "$HR"
    log_info "Gestionando detención de servicios..."
    cd "$MULTI_NODE"
    if docker compose ps -q | grep -q .; then
        docker compose down
        log_info "Contenedores eliminados ✓"
    else
        log_info "No hay servicios activos."
    fi
}

update_docker_compose() {
    echo "----------------------------------------------------------------"
    local backup_dir="$1"
    local docker_compose="$MULTI_NODE/docker-compose.yml"
    local backup_compose="$backup_dir/multi-node/docker-compose.yml"

    # Verificación de seguridad
    if [ ! -f "$backup_compose" ]; then
        log_error "No se encontró el backup de docker-compose.yml en $backup_compose"
        return 1
    fi

    log_info "Sincronizando configuraciones críticas (Passwords y Puertos)..."

    local critical_vars=("INDEXER_PASSWORD" "DASHBOARD_PASSWORD" "API_PASSWORD" "API_USERNAME" "INDEXER_USERNAME" "DASHBOARD_USERNAME")
    log_info "    → Aplicando valores de backup sobre la nueva versión..."

    for var in "${critical_vars[@]}"; do
        local old_value=$(grep -E "${var}=" "$backup_compose" | head -1 | cut -d'=' -f2- | tr -d ' "' | tr -d "'")

        if [ -n "$old_value" ]; then
            sed -i "s|\(${var}=\).*|\1${old_value}|g" "$docker_compose"
            log_info "    ✓ $var preservada"
        fi
    done
    local old_port=$(grep -E '[0-9]+:5601' "$backup_compose" | grep -oE '[0-9]+' | head -1)

    if [ -n "$old_port" ]; then
        sed -i "s|[0-9]\{2,5\}:5601|${old_port}:5601|g" "$docker_compose"
        log_info "    ✓ Puerto Dashboard restaurado: $old_port"
    else
        log_warn "No se pudo detectar el puerto previo, se mantendrá el de la nueva versión."
    fi
    if docker compose -f "$docker_compose" config -q 2>/dev/null; then
        log_info "✅ Validación de sintaxis Docker exitosa."
    else
        log_error "El archivo generado no es válido. Revisa manualmente $docker_compose"
        exit 1
    fi
}

perform_git_update() {
    echo "----------------------------------------------------------------"
    log_info "Actualizando repositorio Git..."

    cd "$WAZUH_DIR"

    log_info "    → Verificar estado actual..."
    CURRENT_VERSION=$(git describe --tags 2>/dev/null || echo "Desconocida")
    log_info "Versión actual: $CURRENT_VERSION"

    log_info "    → Cambiar a la versión objetivo $TARGET_VERSION ..."
    git reset --hard HEAD
    git clean -fd
    git checkout "$TARGET_VERSION"

    log_info "Repositorio actualizado ✓"
}

start_services() {
    echo "$HR"
    log_info "Iniciando servicios..."
    cd "$MULTI_NODE"
    read -p "¿Deseas iniciar los servicios ahora? (s/n): " start_confirm
    if [[ $start_confirm =~ ^[sS]$ ]]; then
        docker compose up -d
        sleep 5
        docker ps --format "table {{.Names}}\t{{.Status}}"
    fi
}

verify_upgrade() {
    echo "$HR"
    log_info "=== VERIFICACIÓN FINAL ==="
    grep "image: wazuh/" "$MULTI_NODE/docker-compose.yml" | sort -u
    
    local user_file="$MULTI_NODE/config/wazuh_indexer/internal_users.yml"
    [ -f "$user_file" ] && log_info "Usuarios Indexer: $(grep -c "hash:" "$user_file")"
    
    local cert_count=$(find "$MULTI_NODE/config/wazuh_indexer_ssl_certs" -type f | wc -l)
    log_info "Certificados SSL detectados: $cert_count"
    echo "$HR"
}

cleanup_old_images() {
    echo "----------------------------------------------------------------"
    if [[ "$CURRENT_VERSION" != "$TARGET_VERSION" ]]; then
        echo ""
        read -p "[?] ¿Deseas eliminar las imágenes antiguas ($CURRENT_VERSION) para liberar espacio? (s/n): " CLEANUP
        if [[ "$CLEANUP" =~ ^([sS][iI]|[sS])$ ]]; then
            log_info "Eliminando imágenes obsoletas..."
            # Usamos docker rmi con las variables dinámicas
            docker image rm "wazuh/wazuh-manager:${CURRENT_VERSION#v}" \
                            "wazuh/wazuh-indexer:${CURRENT_VERSION#v}" \
                            "wazuh/wazuh-dashboard:${CURRENT_VERSION#v}" 2>/dev/null || \
            log_warn "Nota: Algunas imágenes no pudieron ser eliminadas (pueden estar en uso)."
        fi
    fi
}

# EJECUCIÓN PRINCIPAL

upgrade_agents() {
    echo "$HR"
    log_info "PROCESO DE ACTUALIZACIÓN DE AGENTES"
    
    local MASTER_ID=$(docker ps --filter "name=wazuh.master" -q | head -n 1)
    [[ -z "$MASTER_ID" ]] && { log_error "Master no encontrado"; exit 1; }

    local AGENTS=$(docker exec "$MASTER_ID" /var/ossec/bin/agent_upgrade -l 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1}')

    if [ -z "$AGENTS" ]; then
        log_info "✅ Todos los agentes están al día."
    else
        log_info "Enviando upgrade a: [ $(echo $AGENTS | xargs) ]"
        local RESULT=$(docker exec "$MASTER_ID" /var/ossec/bin/agent_upgrade -a $(echo $AGENTS | xargs) 2>&1)
        echo "$RESULT"

        if echo "$RESULT" | grep -iq "lock restart error"; then
            log_warn "⚠️ Se detectó un 'Lock Restart Error'."
            read -p "¿Forzar reinicio (-R) de algún agente? (s/n): " confirm
            if [[ $confirm =~ ^[sS]$ ]]; then
                read -p "Introduce el ID: " TARGET_ID
                docker exec "$MASTER_ID" /var/ossec/bin/agent_control -R -u "$TARGET_ID"
            fi
        fi
    fi
    echo "$HR"
}

show_help() {
    echo -e "Uso: $0 [opciones]\n"
    echo "Opciones:"
    echo "  -a [ID]  Actualizar agentes (deja ID vacío para todos)"
    echo "  -h       Mostrar esta ayuda"
}

main() {
    local AGENT_ONLY=false
    local SPECIFIC_AGENT_ID=""
    
    while getopts "ah" opt; do
        case $opt in
            a) 
                AGENT_ONLY=true
                if [[ -n "${!OPTIND:-}" && ! "${!OPTIND}" =~ ^- ]]; then
                    SPECIFIC_AGENT_ID="${!OPTIND}"
                    OPTIND=$((OPTIND + 1))
                fi
                ;;
            h) show_help; exit 0 ;;
            *) show_help; exit 1 ;;
        esac
    done

    if [ "$AGENT_ONLY" = true ]; then
        upgrade_agents "$SPECIFIC_AGENT_ID"
        exit 0
    fi
    
    clear
    echo "================================================================"
    echo "            ACTUALIZACIÓN SEGURA DE WAZUH DOCKER               "
    echo "================================================================"
    
    check_prerequisites
    get_target_version
    
    echo -e "Infraestructura: ${YELLOW}$WAZUH_DIR${NC}"
    echo -e "Objetivo:        ${GREEN}$TARGET_VERSION${NC}"
    echo -e "Backup:          ${YELLOW}$BACKUP_DIR${NC}"
    echo "$HR"

    read -p "¿Iniciar proceso? (s/n): " main_confirm
    [[ $main_confirm =~ ^[sS]$ ]] || exit 0

    backup_critical_files
    stop_services
    perform_git_update
    restore_critical_files
    start_services
    verify_upgrade
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi