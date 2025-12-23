#!/bin/bash
# wazuh_act.sh - Actualización segura de Wazuh Docker manteniendo configuraciones

# Detenemos el script si hay error
set -euo pipefail

# CONFIGURACIÓN
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WAZUH_DIR="$PARENT_DIR/wazuh-docker"
MULTI_NODE="$WAZUH_DIR/multi-node"
BACKUP_NAME="wazuh-docker.backup.$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$PARENT_DIR/$BACKUP_NAME"

# Versión objetivo
TARGET_VERSION="Buscando..."

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# FUNCIONES

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

get_target_version() {
    cd "$WAZUH_DIR"
    log_info "Sincronizando tags del repositorio..."
    git fetch --all --tags --quiet

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
    log_info "Verificando prerrequisitos..."

    if [ ! -d "$WAZUH_DIR" ]; then
        log_error "No se encuentra $WAZUH_DIR"
        exit 1
    fi

    # Verificar Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker no está instalado"
        exit 1
    fi

    # Verificar Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose no está instalado"
        exit 1
    fi

    # Verificar Git
    if ! command -v git &> /dev/null; then
        log_error "Git no está instalado"
        exit 1
    fi

    log_info "Prerrequisitos OK ✓"
}

backup_critical_files() {
    log_info "Creando backup de archivos críticos..."

    # 1. Backup completo de wazuh-docker
    log_info "Creando backup completo en: $BACKUP_DIR"
    cp -ra "$WAZUH_DIR" "$BACKUP_DIR"

    log_info "Backup completado ✓"
    log_info "Backup guardado en: $BACKUP_DIR"
}

restore_critical_files() {
    log_info "Sincronizando configuración existente con la nueva versión..."

    local src_config="$BACKUP_DIR/multi-node/config"    # Tu config personalizada (del backup)
    local dest_config="$WAZUH_DIR/multi-node/config"    # La config activa en wazuh-docker
    
    # NUEVA UBICACIÓN: Dentro de la carpeta del script
    local nv_reference_dir="$SCRIPT_DIR/new_version_reference"
    local user_file="wazuh_indexer/internal_users.yml"

    if [ -d "$src_config" ]; then
        # 1. RESPALDO DE LA NUEVA VERSIÓN (Referencia de fábrica)
        log_info "  → Guardando originales de fábrica en: $nv_reference_dir"
        
        # Limpiamos referencia anterior si existe y creamos la nueva
        rm -rf "$nv_reference_dir"
        mkdir -p "$nv_reference_dir"
        
        # Copiamos la configuración de fábrica que acabamos de bajar con git
        cp -rp "$dest_config/." "$nv_reference_dir/"

        # 2. Validación de Seguridad: Conteo de Usuarios
        log_info "  → Validando integridad de usuarios internos..."
        local old_user_count=$(grep -c "hash:" "$src_config/$user_file" || echo "0")
        local new_user_count=$(grep -c "hash:" "$nv_reference_dir/$user_file" || echo "0")

        if [ "$old_user_count" -lt "$new_user_count" ]; then
            log_warn "  ! DISCREPANCIA: Tu backup tiene $old_user_count usuarios y la fábrica trae $new_user_count."
            read -p "¿Deseas continuar con tu configuración? (s/n): " user_confirm
            if [[ $user_confirm != "s" && $user_confirm != "S" ]]; then
                log_error "Actualización abortada por discrepancia de seguridad."
                exit 1
            fi
        fi

        # 3. Reporte de diferencias (Guardado también en la carpeta del script)
        local diff_report="$SCRIPT_DIR/upgrade_diff_$(date +%Y%m%d).log"
        log_info "  → Generando reporte de cambios en: $diff_report"
        
        # Comparamos tu backup vs la referencia de fábrica
        diff -r --brief "$src_config" "$nv_reference_dir" > "$diff_report" || true

        # 4. APLICAR TU PERSONALIZACIÓN (Limpieza total)
        log_info "  → Aplicando personalización sobre /config activo..."
        # Copiamos tu config sobre la carpeta activa. 
        # No usamos --backup porque ya tenemos la copia de fábrica en $nv_reference_dir
        cp -rp "$src_config/." "$dest_config/"
        
    else
        log_error "No se encontró la carpeta config en el backup."
        exit 1
    fi

    # Inyección de passwords en docker-compose
    update_docker_compose "$BACKUP_DIR"

    log_info "✅ Configuración sincronizada. Referencia de fábrica disponible en $nv_reference_dir"
}

stop_services() {
    log_info "Deteniendo servicios actuales..."

    if [ -d "$MULTI_NODE" ]; then
        cd "$MULTI_NODE"

        # Verificamos si hay contenedores corriendo antes de intentar detenerlos
        if docker compose ps -q | grep -q .; then
            log_warn "Se han detectado contenedores activos. Procediendo a realizar down..."
            docker compose down
            log_info "Servicios detenidos y contenedores eliminados ✓"
        else
            log_info "No hay servicios en ejecución. Continuando..."
        fi
    else
        log_error "No se pudo acceder a $MULTI_NODE para detener servicios."
        exit 1
    fi
}

update_docker_compose() {
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
    log_info "Actualizando repositorio Git..."

    cd "$MULTI_NODE"

    log_info "    → Verificar estado actual..."
    CURRENT_VERSION=$(git describe --tags 2>/dev/null || echo "Desconocida")
    log_info "Versión actual: $CURRENT_VERSION"

    log_info "    → Obtener todas las tags..."
    git fetch --all --tags

    log_info "    → Verificar si la tag objetivo existe..."
    if ! git tag -l | grep -q "^$TARGET_VERSION$"; then
        log_error "La versión $TARGET_VERSION no existe"
        log_info "Versiones disponibles:"
        git tag -l | tail -10
        exit 1
    fi

    log_info "    → Cambiar a la versión objetivo $TARGET_VERSION ..."
    git reset --hard HEAD
    git clean -fd
    git checkout "$TARGET_VERSION"

    log_info "Repositorio actualizado ✓"
}

start_services() {
    log_info "Iniciando servicios..."

    cd "$MULTI_NODE"

    log_info "    → Verificar configuración Docker Compose..."
    docker compose config -q

    echo ""
    read -p "¿Deseas iniciar los servicios? (s/n): " start_confirm
    if [[ $start_confirm != "s" && $start_confirm != "S" ]]; then
        log_warn "Servicios no iniciados. Puedes iniciarlos manualmente después."
        return
    fi

    log_info "    → Iniciar servicios..."
    docker compose up -d

    log_info "    → Verificar estado de contenedores..."
    sleep 5
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

    log_info "    → Mostrar logs iniciales (Ctrl+C para salir)..."
    echo ""
    log_warn "=== LOGS DASHBOARD ==="
    timeout 10 docker logs -f multi-node-wazuh.dashboard-1 2>/dev/null || true

    echo ""
    log_warn "=== LOGS INDEXER 1 ==="
    timeout 10 docker logs -f multi-node-wazuh1.indexer-1 2>/dev/null || true

    log_info "Servicios iniciados ✓"
}

verify_upgrade() {
    log_info "Verificando actualización..."

    echo ""
    log_warn "=== VERIFICACIÓN FINAL ==="

    log_info "    → Versiones en docker-compose.yml:"
    grep "image: wazuh/" "$MULTI_NODE/docker-compose.yml" | sort -u | sed 's/^[[:space:]]*//'

    log_info "    → Puertos configurados críticos:"
    # Buscamos las líneas de puertos (ej: "1514:1514") limpiando espacios y duplicados
    grep -E '^[[:space:]]*- "[0-9]+:[0-9]+' "$MULTI_NODE/docker-compose.yml" | sed 's/^[[:space:]]*//; s/- "//; s/"//' | sort -u

    log_info "    → Integridad de internal_users.yml:"
    local user_file="$MULTI_NODE/config/wazuh_indexer/internal_users.yml"
    if [ -f "$user_file" ]; then
        local USER_COUNT=$(grep -c "hash:" "$user_file")
        log_info "Usuarios detectados en el indexer: $USER_COUNT"
    else
        log_error "No se encontró internal_users.yml"
    fi

    log_info "    → Estado de Certificados SSL:"
    local CERT_DIR="$MULTI_NODE/config/wazuh_indexer_ssl_certs"
    if [ -d "$CERT_DIR" ]; then
        # Contamos archivos .pem y .key
        local CERT_COUNT=$(find "$CERT_DIR" -type f \( -name "*.pem" -o -name "*.key" \) | wc -l)
        # ESTA ES LA LÍNEA QUE FALTABA O NO SE MOSTRABA:
        log_info "Total de archivos de identidad SSL en $CERT_DIR: $CERT_COUNT"
    else
        log_warn "No se encontró el directorio de certificados en $CERT_DIR"
    fi

    echo ""
    log_info "Backup de seguridad disponible en: $BACKUP_DIR"
    log_info "Actualización completada exitosamente! ✓"
}

cleanup_old_images() {
    # Solo si CURRENT_VERSION y TARGET_VERSION son distintas
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
    log_info "Iniciando proceso de actualización de agentes..."
    
    # 1. Buscar el contenedor Master
    local MASTER_ID=$(docker ps --filter "name=wazuh.master" -q | head -n 1)

    if [ -z "$MASTER_ID" ]; then
        log_error "Contenedor 'wazuh.master' no detectado. ¿Están los servicios activos?"
        exit 1
    fi

    # 2. Verificación de Salud del Servicio (Security Check)
    log_info "Verificando que el Manager esté listo para gestionar upgrades..."
    local RETRIES=0
    local MAX_RETRIES=12
    local READY=false

    while [ $RETRIES -lt $MAX_RETRIES ]; do
        if docker exec "$MASTER_ID" /var/ossec/bin/wazuh-control status 2>&1 | grep -q "wazuh-modulesd is running"; then
            READY=true
            break
        fi
        log_info "  [i] Esperando al servicio (Intento $((RETRIES+1))/$MAX_RETRIES)..."
        sleep 10
        RETRIES=$((RETRIES + 1))
    done

    if [ "$READY" = false ]; then
        log_error "El servicio Wazuh no respondió a tiempo. Revisa los logs del contenedor master."
        exit 1
    fi

    # 3. Listado y actualización
    log_info "Consultando agentes que requieren actualización..."
    local PENDING_IDS=$(docker exec "$MASTER_ID" /var/ossec/bin/agent_upgrade -l 2>/dev/null | grep "ID:" | awk '{print $2}' | sed 's/,//g' || true)

    if [ -z "$PENDING_IDS" ]; then
        log_info "✅ Todos los agentes están en la última versión disponible."
    else
        log_warn "Agentes pendientes detectados: $(echo $PENDING_IDS | tr '\n' ' ')"
        for AGENT_ID in $PENDING_IDS; do
            log_info "Actualizando Agente ID: $AGENT_ID..."
            docker exec "$MASTER_ID" /var/ossec/bin/agent_upgrade -a "$AGENT_ID" > /dev/null 2>&1 || \
            log_warn "Agente $AGENT_ID no disponible para upgrade."
        done
        log_info "✓ Tarea de agentes finalizada."
    fi
}

show_help() {
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -a    Actualizar solo los agentes (requiere clúster activo)"
    echo "  -h    Mostrar esta ayuda"
    echo "  (sin argumentos) Ejecutar actualización completa de infraestructura"
}

main() {

    local AGENT_ONLY=false
    
    while getopts "ah" opt; do
        case $opt in
            a) AGENT_ONLY=true ;;
            h) show_help; exit 0 ;;
            *) show_help; exit 1 ;;
        esac
    done

    if [ "$AGENT_ONLY" = true ]; then
        upgrade_agents
        exit 0
    fi
    
    clear
    echo "========================================="
    echo "  ACTUALIZACIÓN SEGURA DE WAZUH DOCKER  "
    echo "========================================="
    
    check_prerequisites
    get_target_version  # Definimos TARGET_VERSION antes del resumen
    
    echo "-----------------------------------------"
    echo "Directorio: $WAZUH_DIR"
    echo "Objetivo:   $TARGET_VERSION"
    echo "Backup:     $BACKUP_DIR"
    echo "-----------------------------------------"

    read -p "¿Proceder con la actualización? (s/n): " main_confirm
    [[ $main_confirm != "s" ]] && exit 0

    backup_critical_files
    stop_services
    perform_git_update
    restore_critical_files
    start_services
    verify_upgrade
    cleanup_old_images
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi