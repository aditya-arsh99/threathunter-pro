#!/bin/bash
# =============================================================
#  ThreatHunter Pro — Management Script
#  Usage: ./manage.sh [start|stop|restart|status|logs|clean]
# =============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

COMPOSE_FILE="docker-compose.yml"
PROJECT_NAME="threathunter"

banner() {
  echo -e "${CYAN}"
  echo "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗"
  echo "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝"
  echo "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   "
  echo "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   "
  echo "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   "
  echo "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   "
  echo -e "            ${RED}H U N T E R   P R O${NC}"
  echo ""
}

check_env() {
  if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  No .env file found. Copying from .env.example...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✅ .env created. Review passwords before production use.${NC}"
  fi
}

cmd_start() {
  banner
  check_env
  echo -e "${BLUE}🚀 Starting ThreatHunter Pro infrastructure...${NC}"
  echo ""
  docker compose -p $PROJECT_NAME -f $COMPOSE_FILE up -d --remove-orphans

  echo ""
  echo -e "${YELLOW}⏳ Waiting for services to be healthy (this may take ~60s)...${NC}"
  sleep 10

  echo ""
  echo -e "${GREEN}✅ Services started! Access points:${NC}"
  echo -e "   ${CYAN}📊 Kafka UI:       ${NC}http://localhost:8090"
  echo -e "   ${CYAN}🔍 Elasticsearch:  ${NC}http://localhost:9200"
  echo -e "   ${CYAN}📈 Kibana:         ${NC}http://localhost:5601"
  echo -e "   ${CYAN}🗄️  Redis UI:       ${NC}http://localhost:8091"
  echo ""
  echo -e "   ${YELLOW}Credentials: elastic / ThreatHunter@2024${NC}"
  echo ""
}

cmd_stop() {
  echo -e "${YELLOW}🛑 Stopping ThreatHunter Pro...${NC}"
  docker compose -p $PROJECT_NAME -f $COMPOSE_FILE stop
  echo -e "${GREEN}✅ All services stopped.${NC}"
}

cmd_restart() {
  cmd_stop
  sleep 3
  cmd_start
}

cmd_status() {
  banner
  echo -e "${BLUE}📋 Service Status:${NC}"
  docker compose -p $PROJECT_NAME -f $COMPOSE_FILE ps
}

cmd_logs() {
  SERVICE=${2:-""}
  if [ -z "$SERVICE" ]; then
    docker compose -p $PROJECT_NAME -f $COMPOSE_FILE logs -f --tail=50
  else
    docker compose -p $PROJECT_NAME -f $COMPOSE_FILE logs -f --tail=100 "$SERVICE"
  fi
}

cmd_clean() {
  echo -e "${RED}⚠️  This will REMOVE all containers AND volumes (all data will be lost).${NC}"
  read -p "Are you sure? (yes/no): " CONFIRM
  if [ "$CONFIRM" == "yes" ]; then
    docker compose -p $PROJECT_NAME -f $COMPOSE_FILE down -v --remove-orphans
    echo -e "${GREEN}✅ All containers and volumes removed.${NC}"
  else
    echo "Aborted."
  fi
}

cmd_health() {
  banner
  echo -e "${BLUE}🏥 Health Check:${NC}"
  echo ""

  # Elasticsearch
  ES_STATUS=$(curl -s -u "elastic:ThreatHunter@2024" http://localhost:9200/_cluster/health 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unreachable'))" 2>/dev/null || echo "unreachable")
  if [ "$ES_STATUS" == "green" ] || [ "$ES_STATUS" == "yellow" ]; then
    echo -e "   ${GREEN}✅ Elasticsearch: $ES_STATUS${NC}"
  else
    echo -e "   ${RED}❌ Elasticsearch: $ES_STATUS${NC}"
  fi

  # Kafka
  KAFKA_STATUS=$(docker exec threathunter-kafka kafka-broker-api-versions --bootstrap-server localhost:9092 > /dev/null 2>&1 && echo "ok" || echo "unreachable")
  if [ "$KAFKA_STATUS" == "ok" ]; then
    echo -e "   ${GREEN}✅ Kafka: running${NC}"
  else
    echo -e "   ${RED}❌ Kafka: $KAFKA_STATUS${NC}"
  fi

  # Redis
  REDIS_STATUS=$(docker exec threathunter-redis redis-cli ping 2>/dev/null || echo "unreachable")
  if [ "$REDIS_STATUS" == "PONG" ]; then
    echo -e "   ${GREEN}✅ Redis: PONG${NC}"
  else
    echo -e "   ${RED}❌ Redis: $REDIS_STATUS${NC}"
  fi

  # Kafka topics
  echo ""
  echo -e "${BLUE}📌 Kafka Topics:${NC}"
  docker exec threathunter-kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null | sed 's/^/   /'
}

case "$1" in
  start)    cmd_start ;;
  stop)     cmd_stop ;;
  restart)  cmd_restart ;;
  status)   cmd_status ;;
  logs)     cmd_logs "$@" ;;
  clean)    cmd_clean ;;
  health)   cmd_health ;;
  *)
    banner
    echo -e "Usage: ${GREEN}./manage.sh${NC} [command]"
    echo ""
    echo "Commands:"
    echo -e "  ${CYAN}start${NC}          Start all services"
    echo -e "  ${CYAN}stop${NC}           Stop all services"
    echo -e "  ${CYAN}restart${NC}        Restart all services"
    echo -e "  ${CYAN}status${NC}         Show container status"
    echo -e "  ${CYAN}logs [service]${NC} Tail logs (optionally for one service)"
    echo -e "  ${CYAN}health${NC}         Run health checks on all services"
    echo -e "  ${CYAN}clean${NC}          Remove all containers and volumes"
    echo ""
    ;;
esac
