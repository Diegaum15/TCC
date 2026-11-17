#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

ROUNDS=30
OUT_CSV="resultados_tcc_frost_vs_ssh.csv"

echo "cenario,abordagem,rodada,latencia_ms,tx_bytes,rx_bytes,sucesso" > "$OUT_CSV"

aplicar_latencia() {
    local delay="$1"
    for node in frost-node-1 frost-node-2 frost-node-3 ssh-client; do
        docker exec "$node" tc qdisc del dev eth0 root 2>/dev/null || true
        if [ "$delay" != "0ms" ]; then
            docker exec "$node" tc qdisc add dev eth0 root netem delay "$delay"
        fi
    done
}

# Reinicia os nós limpos e executa o DKG uma única vez
docker compose up -d --force-recreate frost-node-1 frost-node-2 frost-node-3
sleep 2
docker compose run --rm frost-coordinator ./target/release/frost_coordinator dkg

for cenario_info in "LAN_0ms:0ms" "WAN_50ms:50ms" "WAN_100ms:100ms"; do
    CENARIO="${cenario_info%%:*}"
    DELAY="${cenario_info##*:}"

    echo "=== Executando cenário: $CENARIO (atraso: $DELAY) ==="
    aplicar_latencia "$DELAY"

    # 1. Benchmark FROST 2-de-3 (30 rodadas)
    for i in $(seq 1 $ROUNDS); do
        OUTPUT=$(docker compose run --rm frost-coordinator ./target/release/frost_coordinator sign 1 2 2>/dev/null)
        LAT=$(echo "$OUTPUT" | awk -F'Latencia_ms: ' '{print $2}' | awk '{print $1}')
        TX=$(echo "$OUTPUT" | awk -F'TX_bytes: ' '{print $2}' | awk '{print $1}')
        RX=$(echo "$OUTPUT" | awk -F'RX_bytes: ' '{print $2}' | awk '{print $1}')
        echo "$CENARIO,FROST_2de3,$i,$LAT,$TX,$RX,1" >> "$OUT_CSV"
    done

    # 2. Benchmark SSH Convencional (30 rodadas)
    for i in $(seq 1 $ROUNDS); do
        START_NS=$(date +%s%N)
        if docker exec ssh-client ssh -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no -p 2222 tccuser@ssh-server "exit" 2>/dev/null; then
            END_NS=$(date +%s%N)
            LAT_MS=$(LC_ALL=C awk "BEGIN {printf \"%.3f\", ($END_NS - $START_NS)/1000000}")
            echo "$CENARIO,SSH_Convencional,$i,$LAT_MS,0,0,1" >> "$OUT_CSV"
        else
            echo "$CENARIO,SSH_Convencional,$i,0,0,0,0" >> "$OUT_CSV"
        fi
    done

    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" frost-node-1 frost-node-2 frost-node-3 ssh-server > "recursos_${CENARIO}.txt"
done

aplicar_latencia "0ms"
echo "Concluído! Dados salvos em $OUT_CSV"
