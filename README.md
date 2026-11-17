# Autenticação Distribuída com Assinaturas Limiares FROST (2-de-3) em Rust

Prova de conceito e avaliação experimental desenvolvida como Trabalho de Conclusão de Curso (TCC) em Ciência da Computação (UFPR). O projeto implementa um protocolo distribuído de geração de chaves (DKG) e assinatura limiar **FROST** (*Flexible Round-Optimized Schnorr Threshold Signatures*) sobre **Ed25519** em esquema **2-de-3**, contrastando seu desempenho, tráfego de rede e propriedades de segurança frente à autenticação SSH convencional.

---

## Arquitetura do Sistema

O ambiente é orquestrado via Docker Compose e dividido em processos isolados que se comunicam exclusivamente por canais autenticados e criptografados via **TLS Mútuo (mTLS)** utilizando `rustls`:

* **`frost-node-1`, `frost-node-2`, `frost-node-3` (`src/bin/frost_node.rs`):** Participantes independentes que executam localmente as etapas do DKG (`part1`, `part2`, `part3`) e as rodadas de assinatura (`SIGN_COMMIT`, `SIGN_SHARE`). Cada nó retém sua fatia privada (`KeyPackage`) e seus *nonces* efêmeros exclusivamente em memória.
* **`frost-coordinator` (`src/bin/frost_coordinator.rs`):** Orquestrador CLI responsável por coordenar as rodadas do DKG, distribuir o `SigningPackage`, coletar as contribuições de assinatura de um quórum mínimo ($t = 2$) e agregar a assinatura final (`frost::aggregate`), sem nunca ter acesso às fatias privadas dos participantes.
* **`ssh-server` e `ssh-client`:** Ambiente de linha de base (*baseline*) baseado em OpenSSH com autenticação por chave pública única (`ssh-ed25519`) para comparação controlada de latência sob diferentes condições de rede.

### Controles de Segurança Implementados
1. **Isolamento de Segredos:** Nenhuma fatia privada (`KeyPackage`) ou *nonce* secreto trafega pela rede ou é exposto ao coordenador.
2. **Prevenção de Reutilização de Nonces (*Nonce Reuse*):** Os *nonces* gerados na rodada de compromisso são consumidos destrutivamente (`.take()`) na geração da assinatura ou descartados imediatamente em caso de erro.
3. **Validação de Integridade do Pacote:** Cada participante verifica se o `SigningPackage` recebido contém exatamente o compromisso público gerado localmente antes de assinar (`ERROR COMMITMENT_MISMATCH`).
4. **Aplicação de Quórum ($t = 2$ de $n = 3$):** O sistema tolera a indisponibilidade de até 1 participante e rejeita operações quando há menos de 2 nós disponíveis.

---

## Estrutura do Repositório

```text
tcc-ssh-lab/
├── docker-compose.yml                 # Orquestração dos nós FROST, coordenador e ambiente SSH
├── run_benchmarks.sh                  # Automação dos experimentos (30 rodadas x 3 cenários de rede)
├── gerar_graficos.py                  # Análise estatística e geração de gráficos (Pandas/Matplotlib)
├── frost-dkg/
│   ├── Dockerfile                     # Imagem Rust + iproute2 (tc/netem)
│   ├── Cargo.toml                     # Dependências (frost-ed25519, rustls, hex, rand)
│   └── src/
│       ├── lib.rs
│       ├── tls.rs                     # Configuração de servidor e cliente mTLS
│       └── bin/
│           ├── frost_node.rs          # Daemon participante do protocolo DKG e FROST
│           └── frost_coordinator.rs   # Orquestrador CLI (dkg, sign, test-security)
└── resultados/
    ├── resultados_tcc_frost_vs_ssh.csv # Dataset bruto (180 execuções)
    ├── estatisticas_resumo_tcc.csv     # Média, mediana, desvio padrão, mínimo e máximo
    ├── evidencias_seguranca.log        # Logs dos testes negativos e tolerância a falhas
    ├── recursos_LAN_0ms.txt            # Consumo de CPU/RAM (LAN)
    ├── recursos_WAN_50ms.txt           # Consumo de CPU/RAM (WAN 50 ms)
    ├── recursos_WAN_100ms.txt          # Consumo de CPU/RAM (WAN 100 ms)
    └── grafico_comparativo_latencia.png
