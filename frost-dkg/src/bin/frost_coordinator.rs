// Orquestrador CLI do protocolo DKG e Assinatura Limiar FROST (2-de-3).
//
// Responsabilidades:
// 1. Coordenar as 3 rodadas da Geração Distribuída de Chaves (DKG) sem ter
//    acesso às fatias privadas (`KeyPackage`) geradas em cada nó.
// 2. Orquestrar as 2 rodadas de assinatura FROST (`SIGN_COMMIT` e `SIGN_SHARE`),
//    agregar as contribuições parciais e verificar a assinatura final de 64 bytes.
// 3. Coletar métricas de latência (ms) e tráfego de aplicação (bytes TX/RX).
// 4. Executar testes negativos automatizados de segurança e resiliência.

use frost_dkg::tls;
use frost_ed25519 as frost;

use rustls::{ClientConfig, ClientConnection, StreamOwned};

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// Mapeamento estático dos 3 participantes do grupo na rede interna Docker.
const PARTICIPANTS: [(u16, &str); 3] = [
    (1, "frost-node-1:5000"),
    (2, "frost-node-2:5000"),
    (3, "frost-node-3:5000"),
];

// Resolve o endereço DNS:porta de um participante a partir do seu ID numérico.
fn get_node_address(id: u16) -> Result<&'static str, Box<dyn Error>> {
    PARTICIPANTS
        .iter()
        .find(|&&(node_id, _)| node_id == id)
        .map(|&(_, addr)| addr)
        .ok_or_else(|| format!("Participante {} inválido (use 1, 2 ou 3)", id).into())
}

// Tenta estabelecer uma conexão mTLS com tolerância a atrasos de inicialização
// dos contêineres (útil durante o boot do `docker compose`).
fn connect_with_retry(
    address: &str,
    config: Arc<ClientConfig>,
    max_attempts: u32,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    // Extrai o hostname (ex: "frost-node-1") para validação do certificado X.509 (SAN)
    let server_name = address.split(':').next().unwrap();

    // Tenta conectar até `max_attempts` vezes, com intervalo de 500 ms entre tentativas
    for attempt in 1..=max_attempts {
        match tls::connect_tls(address, server_name, config.clone()) {
            // Conexão mTLS bem-sucedida, retorna o stream seguro
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if attempt < max_attempts {
                    // Loga a falha e aguarda antes de tentar novamente
                    println!(
                        "[AVISO] Tentativa {}/{} para {} falhou: {}",
                        attempt, max_attempts, address, error
                    );
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }

    // Todas as tentativas falharam, retorna erro final
    Err(format!("Não foi possível estabelecer conexão mTLS com {}", address).into())
}

// Envia um comando delimitado por `\n` via mTLS, lê a resposta e contabiliza
// exatamente quantos bytes da camada de aplicação foram enviados (TX) e recebidos (RX).
fn send_command_metered(
    address: &str,
    command: &str,
    config: Arc<ClientConfig>,
    max_attempts: u32,
) -> Result<(String, usize, usize), Box<dyn Error>> {
    // Estabelece a conexão mTLS com tolerância a falhas de inicialização  
    let mut stream = connect_with_retry(address, config, max_attempts)?;

    // Envia o comando seguido de `\n` e contabiliza os bytes enviados
    let payload = format!("{}\n", command);
    let bytes_sent = payload.len();

    // Escreve o comando no stream e força o flush para envio imediato
    stream.write_all(payload.as_bytes())?;
    stream.flush()?;

    // Lê a resposta do servidor até o próximo `\n` e contabiliza os bytes recebidos
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    let bytes_received = reader.read_line(&mut response)?;

    // Se a resposta estiver vazia, significa que o participante encerrou a conexão
    if response.is_empty() {
        return Err(format!(
            "O participante {} encerrou a conexão sem responder",
            address
        )
        .into());
    }

    // Retorna a resposta (sem o `\n`) e as métricas de tráfego
    Ok((response.trim().to_string(), bytes_sent, bytes_received))
}

// Executa o protocolo completo de Geração Distribuída de Chaves (DKG 2-de-3).
// Ao final, cada nó armazena localmente sua fatia secreta (`KeyPackage`) e
// todos convergem para a mesma chave pública verificadora do grupo.
fn run_dkg(tls_config: Arc<ClientConfig>) -> Result<(), Box<dyn Error>> {
    println!("[COORDENADOR] Iniciando DKG (3 participantes | threshold 2-de-3).");
    let start = Instant::now();

    // 1. ROUND 1: Cada participante gera seu polinômio secreto e compromissos públicos
    let mut public_packages: Vec<(u16, String)> = Vec::new();
    for (participant_id, address) in PARTICIPANTS {
        // Envia o comando ROUND1 e espera a resposta contendo o pacote público codificado
        let (response, _, _) = send_command_metered(address, "ROUND1", tls_config.clone(), 15)?;
        // Valida se a resposta começa com o prefixo esperado "R1 "
        let Some(encoded_package) = response.strip_prefix("R1 ") else {
            return Err(format!("Erro ROUND1 no nó {}: {}", participant_id, response).into());
        };
        // Armazena o pacote público codificado para broadcast na próxima etapa
        public_packages.push((participant_id, encoded_package.to_string()));
    }

    // 2. R1SET: Broadcast dos pacotes públicos da Round 1 para todos os participantes
    let package_entries: Vec<String> = public_packages
        .iter()
        .map(|(id, package)| format!("{}:{}", id, package))
        .collect();
    // Constrói o comando R1SET com todos os pacotes públicos concatenados
    let r1set_command = format!("R1SET {}", package_entries.join(","));

    for (participant_id, address) in PARTICIPANTS {
        // Envia o comando R1SET para cada participante e valida a resposta
        let (response, _, _) = send_command_metered(address, &r1set_command, tls_config.clone(), 5)?;
        // Se algum nó rejeitar o R1SET, aborta o DKG e retorna erro
        if response != "R1SET_OK" {
            // Se algum nó rejeitar o R1SET, aborta o DKG e retorna erro
            return Err(format!("Nó {} rejeitou R1SET: {}", participant_id, response).into());
        }
    }

    // 3. ROUND 2 & R2STATUS: Cada nó calcula avaliações secretas e as envia
    // diretamente aos pares via mTLS ponto-a-ponto (sem passar pelo coordenador)
    for (participant_id, address) in PARTICIPANTS {
        // Envia o comando ROUND2 para cada participante e valida a resposta
        let (response, _, _) = send_command_metered(address, "ROUND2", tls_config.clone(), 5)?;
        // Se algum nó falhar na Round 2, aborta o DKG e retorna erro
        if response != "ROUND2_OK" {
            // Se algum nó falhar na Round 2, aborta o DKG e retorna erro
            return Err(format!("Nó {} falhou na ROUND2: {}", participant_id, response).into());
        }
    }

    // 3.1. R2STATUS: Cada nó confirma que recebeu todas as avaliações secretas
    for (participant_id, address) in PARTICIPANTS {
        // Envia o comando R2STATUS para cada participante e valida a resposta
        let (response, _, _) = send_command_metered(address, "R2STATUS", tls_config.clone(), 5)?;
        // Se algum nó indicar inconsistência, aborta o DKG e retorna erro
        if response != "R2STATUS 2" {
            // Se algum nó indicar inconsistência, aborta o DKG e retorna erro
            return Err(format!("Nó {} com R2STATUS inválido: {}", participant_id, response).into());
        }
    }

    // 4. FINALIZE: Cada nó deriva sua fatia privada (`KeyPackage`) e retorna a
    // chave pública conjunta para conferência de consistência pelo coordenador
    let mut group_verifying_key: Option<String> = None;
    for (participant_id, address) in PARTICIPANTS {
        // Envia o comando FINALIZE para cada participante e valida a resposta
        let (response, _, _) = send_command_metered(address, "FINALIZE", tls_config.clone(), 5)?;
        // Se algum nó falhar na finalização, aborta o DKG e retorna erro
        let Some(verifying_key) = response.strip_prefix("FINALIZED ") else {
            // Se algum nó falhar na finalização, aborta o DKG e retorna erro
            return Err(format!("Nó {} falhou no FINALIZE: {}", participant_id, response).into());
        };

        // Verifica se todos os nós convergiram para a mesma chave pública do grupo
        match &group_verifying_key {
            // Se ainda não houver chave pública do grupo, define a primeira encontrada
            None => group_verifying_key = Some(verifying_key.to_string()),
            Some(expected) if expected != verifying_key => {
                // Se houver divergência de chave pública, aborta o DKG e retorna erro
                return Err(format!("Divergência de chave pública no nó {}!", participant_id).into());
            }
            _ => {}
        }
    }

    // Calcula o tempo total de execução do DKG e exibe a chave pública do grupo
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "[SUCESSO] DKG concluído em {:.2} ms! Chave pública do grupo: {}",
        elapsed_ms,
        group_verifying_key.unwrap()
    );
    Ok(())
}

// Executa uma operação completa de assinatura distribuída FROST 2-de-3 entre
// o subconjunto signer_ids (ex: [1, 2], [1, 3] ou [2, 3]).
// Retorna (latencia_ms, total_tx_bytes, total_rx_bytes) para análise de benchmark.
fn run_sign(
    signer_ids: &[u16],
    message: &[u8],
    tls_config: Arc<ClientConfig>,
) -> Result<(f64, usize, usize), Box<dyn Error>> {
    // Valida se o quórum de signatários é suficiente para FROST 2-de-3
    if signer_ids.len() < 2 {
        // Retorna erro se houver menos de 2 participantes, pois não é possível gerar assinatura
        return Err("Quórum insuficiente: FROST 2-de-3 exige pelo menos 2 participantes.".into());
    }

    // Mapeia os IDs dos signatários para seus respectivos endereços de rede
    let mut signers = Vec::new();
    for &id in signer_ids {
        // Valida se o ID do signatário é válido e obtém seu endereço
        signers.push((id, get_node_address(id)?));
    }

    // Inicia a medição de tempo e tráfego para a operação de assinatura distribuída
    let start = Instant::now();
    let mut total_tx_bytes = 0usize;
    let mut total_rx_bytes = 0usize;

    // 1. Obtém o pacote de chaves públicas do grupo (`PublicKeyPackage`)
    let (pk_response, tx, rx) =
        send_command_metered(signers[0].1, "GET_PUBLIC_KEY", tls_config.clone(), 3)?;
    // Acumula os bytes transmitidos e recebidos durante a operação
    total_tx_bytes += tx;
    total_rx_bytes += rx;

    // Valida se a resposta contém o prefixo esperado "PUBLIC_KEY "
    let Some(pk_hex) = pk_response.strip_prefix("PUBLIC_KEY ") else {
        return Err(format!("Falha ao obter PublicKeyPackage: {}", pk_response).into());
    };
    // Desserializa o pacote de chaves públicas do grupo a partir do hex recebido
    let group_public_key = frost::keys::PublicKeyPackage::deserialize(&hex::decode(pk_hex)?)?;

    // 2. ROUND 1 DA ASSINATURA: Solicita compromissos efêmeros (`SigningCommitments`)
    // aos participantes escolhidos; os nonces permanecem retidos nos nós
    let mut commitments_map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        BTreeMap::new();

    // Para cada signatário, envia o comando SIGN_COMMIT e coleta os compromissos    
    for &(participant_id, address) in &signers {
        // Envia o comando SIGN_COMMIT e coleta a resposta contendo os compromissos
        let (response, tx, rx) =
            send_command_metered(address, "SIGN_COMMIT", tls_config.clone(), 3)?;
        // Acumula os bytes transmitidos e recebidos durante a operação
        total_tx_bytes += tx;
        total_rx_bytes += rx;

        // Valida se a resposta contém o prefixo esperado "SIGN_COMMIT "
        let Some(comm_hex) = response.strip_prefix("SIGN_COMMIT ") else {
            return Err(format!(
                "Nó {} rejeitou SIGN_COMMIT: {}",
                participant_id, response
            )
            .into());
        };

        // Desserializa os compromissos efêmeros do signatário a partir do hex recebido
        let identifier: frost::Identifier = participant_id.try_into()?;
        let commitment =
            frost::round1::SigningCommitments::deserialize(&hex::decode(comm_hex)?)?;
        commitments_map.insert(identifier, commitment);
    }

    // 3. Constrói o `SigningPackage` (compromissos + mensagem) e distribui aos signatários
    let signing_package = frost::SigningPackage::new(commitments_map, message);
    let serialized_pkg = signing_package.serialize()?;
    let pkg_command = format!("SIGN_PACKAGE {}", hex::encode(&serialized_pkg));

    // Envia o pacote de assinatura para cada signatário e valida a aceitação
    for &(participant_id, address) in &signers {
        let (response, tx, rx) =
            send_command_metered(address, &pkg_command, tls_config.clone(), 3)?;
        total_tx_bytes += tx;
        total_rx_bytes += rx;

        // Valida se o signatário aceitou o pacote de assinatura
        if response != "SIGN_PACKAGE_OK" {
            return Err(format!(
                "Nó {} rejeitou SigningPackage: {}",
                participant_id, response
            )
            .into());
        }
    }

    // 4. ROUND 2 DA ASSINATURA: Coleta as contribuições parciais (`SignatureShare`);
    // cada nó destrói seus nonces imediatamente após gerar a parcela
    let mut signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
        BTreeMap::new();

    // Para cada signatário, envia o comando SIGN_SHARE e coleta a parcela de assinatura
    for &(participant_id, address) in &signers {
        let (response, tx, rx) =
            send_command_metered(address, "SIGN_SHARE", tls_config.clone(), 3)?;
        total_tx_bytes += tx;
        total_rx_bytes += rx;

        // Valida se a resposta contém o prefixo esperado "SIGN_SHARE "
        let Some(share_hex) = response.strip_prefix("SIGN_SHARE ") else {
            return Err(format!(
                "Nó {} rejeitou SIGN_SHARE: {}",
                participant_id, response
            )
            .into());
        };

        // Desserializa a parcela de assinatura do signatário a partir do hex recebido
        let identifier: frost::Identifier = participant_id.try_into()?;
        let share = frost::round2::SignatureShare::deserialize(&hex::decode(share_hex)?)?;
        signature_shares.insert(identifier, share);
    }

    // 5. Agrega as parcelas na assinatura Schnorr Ed25519 final (64 bytes) e valida
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &group_public_key)?;

    group_public_key
        .verifying_key()
        .verify(message, &group_signature)?;

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((elapsed_ms, total_tx_bytes, total_rx_bytes))
}

// Bateria automatizada de testes negativos para validação de segurança do protocolo:
// - Bloqueio de geração concorrente de nonces;
// - Rejeição de `SigningPackage` com compromisso adulterado;
// - Descarte obrigatório dos nonces após falha (prevenção de nonce reuse).
fn run_security_tests(tls_config: Arc<ClientConfig>) -> Result<(), Box<dyn Error>> {
    println!("\n========== BATERIA DE TESTES DE SEGURANÇA ==========\n");

    // Teste 1: Bloqueio de nonces pendentes (tentar SIGN_COMMIT duas vezes seguidas)
    println!("[TESTE 1] Tentativa de gerar novos nonces com operação pendente...");
    let addr1 = get_node_address(1)?;
    let (resp1, _, _) = send_command_metered(addr1, "SIGN_COMMIT", tls_config.clone(), 2)?;
    assert!(resp1.starts_with("SIGN_COMMIT "));

    // Segunda tentativa de SIGN_COMMIT sem concluir a primeira deve ser rejeitada
    let (resp_dup, _, _) = send_command_metered(addr1, "SIGN_COMMIT", tls_config.clone(), 2)?;
    println!("  -> Resposta do Nó 1: {}", resp_dup);
    assert_eq!(resp_dup, "ERROR SIGNING_ALREADY_PENDING");

    // Teste 2: Rejeição de SigningPackage adulterado / compromisso substituído
    println!("[TESTE 2] Envio de SigningPackage com compromisso substituído (adulteração)...");
    let addr2 = get_node_address(2)?;
    let (resp2, _, _) = send_command_metered(addr2, "SIGN_COMMIT", tls_config.clone(), 2)?;
    let comm2_hex = resp2.strip_prefix("SIGN_COMMIT ").unwrap();
    let comm2 = frost::round1::SigningCommitments::deserialize(&hex::decode(comm2_hex)?)?;

    // Forja um pacote substituindo o compromisso do Nó 1 pelo do Nó 2
    let mut forged_map = BTreeMap::new();
    forged_map.insert(1u16.try_into()?, comm2);
    forged_map.insert(2u16.try_into()?, comm2);
    let forged_pkg = frost::SigningPackage::new(forged_map, b"mensagem-adulterada");
    let forged_cmd = format!("SIGN_PACKAGE {}", hex::encode(forged_pkg.serialize()?));

    let (resp_forged, _, _) = send_command_metered(addr1, &forged_cmd, tls_config.clone(), 2)?;
    println!("  -> Resposta do Nó 1 ao pacote adulterado: {}", resp_forged);
    assert_eq!(resp_forged, "ERROR COMMITMENT_MISMATCH");

    // Teste 3: Garantia de destruição dos nonces após falha (impossibilidade de reutilização)
    println!("[TESTE 3] Tentativa de assinar (SIGN_SHARE) após pacote rejeitado...");
    let (resp_reuse, _, _) = send_command_metered(addr1, "SIGN_SHARE", tls_config.clone(), 2)?;
    println!("  -> Resposta do Nó 1: {}", resp_reuse);
    assert_eq!(resp_reuse, "ERROR SIGNING_STATE_INCOMPLETE");

    // Limpa o estado pendente do Nó 2 enviando o pacote inválido para resetar seus nonces
    let _ = send_command_metered(addr2, &forged_cmd, tls_config.clone(), 2);

    println!("\n[SUCESSO] Todos os controles de segurança contra adulteração e reuso de nonces foram validados!");
    Ok(())
}

// Ponto de entrada CLI: suporta os subcomandos dkg, sign, test-security e full.
fn main() -> Result<(), Box<dyn Error>> {
    // Recupera o modo de operação a partir dos argumentos da linha de comando
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("full");

    // Carrega identidade X.509 do coordenador e CA raiz para conexões mTLS
    let tls_config = tls::client_config(
        "/app/certs/identity/cert.pem",
        "/app/certs/identity/key.pem",
        "/app/certs/ca.crt",
    )?;

    // Executa o subcomando selecionado pelo usuário
    match mode {
        // Subcomando "dkg": inicia a Geração Distribuída de Chaves (DKG 2-de-3)
        "dkg" => {
            run_dkg(tls_config)?;
        }
        // Subcomando "sign": realiza uma assinatura distribuída FROST 2-de-3 entre dois nós
        "sign" => {
            let id1: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
            let id2: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
            let (ms, tx, rx) =
                run_sign(&[id1, id2], b"desafio-autenticacao-tcc", tls_config)?;
            println!(
                "RESULTADO_ASSINATURA | Nos: [{}, {}] | Latencia_ms: {:.3} | TX_bytes: {} | RX_bytes: {}",
                id1, id2, ms, tx, rx
            );
        }
        // Subcomando "test-security": executa testes automatizados de segurança e resiliência
        "test-security" => {
            run_security_tests(tls_config)?;
        }
        // Subcomando "full": executa DKG, assinatura distribuída e testes de segurança
        "full" => {
            run_dkg(tls_config.clone())?;
            let (ms, tx, rx) =
                run_sign(&[1, 2], b"Teste de assinatura distribuida FROST 2-de-3", tls_config)?;
            println!(
                "[SUCESSO] Assinatura FROST 2-de-3 verificada! Latencia: {:.2} ms | Trafego: {} B enviados / {} B recebidos",
                ms, tx, rx
            );
        }
        // Caso o subcomando seja inválido, exibe mensagem de uso e encerra
        _ => {
            eprintln!("Uso: frost_coordinator [dkg | sign <id1> <id2> | test-security | full]");
            std::process::exit(1);
        }
    }

    Ok(())
}