
use frost_dkg::tls;
use frost_ed25519 as frost;

use rand::rngs::OsRng;
use std::collections::BTreeMap;
use frost::round1::SigningNonces;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

const PARTICIPANTS: [(u16, &str); 3] = [
    (1, "frost-node-1:5000"),
    (2, "frost-node-2:5000"),
    (3, "frost-node-3:5000"),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Uso: frost_node <id> <porta>");
        std::process::exit(1);
    }

    let node_id = &args[1];
    let port: u16 = args[2].parse()?;

    let participant_index: u16 = node_id.parse()?;
    let participant_identifier: frost::Identifier =
        participant_index.try_into()?;

    let certificate_path = "/app/certs/identity/cert.pem";
    let private_key_path = "/app/certs/identity/key.pem";
    let ca_path = "/app/certs/ca.crt";

    // Configuração TLS para receber conexões.
    let tls_server_config = tls::server_config(
        certificate_path,
        private_key_path,
        ca_path,
    )?;

    // Configuração mTLS para enviar pacotes aos outros nós.
    let tls_client_config = tls::client_config(
        certificate_path,
        private_key_path,
        ca_path,
    )?;

    let address = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&address)?;

    // Pacote secreto da Round 1: nunca é transmitido.
    let mut round1_secret_package:
        Option<frost::keys::dkg::round1::SecretPackage> = None;

    // Pacotes públicos recebidos dos outros participantes.
    let mut round1_public_packages:
        Option<BTreeMap<
            frost::Identifier,
            frost::keys::dkg::round1::Package,
        >> = None;

    // Pacote secreto da Round 2: nunca é transmitido.
    let mut round2_secret_package:
        Option<frost::keys::dkg::round2::SecretPackage> = None;

    // Pacotes individuais da Round 2 recebidos dos outros participantes.
    let mut round2_public_packages:
        BTreeMap<
            frost::Identifier,
            frost::keys::dkg::round2::Package,
        > = BTreeMap::new();

    // Chave privada compartilhada do participante, gerada ao finalizar o DKG.
    let mut key_package:
    	Option<frost::keys::KeyPackage> = None;

    // Informações públicas compartilhadas do grupo FROST.
    let mut public_key_package:
    	Option<frost::keys::PublicKeyPackage> = None;

    // Nonces secretos da assinatura FROST.
    // Permanecem exclusivamente na memória deste participante.
    let mut signing_nonces: Option<SigningNonces> = None;


    // Compromissos públicos gerados por este nó na rodada atual (para validação).
    let mut signing_commitments: Option<frost::round1::SigningCommitments> = None;

    // Pacote público da operação de assinatura recebido do coordenador.
    let mut signing_package: Option<frost::SigningPackage> = None;

    println!(
        "[NÓ {}] Servidor mTLS aguardando conexões em {}",
        node_id, address
    );

    for connection in listener.incoming() {
        let stream = connection?;
        let peer = stream.peer_addr()?;

        println!(
            "[NÓ {}] Conexão recebida de {}",
            node_id, peer
        );

        let tls_stream = tls::accept_tls(
            stream,
            tls_server_config.clone(),
        )?;

        let mut reader = BufReader::new(tls_stream);
        let mut message = String::new();

        reader.read_line(&mut message)?;

        let message = message.trim();

	let (command, argument) = message
             .split_once(' ')
    	     .unwrap_or((message, ""));

        println!(
            "[NÓ {}] Comando recebido: {}",
            node_id, command
        );

        match command {
            "PING" => {
                reader.get_mut().write_all(b"PONG\n")?;
                reader.get_mut().flush()?;
            }

	    // ASSINATURA FROST: ROUND 1 (GERAÇÃO DOS COMPROMISSOS)
            // =====================================================
            "SIGN_COMMIT" => {
                // Verifica se o DKG já foi finalizado.
                let signing_key_package = match key_package.as_ref() {
                    Some(package) => package,
                    None => {
                        reader.get_mut().write_all(
                            b"ERROR DKG_NOT_FINALIZED\n"
                        )?;
                        reader.get_mut().flush()?;
                        continue;
                    }
                };

                // Impede a geração de novos nonces enquanto
                // houver uma operação de assinatura pendente.
                if signing_nonces.is_some() {
                    reader.get_mut().write_all(
                        b"ERROR SIGNING_ALREADY_PENDING\n"
                    )?;
                    reader.get_mut().flush()?;
                    continue;
                }

                println!(
                    "[FROST] Nó {} iniciando geração dos compromissos.",
                    participant_index
                );

                // Gera os nonces secretos e os compromissos públicos.
                let mut rng = OsRng;

                let (nonces, commitments) =
                    frost::round1::commit(
                        signing_key_package.signing_share(),
                        &mut rng,
                    );

                // Serializa somente os compromissos públicos.
                let serialized_commitments = commitments.serialize()?;
                let encoded_commitments =
                    hex::encode(&serialized_commitments);

                // Mantém os nonces exclusivamente neste participante.
                signing_nonces = Some(nonces);
		signing_commitments = Some(commitments);

                println!(
                    "[FROST] Nó {} gerou seus compromissos.",
                    participant_index
                );

                println!(
                    "[FROST] Nonces secretos armazenados localmente."
                );

                let response = format!(
                    "SIGN_COMMIT {}\n",
                    encoded_commitments
                );

                reader.get_mut().write_all(response.as_bytes())?;
                reader.get_mut().flush()?;
            }

	    // ASSINATURA FROST: RECEBIMENTO DO SIGNING PACKAGE
            // =====================================================
            "SIGN_PACKAGE" => {
                let (Some(expected_commitments), true) =
                    (signing_commitments.as_ref(), signing_nonces.is_some())
                else {
                    reader.get_mut().write_all(b"ERROR NO_PENDING_SIGNING\n")?;
                    reader.get_mut().flush()?;
                    continue;
                };

                if signing_package.is_some() {
                    reader.get_mut().write_all(b"ERROR SIGN_PACKAGE_ALREADY_SET\n")?;
                    reader.get_mut().flush()?;
                    continue;
                }

                if argument.is_empty() {
                    reader.get_mut().write_all(b"ERROR MISSING_SIGN_PACKAGE\n")?;
                    reader.get_mut().flush()?;
                    continue;
                }

                let parsed_pkg = (|| -> Result<frost::SigningPackage, Box<dyn std::error::Error>> {
                    let bytes = hex::decode(argument)?;
                    let pkg = frost::SigningPackage::deserialize(&bytes)?;
                    Ok(pkg)
                })();

                let pkg = match parsed_pkg {
                    Ok(p) => p,
                    Err(_) => {
                        reader.get_mut().write_all(b"ERROR INVALID_SIGN_PACKAGE\n")?;
                        reader.get_mut().flush()?;
                        continue;
                    }
                };

                // Valida se o pacote inclui este nó e se o compromisso bate com o gerado localmente
                match pkg.signing_commitments().get(&participant_identifier) {
                    Some(received_comm) if received_comm == expected_commitments => {}
                    _ => {
                        // Por segurança, descarta os nonces se o pacote for inconsistente/adulterado
                        signing_nonces = None;
                        signing_commitments = None;
                        reader.get_mut().write_all(b"ERROR COMMITMENT_MISMATCH\n")?;
                        reader.get_mut().flush()?;
                        continue;
                    }
                }

                signing_package = Some(pkg);

                println!(
                    "[FROST] Nó {} validou e armazenou o SigningPackage.",
                    participant_index
                );

                reader.get_mut().write_all(b"SIGN_PACKAGE_OK\n")?;
                reader.get_mut().flush()?;
            }

            // =====================================================
            // ASSINATURA FROST: ROUND 2 (GERAÇÃO DO SIGNATURE SHARE)
            // =====================================================
            "SIGN_SHARE" => {
                let Some(signing_key_package) = key_package.as_ref() else {
                    reader.get_mut().write_all(b"ERROR DKG_NOT_FINALIZED\n")?;
                    reader.get_mut().flush()?;
                    continue;
                };

                // Consome imediatamente (take) os nonces, compromissos e pacote.
                // Garante que nunca haverá reutilização de nonces, mesmo em caso de falha.
                let (Some(nonces), Some(pkg), _) = (
                    signing_nonces.take(),
                    signing_package.take(),
                    signing_commitments.take(),
                ) else {
                    reader.get_mut().write_all(b"ERROR SIGNING_STATE_INCOMPLETE\n")?;
                    reader.get_mut().flush()?;
                    continue;
                };

                let signature_share = match frost::round2::sign(&pkg, &nonces, signing_key_package) {
                    Ok(share) => share,
                    Err(_) => {
                        reader.get_mut().write_all(b"ERROR SIGN_SHARE_FAILED\n")?;
                        reader.get_mut().flush()?;
                        continue;
                    }
                };

                let serialized_share = signature_share.serialize();
                let encoded_share = hex::encode(&serialized_share);

                println!(
                    "[FROST] Nó {} gerou sua parte da assinatura e destruiu os nonces.",
                    participant_index
                );

                let response = format!("SIGN_SHARE {}\n", encoded_share);
                reader.get_mut().write_all(response.as_bytes())?;
                reader.get_mut().flush()?;
            }

            // =====================================================
            // DISPONIBILIZAR PUBLIC KEY PACKAGE PARA O COORDENADOR
            // =====================================================
            "GET_PUBLIC_KEY" => {
                let Some(pub_pkg) = public_key_package.as_ref() else {
                    reader.get_mut().write_all(b"ERROR DKG_NOT_FINALIZED\n")?;
                    reader.get_mut().flush()?;
                    continue;
                };

                let serialized = pub_pkg.serialize()?;
                let encoded = hex::encode(&serialized);

                let response = format!("PUBLIC_KEY {}\n", encoded);
                reader.get_mut().write_all(response.as_bytes())?;
                reader.get_mut().flush()?;
            }

            // =====================================================
            // ROUND 1: geração do pacote público e secreto
            // =====================================================
            "ROUND1" => {
                if round1_secret_package.is_some() {
                    reader.get_mut().write_all(
                        b"ERROR ROUND1_ALREADY_EXECUTED\n"
                    )?;
                    reader.get_mut().flush()?;
                    continue;
                }

                println!(
                    "[DKG] Nó {} iniciando primeira rodada.",
                    node_id
                );

                let mut rng = OsRng;

                let (secret_package, public_package) =
                    frost::keys::dkg::part1(
                        participant_identifier,
                        3,
                        2,
                        &mut rng,
                    )?;

                let serialized_package = public_package.serialize()?;
                let encoded_package = hex::encode(&serialized_package);

                round1_secret_package = Some(secret_package);

                let response = format!("R1 {}\n", encoded_package);

                reader.get_mut().write_all(response.as_bytes())?;
                reader.get_mut().flush()?;

                println!(
                    "[DKG] Nó {} gerou seu pacote público.",
                    node_id
                );
                println!(
                    "[DKG] Pacote secreto mantido localmente."
                );
            }

            // =====================================================
            // ROUND 1: recebimento dos pacotes públicos
            // =====================================================
            "R1SET" => {
                if round1_secret_package.is_none() {
                    reader.get_mut().write_all(
                        b"ERROR ROUND1_NOT_EXECUTED\n"
                    )?;
                    reader.get_mut().flush()?;
                    continue;
                }

                if round1_public_packages.is_some() {
                    reader.get_mut().write_all(
                        b"ERROR R1SET_ALREADY_RECEIVED\n"
                    )?;
                    reader.get_mut().flush()?;
                    continue;
                }

                let encoded_packages = argument;

                let mut packages = BTreeMap::new();
                let mut valid = true;

                for entry in encoded_packages.split(',') {
                    let Some((id_text, package_hex)) =
                        entry.split_once(':')
                    else {
                        valid = false;
                        break;
                    };

                    let parsed = (|| -> Result<
                        (
                            frost::Identifier,
                            frost::keys::dkg::round1::Package,
                        ),
                        Box<dyn std::error::Error>,
                    > {
                        let index: u16 = id_text.parse()?;
                        let identifier: frost::Identifier =
                            index.try_into()?;

                        let bytes = hex::decode(package_hex)?;

                        let package =
                            frost::keys::dkg::round1::Package::deserialize(
                                &bytes
                            )?;

                        Ok((identifier, package))
                    })();

                    match parsed {
                        Ok((identifier, package)) => {
                            if identifier == participant_identifier {
                                continue;
                            }

                            if packages.insert(identifier, package).is_some() {
                                valid = false;
                                break;
                            }
                        }

                        Err(_) => {
                            valid = false;
                            break;
                        }
                    }
                }

                if !valid || packages.len() != 2 {
                    reader.get_mut().write_all(
                        b"ERROR INVALID_R1SET\n"
                    )?;
                    reader.get_mut().flush()?;
                    continue;
                }

                round1_public_packages = Some(packages);

                println!(
                    "[DKG] Nó {} armazenou os pacotes públicos dos outros participantes.",
                    node_id
                );

                reader.get_mut().write_all(b"R1SET_OK\n")?;
                reader.get_mut().flush()?;
            }

            // =====================================================
            // ROUND 2: gerar e enviar pacotes individuais
            // =====================================================
            "ROUND2" => {
                if round1_secret_package.is_none()
                    || round1_public_packages.is_none()
                {
                    reader.get_mut().write_all(
                        b"ERROR ROUND1_INCOMPLETE\n"
                    )?;
                    reader.get_mut().flush()?;
                    continue;
                }

                if round2_secret_package.is_some() {
                    reader.get_mut().write_all(
                        b"ERROR ROUND2_ALREADY_EXECUTED\n"
                    )?;
                    reader.get_mut().flush()?;
                    continue;
                }

                println!(
                    "[DKG] Nó {} iniciando segunda rodada.",
                    node_id
                );

                // Recupera o pacote secreto da Round 1.
                let secret_package =
                    round1_secret_package.take().unwrap();

                let received_round1 =
                    round1_public_packages.as_ref().unwrap();

                // Executa a segunda parte do DKG.
                let (secret_package_r2, outgoing_packages) =
                    frost::keys::dkg::part2(
                        secret_package,
                        received_round1,
                    )?;

                // Guarda o novo pacote secreto somente localmente.
                round2_secret_package = Some(secret_package_r2);

                println!(
                    "[DKG] Nó {} executou part2() com sucesso.",
                    node_id
                );

                // Envia um pacote específico para cada destinatário.
                let mut sent_count = 0;

                for (receiver_id, receiver_address) in PARTICIPANTS {
                    if receiver_id == participant_index {
                        continue;
                    }

                    let receiver_identifier: frost::Identifier =
                        receiver_id.try_into()?;

                    let Some(package) =
                        outgoing_packages.get(&receiver_identifier)
                    else {
                        return Err(format!(
                            "Pacote para o participante {} não encontrado",
                            receiver_id
                        ).into());
                    };

                    let serialized_package = package.serialize()?;
                    let encoded_package = hex::encode(&serialized_package);

                    let command = format!(
                        "R2 {} {}\n",
                        participant_index,
                        encoded_package
                    );

                    println!(
                        "[DKG] Nó {} enviando pacote individual ao nó {}.",
                        participant_index, receiver_id
                    );

                    let server_name =
                        receiver_address.split(':').next().unwrap();

                    let mut peer_stream = tls::connect_tls(
                        receiver_address,
                        server_name,
                        tls_client_config.clone(),
                    )?;

                    peer_stream.write_all(command.as_bytes())?;
                    peer_stream.flush()?;

                    let mut peer_reader = BufReader::new(peer_stream);
                    let mut response = String::new();

                    peer_reader.read_line(&mut response)?;

                    if response.trim() != "R2_OK" {
                        return Err(format!(
                            "Nó {} rejeitou pacote enviado pelo nó {}: {}",
                            receiver_id,
                            participant_index,
                            response.trim()
                        ).into());
                    }

                    println!(
                        "[DKG] Nó {} confirmou recebimento pelo nó {}.",
                        receiver_id, participant_index
                    );

                    sent_count += 1;
                }

                println!(
                    "[DKG] Nó {} concluiu o envio de {} pacotes.",
                    participant_index, sent_count
                );

                reader.get_mut().write_all(b"ROUND2_OK\n")?;
                reader.get_mut().flush()?;
            }

            // =====================================================
            // ROUND 2: receber pacote individual de outro nó
            // =====================================================
            "R2" => {
                let (sender_text, package_hex) = match argument.split_once(' ') {
                 	Some((s, p)) => (Some(s), Some(p)),
                 	None => (None, None),
             	};

                let parsed = (|| -> Result<
                    (
                        frost::Identifier,
                        frost::keys::dkg::round2::Package,
                    ),
                    Box<dyn std::error::Error>,
                > {
                    let sender_index: u16 = sender_text
                        .ok_or("Identificador do remetente ausente")?
                        .parse()?;

                    if !(1..=3).contains(&sender_index)
                        || sender_index == participant_index
                    {
                        return Err(
                            "Identificador de remetente inválido".into()
                        );
                    }

                    let sender_identifier: frost::Identifier =
                        sender_index.try_into()?;

                    let bytes = hex::decode(
                        package_hex.ok_or("Pacote ausente")?
                    )?;

                    let package =
                        frost::keys::dkg::round2::Package::deserialize(
                            &bytes
                        )?;

                    Ok((sender_identifier, package))
                })();

                match parsed {
                    Ok((sender_identifier, package)) => {
                        if round2_public_packages
                            .contains_key(&sender_identifier)
                        {
                            reader.get_mut().write_all(
                                b"ERROR R2_DUPLICATE\n"
                            )?;
                            reader.get_mut().flush()?;
                            continue;
                        }

                        round2_public_packages.insert(
                            sender_identifier,
                            package,
                        );

                        println!(
                            "[DKG] Nó {} recebeu pacote Round 2 do participante {}.",
                            participant_index,
                            sender_text.unwrap_or("?")
                        );

                        reader.get_mut().write_all(b"R2_OK\n")?;
                        reader.get_mut().flush()?;
                    }

                    Err(_) => {
                        reader.get_mut().write_all(
                            b"ERROR INVALID_R2\n"
                        )?;
                        reader.get_mut().flush()?;
                    }
                }
            }

            // =====================================================
            // CONSULTAR QUANTIDADE DE PACOTES ROUND 2 RECEBIDOS
            // =====================================================
            "R2STATUS" => {
                let count = round2_public_packages.len();

                let response = format!(
                    "R2STATUS {}\n",
                    count
                );

                reader.get_mut().write_all(response.as_bytes())?;
                reader.get_mut().flush()?;
            }

	    // =====================================================
	    // FINALIZAÇÃO DO DKG: execução da part3()
	   // =====================================================

	   "FINALIZE" => {
		    if key_package.is_some() {
		        reader.get_mut().write_all(
		            b"ERROR DKG_ALREADY_FINALIZED\n"
		        )?;
		        reader.get_mut().flush()?;
		        continue;
		    }

		    if round2_secret_package.is_none()
		        || round1_public_packages.is_none()
		        || round2_public_packages.len() != 2
		    {
		        reader.get_mut().write_all(
		            b"ERROR DKG_INCOMPLETE\n"
		        )?;
		        reader.get_mut().flush()?;
		        continue;
		    }

		    println!(
		        "[DKG] Nó {} iniciando finalização do DKG.",
		        participant_index
		    );

		    let secret_package = round2_secret_package
		        .as_ref()
		        .unwrap();

		    let received_round1 = round1_public_packages
		        .as_ref()
		        .unwrap();

		    // Executa a terceira e última parte do DKG.
		    let (generated_key_package, generated_public_key_package) =
		        frost::keys::dkg::part3(
		            secret_package,
		            received_round1,
		            &round2_public_packages,
		        )?;

		    // Serializa somente a chave pública do grupo para comparação.
		    let verifying_key = generated_public_key_package
		        .verifying_key()
		        .serialize()?;

		    let encoded_verifying_key = hex::encode(&verifying_key);

		    // Cada nó mantém sua própria chave privada compartilhada.
		    key_package = Some(generated_key_package);

		    // Guarda as informações públicas do grupo.
		    public_key_package = Some(generated_public_key_package);

		    println!(
		        "[DKG] Nó {} finalizou o DKG com sucesso.",
		        participant_index
		    );

		    println!(
		        "[DKG] Chave privada compartilhada mantida localmente."
		    );

		    let response = format!(
		        "FINALIZED {}\n",
		        encoded_verifying_key
		    );

		    reader.get_mut().write_all(response.as_bytes())?;
		    reader.get_mut().flush()?;
		}



            _ => {
                reader.get_mut().write_all(
                    b"ERROR UNKNOWN_COMMAND\n"
                )?;
                reader.get_mut().flush()?;
            }
        }
    }

    Ok(())
}
