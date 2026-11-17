

use std::collections::BTreeMap;
use frost_ed25519 as frost;

fn main() -> Result<(), frost::Error> {
    // Configuração do protocolo 2-de-3.
    let max_signers: u16 = 3;
    let min_signers: u16 = 2;

    let mut rng = rand::rngs::OsRng;

    println!("======================================");
    println!(" FROST - DKG 2 de 3");
    println!("======================================");

    // =====================================================
    // ETAPA 1: DKG - RODADA 1
    // Os três participantes geram seus pacotes iniciais.
    // =====================================================

    let mut round1_secret_packages = BTreeMap::new();
    let mut received_round1_packages = BTreeMap::new();

    for participant_index in 1..=max_signers {
        let participant_id: frost::Identifier =
            participant_index.try_into().expect("ID inválido");

        let (secret_package, public_package) =
            frost::keys::dkg::part1(
                participant_id,
                max_signers,
                min_signers,
                &mut rng,
            )?;

        round1_secret_packages.insert(participant_id, secret_package);

        // Distribuição dos pacotes públicos.
        for receiver_index in 1..=max_signers {
            if receiver_index == participant_index {
                continue;
            }

            let receiver_id: frost::Identifier =
                receiver_index.try_into().expect("ID inválido");

            received_round1_packages
                .entry(receiver_id)
                .or_insert_with(BTreeMap::new)
                .insert(participant_id, public_package.clone());
        }

        println!(
            "[DKG] Participante {}: rodada 1 concluída",
            participant_index
        );
    }

    // =====================================================
    // ETAPA 2: DKG - RODADA 2
    // =====================================================

    let mut round2_secret_packages = BTreeMap::new();
    let mut received_round2_packages = BTreeMap::new();

    for participant_index in 1..=max_signers {
        let participant_id: frost::Identifier =
            participant_index.try_into().expect("ID inválido");

        let secret_package = round1_secret_packages
            .remove(&participant_id)
            .expect("Pacote secreto não encontrado");

        let packages = &received_round1_packages[&participant_id];

        let (round2_secret, round2_packages) =
            frost::keys::dkg::part2(secret_package, packages)?;

        round2_secret_packages.insert(participant_id, round2_secret);

        // Distribuição dos pacotes privados aos destinatários.
        for (receiver_id, package) in round2_packages {
            received_round2_packages
                .entry(receiver_id)
                .or_insert_with(BTreeMap::new)
                .insert(participant_id, package);
        }

        println!(
            "[DKG] Participante {}: rodada 2 concluída",
            participant_index
        );
    }

    // =====================================================
    // ETAPA 3: DKG - FINALIZAÇÃO
    // =====================================================

    let mut key_packages = BTreeMap::new();
    let mut pubkey_packages = BTreeMap::new();

    for participant_index in 1..=max_signers {
        let participant_id: frost::Identifier =
            participant_index.try_into().expect("ID inválido");

        let secret_package = &round2_secret_packages[&participant_id];
        let round1_packages = &received_round1_packages[&participant_id];
        let round2_packages = &received_round2_packages[&participant_id];

        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(
                secret_package,
                round1_packages,
                round2_packages,
            )?;

        key_packages.insert(participant_id, key_package);
        pubkey_packages.insert(participant_id, pubkey_package);

        println!(
            "[DKG] Participante {}: chave gerada",
            participant_index
        );
    }

    println!("\n[SUCESSO] DKG finalizado!");
    println!("Participantes: {}", max_signers);
    println!("Threshold: {}", min_signers);

    // Obtém a chave pública do grupo.
    let first_id: frost::Identifier =
        1u16.try_into().expect("ID inválido");

    let group_public_key = &pubkey_packages[&first_id];

    // Confirma que todos os participantes obtiveram a mesma chave pública.
    for (participant_id, public_package) in &pubkey_packages {
        assert_eq!(
            group_public_key.verifying_key(),
            public_package.verifying_key()
        );

        println!(
            "[OK] Chave pública do grupo confirmada para {:?}",
            participant_id
        );
    }

    // =====================================================
    // ETAPA 4: FROST - ASSINATURA DISTRIBUÍDA
    // TESTE ATUAL: PARTICIPANTES 2 E 3
    // =====================================================

    println!("\n======================================");
    println!(" ASSINATURA FROST");
    println!("======================================");

    let message = b"Teste de assinatura distribuida FROST 2-de-3";

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    // Somente os participantes 1 e 2 assinam.
    for participant_index in [1u16, 2u16] {
        let participant_id: frost::Identifier =
            participant_index.try_into().expect("ID inválido");

        let key_package = &key_packages[&participant_id];

        let (nonces, commitments) =
            frost::round1::commit(
                key_package.signing_share(),
                &mut rng,
            );

        nonces_map.insert(participant_id, nonces);
        commitments_map.insert(participant_id, commitments);

        println!(
            "[ASSINATURA] Participante {}: compromisso gerado",
            participant_index
        );
    }

    // O coordenador monta o pacote de assinatura.
    let signing_package =
        frost::SigningPackage::new(commitments_map, message);

   

    // Rodada 2: geração das partes da assinatura.
    let mut signature_shares = BTreeMap::new();

    let commitment_count = nonces_map.len();

    for (participant_id, nonces) in &nonces_map {
        let key_package = &key_packages[participant_id];

        match frost::round2::sign(
            &signing_package,
            nonces,
            key_package,
        ) {
           Ok(signature_share) => {
                signature_shares.insert(*participant_id, signature_share);

                 println!(
                    "[ASSINATURA] Participante {:?}: parte da assinatura gerada",
                     participant_id
                 );
           }

           Err(frost::Error::IncorrectNumberOfCommitments)
               if commitment_count < min_signers as usize =>
           {
                println!("\n[OK] Assinatura rejeitada.");
                println!("[OK] Quantidade insuficiente de participantes.");
                println!(
                    "Participantes disponíveis: {}",
                    commitment_count
                );
                println!("Threshold necessário: {}", min_signers);

                println!("\n======================================");
                println!(" TESTE NEGATIVO CONCLUÍDO COM SUCESSO");
                println!("======================================");

                return Ok(());
           }

           Err(error) => {
              return Err(error);
           }
       }
   }  

    // Agregação das partes.
    let group_signature =
        frost::aggregate(
            &signing_package,
            &signature_shares,
            group_public_key,
        )?;

    println!("\n[SUCESSO] Assinatura agregada!");

    // =====================================================
    // ETAPA 5: VERIFICAÇÃO CRIPTOGRÁFICA
    // =====================================================

    let valid = group_public_key
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();

    if valid {
        println!("[OK] Assinatura válida!");
        println!("[OK] Verificação realizada com a chave pública do grupo.");
    } else {
        println!("[ERRO] Assinatura inválida!");
    }

    assert!(valid, "A assinatura FROST não foi validada!");

    println!("\n======================================");
    println!(" TESTE FROST CONCLUÍDO COM SUCESSO");
    println!("======================================");

    Ok(())
}
