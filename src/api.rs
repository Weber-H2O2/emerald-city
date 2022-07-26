#![cfg(target_arch = "wasm32")]

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};


use crate::gg_2018::mta::*;
use crate::gg_2018::party_i::*;

use reqwest::Client;

use crate::curv::{
    arithmetic::traits::Converter,
    arithmetic::traits::ConvertFrom,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar}},
    arithmetic::num_bigint::BigInt,
};
use crate::curv::elliptic::curves::traits::{ECPoint, ECScalar};

use crate::paillier::EncryptionKey;
use sha2::Sha256;
use std::{fs, time};

use crate::log;
use crate::console_log;

use crate::common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params,
    PartySignup, AEAD, AES_KEY_BYTES_LEN, Entry,
};

pub async fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-keygen".to_string();

    console_log!("key {}", key);
    let res_body = postb(client, "signupkeygen", key).await.unwrap();
    console_log!("response body {}", res_body);
    serde_json::from_str(&res_body).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen(t: usize, n: usize, save_path: String) {
    let client = reqwest::Client::new();
    //let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold: t,
        share_count: n.clone(),
    };

    let PARTIES = n.clone() as u16;

    console_log!("signup");
    let (party_num_int, uuid) = match signup(&client).await.unwrap() {
        PartySignup {number, uuid} => (number, uuid),
    };

    let party_keys = Keys::create(party_num_int as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();
    console_log!("broadcast");
    assert!(broadcast(
            &client,
            party_num_int,
            "round1",
            serde_json::to_string(&bc_i).unwrap(),
            uuid.clone()
    ).await.is_ok());

    console_log!("poll_for_broadcasts");
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        //delay,
        "round1",
        uuid.clone(),
    ).await;

    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, bc_i);

    console_log!("broadcast round 2");
    // send ephemeral public keys and check commitments correctness
    assert!(broadcast(
            &client,
            party_num_int,
            "round2",
            serde_json::to_string(&decom_i).unwrap(),
            uuid.clone()
    ).await.is_ok());
    console_log!("poll_for_broadcasts round 2");
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        //delay,
        "round2",
        uuid.clone(),
    ).await;

    let mut j = 0;
    let mut point_vec: Vec<Point> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            point_vec.push(decom_i.y_i.clone());
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            point_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            let key_bn: BigInt = (decom_j.y_i.clone() * party_keys.u_i.clone())
                .x_coor()
                .unwrap();
            let key_bytes = BigInt::to_vec(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j += 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    console_log!("phase1_verify_com_phase3_verify_correct_key_phase2_distribute");
    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                    &client,
                    party_num_int,
                    i,
                    "round3",
                    serde_json::to_string(&aead_pack_i).unwrap(),
                    uuid.clone()
            ).await.is_ok());
            j += 1;
        }
    }

    console_log!("poll_for_p2p");
    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        PARTIES,
        //delay,
        "round3",
        uuid.clone(),
    ).await;

    let mut j = 0;
    let mut party_shares: Vec<Scalar> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes_be(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments
    console_log!("broadcast round 4");
    assert!(broadcast(
            &client,
            party_num_int,
            "round4",
            serde_json::to_string(&vss_scheme).unwrap(),
            uuid.clone()
    ).await.is_ok());
    console_log!("poll_for_broadcasts round 4");
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        //delay,
        "round4",
        uuid.clone(),
    ).await;

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    console_log!("phase2_verify_vss_construct_keypair_phase3_pok_dlog");
    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            &(party_num_int.clone() as usize), // FIXME
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    assert!(broadcast(
            &client,
            party_num_int,
            "round5",
            serde_json::to_string(&dlog_proof).unwrap(),
            uuid.clone()
    ).await.is_ok());
    let round5_ans_vec =
        poll_for_broadcasts(&client, party_num_int, PARTIES, /*delay,*/ "round5", uuid).await;

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof =
                serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
            party_keys,
            shared_keys,
            party_num_int,
            vss_scheme_vec,
            paillier_key_vec,
            y_sum,
    )).unwrap();
    console_log!("save {} to {}", keygen_json, save_path);

    //fs::write(save_path, keygen_json).expect("Unable to save !");
}

#[wasm_bindgen]
pub async fn gg18_sign(t: usize, n: usize, message_str: String, key: String) {

    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let client = Client::new();
    // delay:
    // let delay = time::Duration::from_millis(25);
    // read key file
    // let data = fs::read_to_string(env::args().nth(2).unwrap())
    //     .expect("Unable to load keys, did you run keygen first? ");
    let data = key;
    let (party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        usize,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        Vec<Point>,
    ) = serde_json::from_str(&data).unwrap();

    //read parameters:
    // let data = fs::read_to_string("params.json")
    //     .expect("Unable to read params, make sure config file is present in the same folder ");
    let params = Parameters {
        threshold: t,
        share_count: n.clone(),
    };

    let PARTIES = n.clone() as usize;

    let THRESHOLD = params.threshold.clone() as usize;

    // signup:
    let (party_num_int, uuid) = match signup(&client).await.unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    // round 0: collect signers IDs
    assert!(broadcast(
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone()
    )
    .await.is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD as u16 + 1,
        // delay,
        "round0",
        uuid.clone(),
    ).await;

    let mut j = 0;
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=THRESHOLD + 1 {
        if i == party_num_int as usize {
            signers_vec.push(party_id - 1);
        } else {
            let signer_j: usize = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push(signer_j - 1);
            j += 1;
        }
    }

    let private = PartyPrivate::set_private(party_keys.clone(), shared_keys);

    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[usize::from(signers_vec[usize::from(party_num_int - 1)])],
        signers_vec[usize::from(party_num_int - 1)],
        &signers_vec,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    //////////////////////////////////////////////////////////////////////////////
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &party_keys.ek, &[_; 0]);
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&(com.clone(), m_a_k)).unwrap(),
        uuid.clone()
    )
    .await.is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD as u16 + 1,
        // delay,
        "round1",
        uuid.clone(),
    ).await;

    // let mut j = 0;
    // let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    // let mut m_a_vec: Vec<MessageA> = Vec::new();

    // for i in 1..THRESHOLD + 2 {
    //     if i == party_num_int {
    //         bc1_vec.push(com.clone());
    //     //   m_a_vec.push(m_a_k.clone());
    //     } else {
    //         //     if signers_vec.contains(&(i as usize)) {
    //         let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
    //             serde_json::from_str(&round1_ans_vec[j]).unwrap();
    //         bc1_vec.push(bc1_j);
    //         m_a_vec.push(m_a_party_j);

    //         j += 1;
    //         //       }
    //     }
    // }
    // assert_eq!(signers_vec.len(), bc1_vec.len());

    // //////////////////////////////////////////////////////////////////////////////
    // let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    // let mut beta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    // let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    // let mut ni_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    // let mut j = 0;
    // for i in 1..THRESHOLD + 2 {
    //     if i != party_num_int {
    //         let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
    //             &sign_keys.gamma_i,
    //             &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
    //             m_a_vec[j].clone(),
    //             &[],
    //         )
    //         .unwrap();
    //         let (m_b_w, beta_wi, _, _) = MessageB::b(
    //             &sign_keys.w_i,
    //             &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
    //             m_a_vec[j].clone(),
    //             &[],
    //         )
    //         .unwrap();
    //         m_b_gamma_send_vec.push(m_b_gamma);
    //         m_b_w_send_vec.push(m_b_w);
    //         beta_vec.push(beta_gamma);
    //         ni_vec.push(beta_wi);
    //         j += 1;
    //     }
    // }

    // let mut j = 0;
    // for i in 1..THRESHOLD + 2 {
    //     if i != party_num_int {
    //         assert!(sendp2p(
    //             &client,
    //             party_num_int,
    //             i,
    //             "round2",
    //             serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
    //                 .unwrap(),
    //             uuid.clone()
    //         )
    //         .is_ok());
    //         j += 1;
    //     }
    // }

    // let round2_ans_vec = poll_for_p2p(
    //     &client,
    //     party_num_int,
    //     THRESHOLD + 1,
    //     // delay,
    //     "round2",
    //     uuid.clone(),
    // );

    // let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    // let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    // for i in 0..THRESHOLD {
    //     //  if signers_vec.contains(&(i as usize)) {
    //     let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
    //         serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
    //     m_b_gamma_rec_vec.push(m_b_gamma_i);
    //     m_b_w_rec_vec.push(m_b_w_i);
    //     //     }
    // }

    // let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    // let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    // let mut j = 0;
    // for i in 1..THRESHOLD + 2 {
    //     if i != party_num_int {
    //         let m_b = m_b_gamma_rec_vec[j].clone();

    //         let alpha_ij_gamma = m_b
    //             .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
    //             .expect("wrong dlog or m_b");
    //         let m_b = m_b_w_rec_vec[j].clone();
    //         let alpha_ij_wi = m_b
    //             .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
    //             .expect("wrong dlog or m_b");
    //         alpha_vec.push(alpha_ij_gamma.0);
    //         miu_vec.push(alpha_ij_wi.0);
    //         let g_w_i = Keys::update_commitments_to_xi(
    //             &xi_com_vec[usize::from(signers_vec[usize::from(i - 1)])],
    //             &vss_scheme_vec[usize::from(signers_vec[usize::from(i - 1)])],
    //             signers_vec[usize::from(i - 1)],
    //             &signers_vec,
    //         );
    //         assert_eq!(m_b.b_proof.pk, g_w_i);
    //         j += 1;
    //     }
    // }
    // //////////////////////////////////////////////////////////////////////////////
    // let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    // let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    // assert!(broadcast(
    //     &client,
    //     party_num_int,
    //     "round3",
    //     serde_json::to_string(&delta_i).unwrap(),
    //     uuid.clone()
    // )
    // .is_ok());
    // let round3_ans_vec = poll_for_broadcasts(
    //     &client,
    //     party_num_int,
    //     THRESHOLD + 1,
    //     // delay,
    //     "round3",
    //     uuid.clone(),
    // );
    // let mut delta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    // format_vec_from_reads(
    //     &round3_ans_vec,
    //     party_num_int as usize,
    //     delta_i,
    //     &mut delta_vec,
    // );
    // let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    // //////////////////////////////////////////////////////////////////////////////
    // // decommit to gamma_i
    // assert!(broadcast(
    //     &client,
    //     party_num_int,
    //     "round4",
    //     serde_json::to_string(&decommit).unwrap(),
    //     uuid.clone()
    // )
    // .is_ok());
    // let round4_ans_vec = poll_for_broadcasts(
    //     &client,
    //     party_num_int,
    //     THRESHOLD + 1,
    //     // delay,
    //     "round4",
    //     uuid.clone(),
    // );

    // let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    // format_vec_from_reads(
    //     &round4_ans_vec,
    //     party_num_int as usize,
    //     decommit,
    //     &mut decommit_vec,
    // );
    // let decomm_i = decommit_vec.remove(usize::from(party_num_int - 1));
    // bc1_vec.remove(usize::from(party_num_int - 1));
    // let b_proof_vec = (0..m_b_gamma_rec_vec.len())
    //     .map(|i| &m_b_gamma_rec_vec[i].b_proof)
    //     .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
    // let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
    //     .expect("bad gamma_i decommit");

    // // adding local g_gamma_i
    // let R = R + decomm_i.g_gamma_i * delta_inv;

    // // we assume the message is already hashed (by the signer).
    // let message_bn = BigInt::from_bytes(message);
    // let local_sig =
    //     LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    // let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
    //     local_sig.phase5a_broadcast_5b_zkproof();

    // //phase (5A)  broadcast commit
    // assert!(broadcast(
    //     &client,
    //     party_num_int,
    //     "round5",
    //     serde_json::to_string(&phase5_com).unwrap(),
    //     uuid.clone()
    // )
    // .is_ok());
    // let round5_ans_vec = poll_for_broadcasts(
    //     &client,
    //     party_num_int,
    //     THRESHOLD + 1,
    //     // delay,
    //     "round5",
    //     uuid.clone(),
    // );

    // let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    // format_vec_from_reads(
    //     &round5_ans_vec,
    //     party_num_int as usize,
    //     phase5_com,
    //     &mut commit5a_vec,
    // );

    // //phase (5B)  broadcast decommit and (5B) ZK proof
    // assert!(broadcast(
    //     &client,
    //     party_num_int,
    //     "round6",
    //     serde_json::to_string(&(
    //         phase_5a_decom.clone(),
    //         helgamal_proof.clone(),
    //         dlog_proof_rho.clone()
    //     ))
    //     .unwrap(),
    //     uuid.clone()
    // )
    // .is_ok());
    // let round6_ans_vec = poll_for_broadcasts(
    //     &client,
    //     party_num_int,
    //     THRESHOLD + 1,
    //     // delay,
    //     "round6",
    //     uuid.clone(),
    // );

    // let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
    //     Phase5ADecom1,
    //     HomoELGamalProof<Secp256k1, Sha256>,
    //     DLogProof<Secp256k1, Sha256>,
    // )> = Vec::new();
    // format_vec_from_reads(
    //     &round6_ans_vec,
    //     party_num_int as usize,
    //     (phase_5a_decom.clone(), helgamal_proof, dlog_proof_rho),
    //     &mut decommit5a_and_elgamal_and_dlog_vec,
    // );
    // let decommit5a_and_elgamal_and_dlog_vec_includes_i =
    //     decommit5a_and_elgamal_and_dlog_vec.clone();
    // decommit5a_and_elgamal_and_dlog_vec.remove(usize::from(party_num_int - 1));
    // commit5a_vec.remove(usize::from(party_num_int - 1));
    // let phase_5a_decomm_vec = (0..THRESHOLD)
    //     .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
    //     .collect::<Vec<Phase5ADecom1>>();
    // let phase_5a_elgamal_vec = (0..THRESHOLD)
    //     .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
    //     .collect::<Vec<HomoELGamalProof<Secp256k1, Sha256>>>();
    // let phase_5a_dlog_vec = (0..THRESHOLD)
    //     .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
    //     .collect::<Vec<DLogProof<Secp256k1, Sha256>>>();
    // let (phase5_com2, phase_5d_decom2) = local_sig
    //     .phase5c(
    //         &phase_5a_decomm_vec,
    //         &commit5a_vec,
    //         &phase_5a_elgamal_vec,
    //         &phase_5a_dlog_vec,
    //         &phase_5a_decom.V_i,
    //         &R,
    //     )
    //     .expect("error phase5");

    // //////////////////////////////////////////////////////////////////////////////
    // assert!(broadcast(
    //     &client,
    //     party_num_int,
    //     "round7",
    //     serde_json::to_string(&phase5_com2).unwrap(),
    //     uuid.clone()
    // )
    // .is_ok());
    // let round7_ans_vec = poll_for_broadcasts(
    //     &client,
    //     party_num_int,
    //     THRESHOLD + 1,
    //     // delay,
    //     "round7",
    //     uuid.clone(),
    // );

    // let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    // format_vec_from_reads(
    //     &round7_ans_vec,
    //     party_num_int as usize,
    //     phase5_com2,
    //     &mut commit5c_vec,
    // );

    // //phase (5B)  broadcast decommit and (5B) ZK proof
    // assert!(broadcast(
    //     &client,
    //     party_num_int,
    //     "round8",
    //     serde_json::to_string(&phase_5d_decom2).unwrap(),
    //     uuid.clone()
    // )
    // .is_ok());
    // let round8_ans_vec = poll_for_broadcasts(
    //     &client,
    //     party_num_int,
    //     THRESHOLD + 1,
    //     // delay,
    //     "round8",
    //     uuid.clone(),
    // );

    // let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    // format_vec_from_reads(
    //     &round8_ans_vec,
    //     party_num_int as usize,
    //     phase_5d_decom2,
    //     &mut decommit5d_vec,
    // );

    // let phase_5a_decomm_vec_includes_i = (0..=THRESHOLD)
    //     .map(|i| {
    //         decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
    //             .0
    //             .clone()
    //     })
    //     .collect::<Vec<Phase5ADecom1>>();
    // let s_i = local_sig
    //     .phase5d(
    //         &decommit5d_vec,
    //         &commit5c_vec,
    //         &phase_5a_decomm_vec_includes_i,
    //     )
    //     .expect("bad com 5d");

    // //////////////////////////////////////////////////////////////////////////////
    // assert!(broadcast(
    //     &client,
    //     party_num_int,
    //     "round9",
    //     serde_json::to_string(&s_i).unwrap(),
    //     uuid.clone()
    // )
    // .is_ok());
    // let round9_ans_vec =
    //     poll_for_broadcasts(&client, party_num_int, THRESHOLD + 1, /*delay, */"round9", uuid);

    // let mut s_i_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    // format_vec_from_reads(&round9_ans_vec, party_num_int as usize, s_i, &mut s_i_vec);

    // s_i_vec.remove(usize::from(party_num_int - 1));
    // let sig = local_sig
    //     .output_signature(&s_i_vec)
    //     .expect("verification failed");
    // println!("party {:?} Output Signature: \n", party_num_int);
    // println!("R: {:?}", sig.r);
    // println!("s: {:?} \n", sig.s);
    // println!("recid: {:?} \n", sig.recid.clone());

    // let sign_json = serde_json::to_string(&(
    //     "r",
    //     BigInt::from_bytes(sig.r.to_bytes().as_ref()).to_str_radix(16),
    //     "s",
    //     BigInt::from_bytes(sig.s.to_bytes().as_ref()).to_str_radix(16),
    // ))
    // .unwrap();

    // // check sig against secp256k1
    // check_sig(&sig.r, &sig.s, &message_bn, &y_sum);

    // fs::write("signature".to_string(), sign_json).expect("Unable to save !");
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a [String],
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j += 1;
        }
    }
}
