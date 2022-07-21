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

    // send ephemeral public keys and check commitments correctness
    assert!(broadcast(
            &client,
            party_num_int,
            "round2",
            serde_json::to_string(&decom_i).unwrap(),
            uuid.clone()
    ).await.is_ok());
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
    assert!(broadcast(
            &client,
            party_num_int,
            "round4",
            serde_json::to_string(&vss_scheme).unwrap(),
            uuid.clone()
    ).await.is_ok());
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
    ))
        .unwrap();
    fs::write(save_path, keygen_json).expect("Unable to save !");
}
