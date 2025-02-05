#![cfg(target_arch = "wasm32")]
#![allow(dead_code)]

//use std::{env, time, time::Duration};
//use super::secp256k1::{Message, PublicKey, SECP256K1};

use crate::gg_2018::party_i::Signature;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen::JsValue;

use crate::log;

use crate::curv::{
    arithmetic::traits::Converter,
    elliptic::curves::secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar},
    arithmetic::num_bigint::BigInt,
};

use reqwest::{Client, Body};
use serde::{Deserialize, Serialize};

pub type Key = String;

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}


#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let aes_key = aes_gcm::Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let aes_key = aes_gcm::Key::from_slice(key);
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    let out = gcm.decrypt(nonce, aead_pack.ciphertext.as_slice());
    out.unwrap()
}

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

pub async fn postb<T>(client: &Client, path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    let addr = "http://127.0.0.1:8000".to_string();
    let retries = 3;
    let url = format!("{}/{}", addr, path);

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("Content-Type:application/json; charset=utf-8"));
    headers.insert("Accept", HeaderValue::from_static("application/json; charset=utf-8"));

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build().unwrap();

    let mut res = client.post(url)
        .header("Content-Type", "application/json; charset=utf-8")
        .json(&body)
        .send().await;

    if let Ok(mut res) = res {
        return Some(res.text().await.unwrap())
    } else {
        crate::console_log!("res: {:?}", res);
    }
    None
}

pub async fn broadcast(
    client: &Client,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry { key, value: data };

    let res_body = postb(client, "set", entry).await.unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub async fn sendp2p(
    client: &Client,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry { key, value: data };

    let res_body = postb(client, "set", entry).await.unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub async fn poll_for_broadcasts(
    client: &Client,
    party_num: u16,
    n: u16,
    //delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                //thread::sleep(delay);
                let res_body = postb(client, "get", index.clone()).await.unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub async fn poll_for_p2p(
    client: &Client,
    party_num: u16,
    n: u16,
    //delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                //thread::sleep(delay);
                let res_body = postb(client, "get", index.clone()).await.unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

/*
pub fn check_sig(
    r: &Scalar,
    s: &Scalar,
    msg: &BigInt,
    pk: &Point,
) {

    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::from_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::from_slice(&raw_pk).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::from_compact(compact.as_slice()).unwrap();

    let is_correct = SECP256K1.verify(&msg, &secp_sig, &pk).is_ok();

    println!("public key: {:}", pk);
    println!("address: {:}", public_key_address(&pk));


    assert!(is_correct);
}

pub fn public_key_address(public_key: &PublicKey) -> web3::types::Address {
    let public_key = public_key.serialize_uncompressed();

    debug_assert_eq!(public_key[0], 0x04);
    let hash = web3::signing::keccak256(&public_key[1..]);

    web3::types::Address::from_slice(&hash[12..])
}
*/
