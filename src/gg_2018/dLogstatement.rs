use crate::curv::arithmetic::num_bigint::BigInt;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DLogStatement {
    pub N: BigInt,
    pub g: BigInt,
    pub ni: BigInt,
}

