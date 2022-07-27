use crate::curv::arithmetic::BigInt;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DLogStatement {
    pub N: BigInt,
    pub g: BigInt,
    pub ni: BigInt,
}

