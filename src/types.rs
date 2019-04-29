use clarity::utils::{bytes_to_hex_str, hex_str_to_bytes};
use clarity::Address;
use num256::Uint256;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serializer;
use std::ops::Deref;

/// Serializes slice of data as "UNFORMATTED DATA" format required
/// by Ethereum JSONRPC API.
///
/// See more https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
pub fn data_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&format!("0x{}", bytes_to_hex_str(x)))
}

/// Deserializes slice of data as "UNFORMATTED DATA" format required
/// by Ethereum JSONRPC API.
///
/// See more https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
pub fn data_deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    hex_str_to_bytes(&s).map_err(serde::de::Error::custom)
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Log {
    /// true when the log was removed, due to a chain reorganization. false if its a valid log.
    pub removed: Option<bool>,
    /// integer of the log index position in the block. null when its pending log.
    #[serde(rename = "logIndex")]
    pub log_index: Option<Uint256>,
    /// integer of the transactions index position log was created from. null when its pending log.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<Uint256>,
    /// hash of the transactions this log was created from. null when its pending log.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<Data>,
    /// hash of the block where this log was in. null when its pending. null when its pending log.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<Data>,
    /// the block number where this log was in. null when its pending. null when its pending log.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<Uint256>,
    /// 20 Bytes - address from which this log originated.
    pub address: Address,
    /// contains the non-indexed arguments of the log.
    pub data: Data,
    /// Array of 0 to 4 32 Bytes DATA of indexed log arguments. (In solidity:
    /// The first topic is the hash of the signature of the
    /// event (e.g. Deposit(address,bytes32,uint256)), except you declared
    /// the event with the anonymous specifier.)
    pub topics: Vec<Data>,
    #[serde(rename = "type")]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Data(
    #[serde(
        serialize_with = "data_serialize",
        deserialize_with = "data_deserialize"
    )]
    pub Vec<u8>,
);

impl Deref for Data {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

/// As received by getTransactionByHash
///
/// See more: https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactionbyhash
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct TransactionResponse {
    /// hash of the block where this transaction was in. null when its pending.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<Data>,
    /// block number where this transaction was in. null when its pending.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<Uint256>,
    /// address of the sender.
    pub from: Address,
    /// gas provided by the sender.
    pub gas: Uint256,
    /// gas price provided by the sender in Wei.
    #[serde(rename = "gasPrice")]
    pub gas_price: Uint256,
    /// hash of the transaction
    pub hash: Data,
    /// the data send along with the transaction.
    pub input: Data,
    /// the number of transactions made by the sender prior to this one.
    pub nonce: Uint256,
    /// address of the receiver. null when its a contract creation transaction.
    pub to: Address,
    /// integer of the transaction's index position in the block. null when its pending.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Uint256,
    /// value transferred in Wei.
    pub value: Uint256,
    /// ECDSA recovery id
    pub v: Uint256,
    /// ECDSA signature r
    pub r: Uint256,
    /// ECDSA signature s
    pub s: Uint256,
}

#[derive(Serialize, Default, Debug)]
pub struct NewFilter {
    #[serde(rename = "fromBlock", skip_serializing_if = "Option::is_none")]
    pub from_block: Option<String>,
    #[serde(rename = "toBlock", skip_serializing_if = "Option::is_none")]
    pub to_block: Option<String>,
    pub address: Vec<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<Vec<Option<String>>>>>,
}

#[derive(Serialize, Debug)]
pub struct TransactionRequest {
    //The address the transaction is send from.
    pub from: Address,
    // The address the transaction is directed to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    // Integer of the gas provided for the transaction execution. It will return unused gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<Uint256>,
    // Integer of the gasPrice used for each paid gas
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<Uint256>,
    // Integer of the value sent with this transaction
    pub value: Option<Uint256>,
    // The compiled code of a contract OR the hash of the invoked method signature and encoded parameters. For details see Ethereum Contract ABI
    pub data: Option<Data>,
    //  This allows to overwrite your own pending transactions that use the same nonce.
    pub nonce: Option<Uint256>,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct Block {
    pub number: Option<Uint256>,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub nonce: u8,
    pub sha3_uncles: u8,
    pub logs_bloom: [u8; 32],
    pub transactions_root: [u8; 32],
    pub miner: Address,
    pub difficulty: Uint256,
    pub total_difficulty: Uint256,
    pub extra_data: Data,
    pub size: Uint256,
    pub gas_limit: Uint256,
    pub gas_used: Uint256,
    pub timestamp: Uint256,
    pub transactions: Vec<[u8; 32]>,
    pub uncles: Vec<[u8; 32]>,
}

#[test]
fn decode_log() {
    let res: Vec<Log> = serde_json::from_str(
        r#"[{
      "address": "0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359",
      "blockHash": "0xd8fb35a10b60e5fd1848a83d052424954e4a400fc7826bf85a743ff55acf73d3",
      "blockNumber": "0x74de5d",
      "data": "0x00000000000000000000000000000000000000000000000dae06677922ff8290",
      "logIndex": "0x14",
      "removed": false,
      "topics": [
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        "0x000000000000000000000000802275979b020f0ec871c5ec1db6e412b72ff20b",
        "0x000000000000000000000000af38668f4719ecf9452dc0300be3f6c83cbf3721"
      ],
      "transactionHash": "0xceb484eb92fd7ad626bc5aced6d669a693baf3d776b515a08d65fafca633a6a6",
      "transactionIndex": "0xc"
    }]"#,
    )
    .unwrap();

    println!("{:#?}", res);
}

#[test]
fn decode_transaction_response() {
    let _res: TransactionResponse = serde_json::from_str(
        r#"{
    "blockHash":"0x1d59ff54b1eb26b013ce3cb5fc9dab3705b415a67127a003c3e61eb445bb8df2",
    "blockNumber":"0x5daf3b",
    "from":"0xa7d9ddbe1f17865597fbd27ec712455208b6b76d",
    "gas":"0xc350",
    "gasPrice":"0x4a817c800",
    "hash":"0x88df016429689c079f3b2f6ad39fa052532c56795b733da78a91ebe6a713944b",
    "input":"0x68656c6c6f21",
    "nonce":"0x15",
    "to":"0xf02c1c8e6114b1dbe8937a39260b5b0a374432bb",
    "transactionIndex":"0x41",
    "value":"0xf3dbb76162000",
    "v":"0x25",
    "r":"0x1b5e176d927f8e9ab405058b2d2457392da3e20f328b16ddabcebc33eaac5fea",
    "s":"0x4ba69724e8f69de52f0125ad8b3c5c2cef33019bac3249e2c0a2192766d1721c"
  }"#,
    )
    .unwrap();
}
