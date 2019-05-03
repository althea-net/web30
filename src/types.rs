use clarity::utils::{bytes_to_hex_str, hex_str_to_bytes};
use clarity::{Address, BigEndianInt};
use num256::Uint256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
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

#[derive(Serialize)]
pub struct TransactionRequest {
  //The address the transaction is send from.
  pub from: Address,
  // The address the transaction is directed to.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub to: Option<Address>,
  // Integer of the gas provided for the transaction execution. It will return unused gas.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gas: Option<UnpaddedHex>,
  // Integer of the gasPrice used for each paid gas
  #[serde(rename = "gasPrice")]
  pub gas_price: Option<UnpaddedHex>,
  // Integer of the value sent with this transaction
  pub value: Option<UnpaddedHex>,
  // The compiled code of a contract OR the hash of the invoked method signature and encoded parameters. For details see Ethereum Contract ABI
  pub data: Option<Data>,
  //  This allows to overwrite your own pending transactions that use the same nonce.
  pub nonce: Option<UnpaddedHex>,
}

pub struct UnpaddedHex(pub Uint256);

impl Serialize for UnpaddedHex {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&format!("{:#x}", *self.0))
  }
}

/// This struct currently only has the 'timestamp' field. You can add the others using the example
/// JSON pasted above this comment in the source code.
#[derive(Serialize, Debug, Deserialize)]
pub struct Block {
  pub timestamp: Uint256,
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
fn decode_block() {
  let original = r#"{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "difficulty": "0x6c32fa8089ec4",
    "extraData": "0x5050594520737061726b706f6f6c2d6574682d636e2d687a",
    "gasLimit": "0x7a121d",
    "gasUsed": "0x41e026",
    "hash": "0x1539b836d40adc72e3cc3d6b2aabe55c4347c7bfb68e09020ea6ebd95a65b434",
    "logsBloom": "0x0000080000002010010000090021002160110040401020820048403000040000882000001010440800020108010000000300000000820070028408000050000180016480b003804184000208411100500800080002080204a00002100100003801090001060002020008a00000020800204040820010329041000011000000880912021100000044004000000025840800190a0000001000264880080100240000808000100092000004500001008404088000010011200080102000200000e0100c1102000000000000000800040004000c800001001004b1022000804070010800208201451000200c208c000080c0202021410040d0020008000016000004",
    "miner": "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
    "mixHash": "0x2d8faa3690ec380b8c4ce5ffd6df444b8e532ddceb87a69890482af1137289e6",
    "nonce": "0xa2d323400067995d",
    "number": "0x753ddd",
    "parentHash": "0xa68a4b2c0e47201aef3729055a0c01a74fa0ecf59ddde6cc0111d897442dd830",
    "receiptsRoot": "0x3b536e11afd70f5b893619f2aa1401c1388579a63dabd149172b2b50e63d2c2a",
    "sha3Uncles": "0x7338c4e69477e51b91b693a7241903033331b693750e92b619139b1468d68eb4",
    "size": "0x14a8",
    "stateRoot": "0x3b39c0bd303e9c135c6648890175b697a274f7ad3a25d3b6804d6744ae7dc226",
    "timestamp": "0x5ccb4648",
    "totalDifficulty": "0x220b1c200879e319650",
    "transactions": [
      "0xb474e6dd57954812bf2e8dd9f02c03f2e93623097a7f375bdc26d31ce4b09af7"
    ],
    "transactionsRoot": "0x8a42d36e3b8cd391879a2c26c9649a0e55425799e071abc2211161442ed249be",
    "uncles": [
      "0x0ee490b22ceeffa818df767b5c5e9db0ea11620a7c948de008a52cb9df1b3725"
    ]
  }
}"#;

  let value_from_string: Value = serde_json::from_str(original).unwrap();

  let decoded: TransactionResponse = serde_json::from_str(original).unwrap();

  let value_from_struct: Value = serde_json::to_value(&decoded).unwrap();

  assert_json_include!(actual: value_from_string, expected: value_from_struct);
}
