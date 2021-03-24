//! Byte-order safe and lightweight Web3 client.
//!
//! Rust-web3 has its problems because it uses ethereum-types which does not
//! work on big endian. We can do better than that just crafting our own
//! JSONRPC requests.
//!
use crate::jsonrpc::client::HTTPClient;
use crate::jsonrpc::error::Web3Error;
use crate::types::{Block, Log, NewFilter, TransactionRequest, TransactionResponse};
use crate::types::{ConciseBlock, ConciseXdaiBlock, Data, SendTxOption, UnpaddedHex, XdaiBlock};
use clarity::abi::{encode_call, Token};
use clarity::utils::bytes_to_hex_str;
use clarity::{Address, PrivateKey, Transaction};
use num256::Uint256;
use std::{cmp::min, time::Duration};
use std::{sync::Arc, time::Instant};
use tokio::time::delay_for;

/// An instance of Web3Client.
#[derive(Clone)]
pub struct Web3 {
    url: String,
    jsonrpc_client: Arc<Box<HTTPClient>>,
    timeout: Duration,
}

impl Web3 {
    pub fn new(url: &str, timeout: Duration) -> Self {
        Self {
            jsonrpc_client: Arc::new(Box::new(HTTPClient::new(url))),
            timeout,
            url: url.to_string(),
        }
    }

    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    pub fn get_url(&self) -> String {
        self.url.clone()
    }

    pub async fn eth_accounts(&self) -> Result<Vec<Address>, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_accounts", Vec::<String>::new(), self.timeout, None)
            .await
    }
    pub async fn net_version(&self) -> Result<u64, Web3Error> {
        let ret: Result<String, Web3Error> = self
            .jsonrpc_client
            .request_method("net_version", Vec::<String>::new(), self.timeout, None)
            .await;
        Ok(ret?.parse()?)
    }
    pub async fn eth_new_filter(&self, new_filter: NewFilter) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_newFilter", vec![new_filter], self.timeout, None)
            .await
    }
    pub async fn eth_get_filter_changes(&self, filter_id: Uint256) -> Result<Vec<Log>, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getFilterChanges",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
                Some(10_000_000),
            )
            .await
    }
    pub async fn eth_uninstall_filter(&self, filter_id: Uint256) -> Result<bool, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_uninstallFilter",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
                None,
            )
            .await
    }

    pub async fn eth_get_logs(&self, new_filter: NewFilter) -> Result<Vec<Log>, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getLogs",
                vec![new_filter],
                self.timeout,
                Some(10_000_000),
            )
            .await
    }

    pub async fn eth_get_transaction_count(&self, address: Address) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getTransactionCount",
                vec![address.to_string(), "latest".to_string()],
                self.timeout,
                None,
            )
            .await
    }
    pub async fn eth_gas_price(&self) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_gasPrice", Vec::<String>::new(), self.timeout, None)
            .await
    }
    pub async fn eth_estimate_gas(
        &self,
        transaction: TransactionRequest,
    ) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_estimateGas", vec![transaction], self.timeout, None)
            .await
    }
    pub async fn eth_get_balance(&self, address: Address) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBalance",
                vec![address.to_string(), "latest".to_string()],
                self.timeout,
                None,
            )
            .await
    }
    pub async fn eth_send_transaction(
        &self,
        transactions: Vec<TransactionRequest>,
    ) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_sendTransaction", transactions, self.timeout, None)
            .await
    }
    pub async fn eth_call(&self, transaction: TransactionRequest) -> Result<Data, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_call", (transaction, "latest"), self.timeout, None)
            .await
    }
    pub async fn eth_block_number(&self) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_blockNumber", Vec::<String>::new(), self.timeout, None)
            .await
    }

    pub async fn eth_get_block_by_number(&self, block_number: Uint256) -> Result<Block, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                (format!("{:#x}", block_number), true),
                self.timeout,
                Some(5_000_000),
            )
            .await
    }

    pub async fn xdai_get_block_by_number(
        &self,
        block_number: Uint256,
    ) -> Result<XdaiBlock, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                (format!("{:#x}", block_number), true),
                self.timeout,
                Some(5_000_000),
            )
            .await
    }

    pub async fn eth_get_concise_block_by_number(
        &self,
        block_number: Uint256,
    ) -> Result<ConciseBlock, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                (format!("{:#x}", block_number), false),
                self.timeout,
                None,
            )
            .await
    }

    pub async fn xdai_get_concise_block_by_number(
        &self,
        block_number: Uint256,
    ) -> Result<ConciseXdaiBlock, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                (format!("{:#x}", block_number), false),
                self.timeout,
                None,
            )
            .await
    }

    pub async fn eth_get_latest_block(&self) -> Result<ConciseBlock, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", false),
                self.timeout,
                None,
            )
            .await
    }

    pub async fn xdai_get_latest_block(&self) -> Result<ConciseXdaiBlock, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", false),
                self.timeout,
                None,
            )
            .await
    }

    pub async fn eth_get_latest_block_full(&self) -> Result<Block, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", true),
                self.timeout,
                Some(5_000_000),
            )
            .await
    }

    pub async fn xdai_get_latest_block_full(&self) -> Result<XdaiBlock, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", true),
                self.timeout,
                Some(5_000_000),
            )
            .await
    }

    pub async fn eth_send_raw_transaction(&self, data: Vec<u8>) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_sendRawTransaction",
                vec![format!("0x{}", bytes_to_hex_str(&data))],
                self.timeout,
                None,
            )
            .await
    }
    pub async fn eth_get_transaction_by_hash(
        &self,
        hash: Uint256,
    ) -> Result<Option<TransactionResponse>, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getTransactionByHash",
                // XXX: Technically it doesn't need to be Uint256, but since send_raw_transaction is
                // returning it we'll keep it consistent.
                vec![format!("{:#066x}", hash)],
                self.timeout,
                None,
            )
            .await
    }
    pub async fn evm_snapshot(&self) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("evm_snapshot", Vec::<String>::new(), self.timeout, None)
            .await
    }
    pub async fn evm_revert(&self, snapshot_id: Uint256) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "evm_revert",
                vec![format!("{:#066x}", snapshot_id)],
                self.timeout,
                None,
            )
            .await
    }

    /// Sends a transaction which changes blockchain state.
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like chain id, gas,
    /// and network id.
    /// WARNING: you must specify networkID in situations where a single
    /// node is operating no more than one chain. Otherwise it is possible
    /// for the full node to trick the client into signing transactions
    /// on unintended chains potentially to their benefit
    pub async fn send_transaction(
        &self,
        to_address: Address,
        data: Vec<u8>,
        value: Uint256,
        own_address: Address,
        secret: PrivateKey,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let mut gas_price = None;
        let mut gas_price_multiplier = 1u64.into();
        let mut gas_limit = None;
        let mut network_id = None;
        let our_balance = self.eth_get_balance(own_address).await?;
        let mut nonce = self.eth_get_transaction_count(own_address).await?;

        for option in options {
            match option {
                SendTxOption::GasPrice(gp) => gas_price = Some(gp),
                SendTxOption::GasPriceMultiplier(gpm) => gas_price_multiplier = gpm,
                SendTxOption::GasLimit(gl) => gas_limit = Some(gl),
                SendTxOption::NetworkId(ni) => network_id = Some(ni),
                SendTxOption::Nonce(n) => nonce = n,
            }
        }

        let mut gas_price = if let Some(gp) = gas_price {
            gp
        } else {
            self.eth_gas_price().await? * gas_price_multiplier
        };

        let gas_limit = if let Some(gl) = gas_limit {
            gl
        } else {
            // Geth and parity behave differently for the Estimate gas call
            // Parity / OpenEthereum will allow you to specify no gas price
            // and no gas amount the estimate gas call will then return the
            // amount of gas the transaction would take. This is reasonable behavior
            // from an endpoint that's supposed to let you estimate gas usage
            //
            // The gas price is of course irrelevant unless someone goes out of their
            // way to design a contract that fails a low gas prices. Geth and Parity
            // can't simulate an actual transaction market accurately.
            //
            // Geth on the other hand insists that you provide a gas price (any price)
            // and a gas value. Otherwise it will not provide an estimate.
            //
            // If this value is too low Geth will fail, if this value is higher than
            // your balance Geth will once again fail. So Geth at this juncture won't
            // tell you what the transaction would cost, just that you can't afford it.
            //
            // So if yes you could set these values to none if making a parity request
            let gas_price: Uint256 = 1u8.into();
            // Geth represents gas as a u64 it will truncate leading zeros but not take
            // a value larger than u64::MAX, likewise the command will fail if we can't
            // actually pay that fee. This operation maximizes the info we can get
            let gas_limit = min((u64::MAX - 1).into(), our_balance.clone());
            self.eth_estimate_gas(TransactionRequest {
                from: Some(own_address),
                to: to_address,
                nonce: Some(nonce.clone().into()),
                gas_price: Some(gas_price.into()),
                gas: Some(gas_limit.into()),
                value: Some(value.clone().into()),
                data: Some(data.clone().into()),
            })
            .await?
        };

        let network_id = if let Some(ni) = network_id {
            ni
        } else {
            self.net_version().await?
        };

        // this is an edge case where we are about to send a transaction that can't possibly
        // be valid, we simply don't have the the funds to pay the full gas amount we are promising
        // in this case we reduce the gas price to exactly what we can afford.
        if gas_price.clone() * gas_limit.clone() > our_balance {
            gas_price = our_balance / gas_limit.clone();
        }

        let transaction = Transaction {
            to: to_address,
            nonce,
            gas_price,
            gas_limit,
            value,
            data,
            signature: None,
        };

        let transaction = transaction.sign(&secret, Some(network_id));

        self.eth_send_raw_transaction(
            transaction
                .to_bytes()
                .expect("transaction.to_bytes() failed"),
        )
        .await
    }

    /// Sends a transaction which does not change blockchain state, usually to get information.
    pub async fn contract_call(
        &self,
        contract_address: Address,
        sig: &str,
        tokens: &[Token],
        own_address: Address,
    ) -> Result<Vec<u8>, Web3Error> {
        let our_balance = self.eth_get_balance(own_address).await?;
        let nonce = self.eth_get_transaction_count(own_address).await?;

        let payload = encode_call(sig, tokens)?;

        let gas_price: Uint256 = 1u8.into();
        // Geth represents gas as a u64 it will truncate leading zeros but not take
        // a value larger than u64::MAX, likewise the command will fail if we can't
        // actually pay that fee. This operation maximizes the info we can get
        let gas_limit = min((u64::MAX - 1).into(), our_balance);
        let transaction = TransactionRequest {
            from: Some(own_address),
            to: contract_address,
            nonce: Some(UnpaddedHex(nonce)),
            gas: Some(gas_limit.into()),
            gas_price: Some(UnpaddedHex(gas_price)),
            value: Some(UnpaddedHex(0u64.into())),
            data: Some(Data(payload)),
        };

        let bytes = match self.eth_call(transaction).await {
            Ok(val) => val,
            Err(e) => return Err(e),
        };
        Ok(bytes.0)
    }

    /// Waits for a transaction with the given hash to be included in a block
    /// it will wait for at most timeout time and optionally can wait for n
    /// blocks to have passed
    pub async fn wait_for_transaction(
        &self,
        tx_hash: Uint256,
        timeout: Duration,
        blocks_to_wait: Option<Uint256>,
    ) -> Result<TransactionResponse, Web3Error> {
        let start = Instant::now();
        loop {
            delay_for(Duration::from_secs(1)).await;
            match self.eth_get_transaction_by_hash(tx_hash.clone()).await {
                Ok(maybe_transaction) => {
                    if let Some(transaction) = maybe_transaction {
                        // if no wait time is specified and the tx is in a block return right away
                        if blocks_to_wait.clone().is_none() && transaction.block_number.is_some() {
                            return Ok(transaction);
                        }
                        // One the tx is in a block we start waiting here
                        else if let (Some(blocks_to_wait), Some(tx_block)) =
                            (blocks_to_wait.clone(), transaction.block_number.clone())
                        {
                            let current_block = self.eth_block_number().await?;
                            // we check for underflow, which is possible on testnets
                            if current_block > blocks_to_wait
                                && current_block - blocks_to_wait >= tx_block
                            {
                                return Ok(transaction);
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }

            if Instant::now() - start > timeout {
                return Err(Web3Error::TransactionTimeout);
            }
        }
    }
}

#[test]
#[ignore]
fn test_complex_response() {
    use actix::Arbiter;
    use actix::System;
    System::run(|| {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
        let txid1 = "0x8b9ef028f99016cd3cb8d4168df7491a0bf44f08b678d37f63ab61e782c500ab"
            .parse()
            .unwrap();
        Arbiter::spawn(async move {
            let val = web3.eth_get_transaction_by_hash(txid1).await;
            let val = val.expect("Actix failure");
            let response = val.expect("Failed to parse transaction response");
            assert!(response.block_number.unwrap() > 10u32.into());
            System::current().stop();
        });
    })
    .expect("Actix failure");
}

#[test]
fn test_transaction_count_response() {
    use actix::Arbiter;
    use actix::System;
    System::run(|| {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
        let address: Address = "0x04668ec2f57cc15c381b461b9fedab5d451c8f7f"
            .parse()
            .unwrap();
        Arbiter::spawn(async move {
            let val = web3.eth_get_transaction_count(address).await;
            let val = val.unwrap();
            assert!(val > 0u32.into());
            System::current().stop();
        });
    })
    .expect("Actix failure");
}

#[test]
fn test_block_response() {
    env_logger::init();
    use actix::Arbiter;
    use actix::System;
    System::run(|| {
        let web3 = Web3::new("https://eth.altheamesh.com", Duration::from_secs(5));
        Arbiter::spawn(async move {
            let val = web3.eth_get_latest_block().await;
            let val = val.expect("Actix failure");
            assert!(val.number > 10u32.into());
            System::current().stop();
        });
    })
    .expect("Actix failure");
}

#[test]
fn test_dai_block_response() {
    use actix::Arbiter;
    use actix::System;
    System::run(|| {
        let web3 = Web3::new("https://dai.althea.net", Duration::from_secs(5));
        Arbiter::spawn(async move {
            let val = web3.xdai_get_latest_block().await;
            let val = val.expect("Actix failure");
            assert!(val.number > 10u32.into());
            System::current().stop();
        });
    })
    .expect("Actix failure");
}
