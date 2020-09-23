//! Byte-order safe and lightweight Web3 client.
//!
//! Rust-web3 has its problems because it uses ethereum-types which does not
//! work on big endian. We can do better than that just crafting our own
//! JSONRPC requests.
//!
use crate::jsonrpc::client::HTTPClient;
use crate::types::{Block, Log, NewFilter, TransactionRequest, TransactionResponse};
use crate::types::{ConciseBlock, ConciseXdaiBlock, Data, SendTxOption, UnpaddedHex, XdaiBlock};
use clarity::abi::{derive_signature, encode_call, Token};
use clarity::utils::bytes_to_hex_str;
use clarity::{Address, PrivateKey, Transaction};
use failure::Error;
use num256::Uint256;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

fn bytes_to_data(s: &[u8]) -> String {
    let mut val = "0x".to_string();
    val.push_str(&bytes_to_hex_str(&s));
    val
}

/// An instance of Web3Client.
#[derive(Clone)]
pub struct Web3 {
    jsonrpc_client: Arc<Box<HTTPClient>>,
    timeout: Duration,
}

impl Web3 {
    pub fn new(url: &str, timeout: Duration) -> Self {
        Self {
            jsonrpc_client: Arc::new(Box::new(HTTPClient::new(url))),
            timeout,
        }
    }

    pub async fn eth_accounts(&self) -> Result<Vec<Address>, Error> {
        self.jsonrpc_client
            .request_method("eth_accounts", Vec::<String>::new(), self.timeout, None)
            .await
    }
    pub async fn net_version(&self) -> Result<u64, Error> {
        let ret: Result<String, Error> = self
            .jsonrpc_client
            .request_method("net_version", Vec::<String>::new(), self.timeout, None)
            .await;
        Ok(ret?.parse()?)
    }
    pub async fn eth_new_filter(&self, new_filter: NewFilter) -> Result<Uint256, Error> {
        self.jsonrpc_client
            .request_method("eth_newFilter", vec![new_filter], self.timeout, None)
            .await
    }
    pub async fn eth_get_filter_changes(&self, filter_id: Uint256) -> Result<Vec<Log>, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getFilterChanges",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
                None,
            )
            .await
    }
    pub async fn eth_uninstall_filter(&self, filter_id: Uint256) -> Result<bool, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_uninstallFilter",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
                None,
            )
            .await
    }

    pub async fn eth_get_logs(&self, new_filter: NewFilter) -> Result<Vec<Log>, Error> {
        self.jsonrpc_client
            .request_method("eth_getLogs", vec![new_filter], self.timeout, None)
            .await
    }

    pub async fn eth_get_transaction_count(&self, address: Address) -> Result<Uint256, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getTransactionCount",
                vec![address.to_string(), "latest".to_string()],
                self.timeout,
                None,
            )
            .await
    }
    pub async fn eth_gas_price(&self) -> Result<Uint256, Error> {
        self.jsonrpc_client
            .request_method("eth_gasPrice", Vec::<String>::new(), self.timeout, None)
            .await
    }
    pub async fn eth_estimate_gas(
        &self,
        transaction: TransactionRequest,
    ) -> Result<Uint256, Error> {
        self.jsonrpc_client
            .request_method("eth_estimateGas", vec![transaction], self.timeout, None)
            .await
    }
    pub async fn eth_get_balance(&self, address: Address) -> Result<Uint256, Error> {
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
    ) -> Result<Uint256, Error> {
        self.jsonrpc_client
            .request_method("eth_sendTransaction", transactions, self.timeout, None)
            .await
    }
    pub async fn eth_call(&self, transaction: TransactionRequest) -> Result<Data, Error> {
        self.jsonrpc_client
            .request_method("eth_call", (transaction, "latest"), self.timeout, None)
            .await
    }
    pub async fn eth_block_number(&self) -> Result<Uint256, Error> {
        self.jsonrpc_client
            .request_method("eth_blockNumber", Vec::<String>::new(), self.timeout, None)
            .await
    }

    pub async fn eth_get_block_by_number(&self, block_number: Uint256) -> Result<Block, Error> {
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
    ) -> Result<XdaiBlock, Error> {
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
    ) -> Result<ConciseBlock, Error> {
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
    ) -> Result<ConciseXdaiBlock, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                (format!("{:#x}", block_number), false),
                self.timeout,
                None,
            )
            .await
    }

    pub async fn eth_get_latest_block(&self) -> Result<ConciseBlock, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", false),
                self.timeout,
                None,
            )
            .await
    }

    pub async fn xdai_get_latest_block(&self) -> Result<ConciseXdaiBlock, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", false),
                self.timeout,
                None,
            )
            .await
    }

    pub async fn eth_get_latest_block_full(&self) -> Result<Block, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", true),
                self.timeout,
                Some(5_000_000),
            )
            .await
    }

    pub async fn xdai_get_latest_block_full(&self) -> Result<XdaiBlock, Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                ("latest", true),
                self.timeout,
                Some(5_000_000),
            )
            .await
    }

    pub async fn eth_send_raw_transaction(&self, data: Vec<u8>) -> Result<Uint256, Error> {
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
    ) -> Result<Option<TransactionResponse>, Error> {
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
    pub async fn evm_snapshot(&self) -> Result<Uint256, Error> {
        self.jsonrpc_client
            .request_method("evm_snapshot", Vec::<String>::new(), self.timeout, None)
            .await
    }
    pub async fn evm_revert(&self, snapshot_id: Uint256) -> Result<Uint256, Error> {
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
    ) -> Result<Uint256, Error> {
        let mut gas_price = None;
        let mut gas_price_multiplier = 1u64.into();
        let mut gas_limit = None;
        let mut network_id = None;
        let our_balance = self.eth_get_balance(own_address).await?;

        for option in options {
            match option {
                SendTxOption::GasPrice(gp) => gas_price = Some(gp),
                SendTxOption::GasPriceMultiplier(gpm) => gas_price_multiplier = gpm,
                SendTxOption::GasLimit(gl) => gas_limit = Some(gl),
                SendTxOption::NetworkId(ni) => network_id = Some(ni),
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
            self.eth_estimate_gas(TransactionRequest {
                from: None,
                to: to_address,
                nonce: None,
                gas_price: None,
                gas: None,
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

        let nonce = self.eth_get_transaction_count(own_address).await?;

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
    ) -> Result<Vec<u8>, Error> {
        let gas_price = match self.eth_gas_price().await {
            Ok(val) => val,
            Err(e) => return Err(e),
        };

        let nonce = match self.eth_get_transaction_count(own_address).await {
            Ok(val) => val,
            Err(e) => return Err(e),
        };

        let payload = encode_call(sig, tokens);

        let transaction = TransactionRequest {
            from: Some(own_address),
            to: contract_address,
            nonce: Some(UnpaddedHex(nonce)),
            gas: None,
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

    /// Checks if an event has already happened.
    pub async fn check_for_event(
        &self,
        contract_address: Address,
        event: &str,
        topic1: Option<Vec<[u8; 32]>>,
        topic2: Option<Vec<[u8; 32]>>,
    ) -> Result<Option<Log>, Error> {
        // Build a filter with specified topics
        let mut new_filter = NewFilter::default();
        new_filter.address = vec![contract_address];
        new_filter.topics = Some(vec![
            Some(vec![Some(bytes_to_data(&derive_signature(event)))]),
            topic1.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            topic2.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
        ]);

        match self.eth_get_logs(new_filter).await {
            // Assuming the latest log is at the head of the vec
            Ok(log) => Ok(log.first().cloned()),
            Err(e) => Err(e),
        }
    }

    /// Waits for a transaction with the given hash to show up on the chain
    /// warning, this function can and will wait forever if it has to
    pub async fn wait_for_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<TransactionResponse, Error> {
        loop {
            delay_for(Duration::from_secs(1)).await;
            match self.eth_get_transaction_by_hash(tx_hash.into()).await {
                Ok(maybe_transaction) => {
                    if let Some(transaction) = maybe_transaction {
                        return Ok(transaction);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Same as wait_for_event, but doesn't use eth_newFilter
    pub async fn wait_for_event_alt<F: Fn(Log) -> bool + 'static>(
        &self,
        contract_address: Address,
        event: &str,
        topic1: Option<Vec<[u8; 32]>>,
        topic2: Option<Vec<[u8; 32]>>,
        topic3: Option<Vec<[u8; 32]>>,
        local_filter: F,
    ) -> Result<Log, Error> {
        let new_filter = NewFilter {
            address: vec![contract_address],
            from_block: None,
            to_block: None,
            topics: Some(vec![
                Some(vec![Some(bytes_to_data(&derive_signature(event)))]),
                topic1.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
                topic2.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
                topic3.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            ]),
        };

        delay_for(Duration::from_secs(10)).await;
        let logs = match self.eth_get_logs(new_filter.clone()).await {
            Ok(logs) => logs,
            Err(e) => return Err(e),
        };

        for log in logs {
            if local_filter(log.clone()) {
                return Ok(log);
            }
        }
        Err(format_err!("Not found!"))
    }

    /// Sets up an event filter, waits for the event to happen, then removes the filter. Includes a
    /// local filter. If a captured event does not pass this filter, it is ignored.
    pub async fn wait_for_event<F: Fn(Log) -> bool + 'static>(
        &self,
        contract_address: Address,
        event: &str,
        topic1: Option<Vec<[u8; 32]>>,
        topic2: Option<Vec<[u8; 32]>>,
        topic3: Option<Vec<[u8; 32]>>,
        local_filter: F,
    ) -> Result<Log, Error> {
        let mut new_filter = NewFilter::default();
        new_filter.address = vec![contract_address];
        new_filter.from_block = None;
        new_filter.to_block = None;
        new_filter.topics = Some(vec![
            Some(vec![Some(bytes_to_data(&derive_signature(event)))]),
            topic1.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            topic2.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            topic3.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
        ]);

        let filter_id = match self.eth_new_filter(new_filter).await {
            Ok(f) => f,
            Err(e) => return Err(e),
        };

        delay_for(Duration::from_secs(10)).await;
        let logs = match self.eth_get_filter_changes(filter_id.clone()).await {
            Ok(changes) => changes,
            Err(e) => return Err(e),
        };
        let mut found_log = None;
        for log in logs {
            if local_filter(log.clone()) {
                found_log = Some(log);
            }
        }

        if let Err(e) = self.eth_uninstall_filter(filter_id).await {
            return Err(format_err!("Unable to properly uninstall filter {:?}", e));
        }

        match found_log {
            Some(log) => Ok(log),
            None => Err(format_err!("Not found!")),
        }
    }
}

#[test]
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
    use actix::Arbiter;
    use actix::System;
    System::run(|| {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
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
