//! Byte-order safe and lightweight Web3 client.
//!
//! Rust-web3 has its problems because it uses ethereum-types which does not
//! work on big endian. We can do better than that just crafting our own
//! JSONRPC requests.
//!
use crate::jsonrpc::client::HttpClient;
use crate::jsonrpc::error::Web3Error;
use crate::types::{Block, Log, NewFilter, TransactionRequest, TransactionResponse};
use crate::types::{ConciseBlock, ConciseXdaiBlock, Data, SendTxOption, XdaiBlock};
use clarity::utils::bytes_to_hex_str;
use clarity::{Address, PrivateKey, Transaction};
use num::ToPrimitive;
use num256::Uint256;
use std::cmp::max;
use std::{cmp::min, time::Duration};
use std::{sync::Arc, time::Instant};
use tokio::time::sleep as delay_for;

/// An instance of Web3Client.
#[derive(Clone)]
pub struct Web3 {
    url: String,
    jsonrpc_client: Arc<HttpClient>,
    timeout: Duration,
}

impl Web3 {
    pub fn new(url: &str, timeout: Duration) -> Self {
        Self {
            jsonrpc_client: Arc::new(HttpClient::new(url)),
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
            .request_method("eth_accounts", Vec::<String>::new(), self.timeout)
            .await
    }

    /// Returns the EIP155 chain ID used for transaction signing at the current best block. Null is returned if not available.
    pub async fn eth_chainid(&self) -> Result<Option<Uint256>, Web3Error> {
        let ret: Result<Uint256, Web3Error> = self
            .jsonrpc_client
            .request_method("eth_chainId", Vec::<String>::new(), self.timeout)
            .await;

        Ok(Some(ret?))
    }

    pub async fn net_version(&self) -> Result<u64, Web3Error> {
        let ret: Result<String, Web3Error> = self
            .jsonrpc_client
            .request_method("net_version", Vec::<String>::new(), self.timeout)
            .await;
        Ok(ret?.parse()?)
    }

    pub async fn eth_new_filter(&self, new_filter: NewFilter) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_newFilter", vec![new_filter], self.timeout)
            .await
    }

    pub async fn eth_get_filter_changes(&self, filter_id: Uint256) -> Result<Vec<Log>, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getFilterChanges",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
            )
            .await
    }

    pub async fn eth_uninstall_filter(&self, filter_id: Uint256) -> Result<bool, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_uninstallFilter",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
            )
            .await
    }

    pub async fn eth_get_logs(&self, new_filter: NewFilter) -> Result<Vec<Log>, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_getLogs", vec![new_filter], self.timeout)
            .await
    }

    pub async fn eth_get_transaction_count(&self, address: Address) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getTransactionCount",
                vec![address.to_string(), "latest".to_string()],
                self.timeout,
            )
            .await
    }

    /// Get the median gas price over the last 10 blocks. This function does not
    /// simply wrap eth_gasPrice, in post London chains it also requests the base
    /// gas from the previous block and prevents the use of a lower value
    pub async fn eth_gas_price(&self) -> Result<Uint256, Web3Error> {
        let median_gas = self
            .jsonrpc_client
            .request_method("eth_gasPrice", Vec::<String>::new(), self.timeout)
            .await?;
        let base_gas = self.get_base_fee_per_gas().await?;
        Ok(match base_gas {
            Some(base_gas) => max(base_gas, median_gas),
            None => median_gas,
        })
    }

    pub async fn eth_estimate_gas(
        &self,
        transaction: TransactionRequest,
    ) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_estimateGas", vec![transaction], self.timeout)
            .await
    }

    pub async fn eth_get_balance(&self, address: Address) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBalance",
                vec![address.to_string(), "latest".to_string()],
                self.timeout,
            )
            .await
    }

    pub async fn eth_send_transaction(
        &self,
        transactions: Vec<TransactionRequest>,
    ) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_sendTransaction", transactions, self.timeout)
            .await
    }

    pub async fn eth_call(&self, transaction: TransactionRequest) -> Result<Data, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_call", (transaction, "latest"), self.timeout)
            .await
    }

    pub async fn eth_call_at_height(
        &self,
        transaction: TransactionRequest,
        block: Uint256,
    ) -> Result<Data, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_call", (transaction, block), self.timeout)
            .await
    }

    pub async fn eth_block_number(&self) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_blockNumber", Vec::<String>::new(), self.timeout)
            .await
    }

    pub async fn eth_get_block_by_number(&self, block_number: Uint256) -> Result<Block, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getBlockByNumber",
                (format!("{:#x}", block_number), true),
                self.timeout,
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
            )
            .await
    }

    pub async fn eth_get_latest_block(&self) -> Result<ConciseBlock, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_getBlockByNumber", ("latest", false), self.timeout)
            .await
    }

    pub async fn xdai_get_latest_block(&self) -> Result<ConciseXdaiBlock, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_getBlockByNumber", ("latest", false), self.timeout)
            .await
    }

    pub async fn eth_get_latest_block_full(&self) -> Result<Block, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_getBlockByNumber", ("latest", true), self.timeout)
            .await
    }

    pub async fn xdai_get_latest_block_full(&self) -> Result<XdaiBlock, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_getBlockByNumber", ("latest", true), self.timeout)
            .await
    }

    pub async fn eth_send_raw_transaction(&self, data: Vec<u8>) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_sendRawTransaction",
                vec![format!("0x{}", bytes_to_hex_str(&data))],
                self.timeout,
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
            )
            .await
    }

    pub async fn evm_snapshot(&self) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("evm_snapshot", Vec::<String>::new(), self.timeout)
            .await
    }

    pub async fn evm_revert(&self, snapshot_id: Uint256) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "evm_revert",
                vec![format!("{:#066x}", snapshot_id)],
                self.timeout,
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
        let mut gas_price_multiplier = 1f32;
        let mut gas_limit_multiplier = 1f32;
        let mut gas_limit = None;
        let mut network_id = None;
        let our_balance = self.eth_get_balance(own_address).await?;
        let mut nonce = self.eth_get_transaction_count(own_address).await?;

        for option in options {
            match option {
                SendTxOption::GasPrice(gp) => gas_price = Some(gp),
                SendTxOption::GasPriceMultiplier(gpm) => gas_price_multiplier = gpm,
                SendTxOption::GasLimitMultiplier(glm) => gas_limit_multiplier = glm,
                SendTxOption::GasLimit(gl) => gas_limit = Some(gl),
                SendTxOption::NetworkId(ni) => network_id = Some(ni),
                SendTxOption::Nonce(n) => nonce = n,
            }
        }

        let mut gas_price = if let Some(gp) = gas_price {
            gp
        } else {
            let gas_price = self.eth_gas_price().await?;
            let f32_gas = gas_price.to_u128();
            if let Some(v) = f32_gas {
                // convert to f32, multiply, then convert back, this
                // will be lossy but you want an exact price you can set it
                ((v as f32 * gas_price_multiplier) as u128).into()
            } else {
                // gas price is insanely high, best effort rounding
                // perhaps we should panic here
                gas_price * (gas_price_multiplier.round() as u128).into()
            }
        };

        let mut gas_limit = if let Some(gl) = gas_limit {
            gl
        } else {
            let gas = self
                .simulated_gas_price_and_limit(our_balance.clone())
                .await?;
            self.eth_estimate_gas(TransactionRequest {
                from: Some(own_address),
                to: to_address,
                nonce: Some(nonce.clone().into()),
                gas_price: Some(gas.price.into()),
                gas: Some(gas.limit.into()),
                value: Some(value.clone().into()),
                data: Some(data.clone().into()),
            })
            .await?
        };

        // multiply limit by gasLimitMultiplier
        let gas_limit_128 = gas_limit.to_u128();
        if let Some(v) = gas_limit_128 {
            gas_limit = ((v as f32 * gas_limit_multiplier) as u128).into()
        } else {
            gas_limit *= (gas_limit_multiplier.round() as u128).into()
        }

        let network_id = if let Some(ni) = network_id {
            ni
        } else {
            self.net_version().await?
        };

        // this is an edge case where we are about to send a transaction that can't possibly
        // be valid, we simply don't have the the funds to pay the full gas amount we are promising
        // this segment computes either the highest valid gas price we can pay or in the post-london
        // chain case errors if we can't meet the minimum fee
        if gas_price.clone() * gas_limit.clone() > our_balance {
            let base_fee_per_gas = self.get_base_fee_per_gas().await?;
            if let Some(base_fee_per_gas) = base_fee_per_gas {
                if base_fee_per_gas.clone() * gas_limit.clone() > our_balance {
                    return Err(Web3Error::InsufficientGas {
                        balance: our_balance,
                        base_gas: base_fee_per_gas,
                        gas_required: gas_limit,
                    });
                }
            }
            // this will give some value >= base_fee_per_gas * gas_limit
            // in post-london and some non zero value in pre-london
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

    /// Simulates an Ethereum contract call by making a fake transaction and sending it to a special endpoint
    /// this code is executed exactly as if it where an actual transaction executing. This can be used to execute
    /// both getter endpoints on Solidity contracts and to test actual executions. User beware, this function requires
    /// ETH in the caller address to run. Even if you're just trying to call a getter function and never need to actually
    /// run code this faithful simulation will fail if you have no ETH to pay for gas.
    ///
    /// In an attempt to maximize the amount of info you can get with this function gas is computed for you as the maximum
    /// possible value, if you need to get  gas estimation you should use `web3.eth_estimate_gas` instead.
    ///
    /// optionally this data can come from some historic block
    pub async fn simulate_transaction(
        &self,
        contract_address: Address,
        value: Uint256,
        data: Vec<u8>,
        own_address: Address,
        height: Option<Uint256>,
    ) -> Result<Vec<u8>, Web3Error> {
        let our_balance = self.eth_get_balance(own_address).await?;
        let nonce = self.eth_get_transaction_count(own_address).await?;

        let gas = self.simulated_gas_price_and_limit(our_balance).await?;
        let transaction = TransactionRequest {
            from: Some(own_address),
            to: contract_address,
            gas: Some(gas.limit.into()),
            nonce: Some(nonce.clone().into()),
            gas_price: Some(gas.price.into()),
            value: Some(value.clone().into()),
            data: Some(data.clone().into()),
        };

        match height {
            Some(height) => {
                let bytes = match self.eth_call_at_height(transaction, height).await {
                    Ok(val) => val,
                    Err(e) => return Err(e),
                };
                Ok(bytes.0)
            }
            None => {
                let bytes = match self.eth_call(transaction).await {
                    Ok(val) => val,
                    Err(e) => return Err(e),
                };
                Ok(bytes.0)
            }
        }
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

    /// Geth and parity behave differently for the Estimate gas call or eth_call()
    /// Parity / OpenEthereum will allow you to specify no gas price
    /// and no gas amount the estimate gas call will then return the
    /// amount of gas the transaction would take. This is reasonable behavior
    /// from an endpoint that's supposed to let you estimate gas usage
    ///
    /// The gas price is of course irrelevant unless someone goes out of their
    /// way to design a contract that fails a low gas prices. Geth and Parity
    /// can't simulate an actual transaction market accurately.
    ///
    /// Geth on the other hand insists that you provide a gas price of at least
    /// 7 post London hardfork in order to respond. This seems to be because Geth
    /// simply tosses your transaction into the actual execution code, so no gas
    /// instantly fails.
    ///
    /// If this value is too low Geth will fail, if this value is higher than
    /// your balance Geth will once again fail. So Geth at this juncture won't
    /// tell you what the transaction would cost, just that you can't afford it.
    ///
    /// Max possible gas price is Uint 32 max, Geth will print warnings above 25mil
    /// gas, hardhat will error above 12.45 mil gas. So we select the minimum of these
    ///
    /// This function will navigate all these restrictions in order to give you the
    /// maximum valid gas possible for any simulated call
    async fn simulated_gas_price_and_limit(
        &self,
        balance: Uint256,
    ) -> Result<SimulatedGas, Web3Error> {
        const GAS_LIMIT: u128 = 12450000;
        let base_fee_per_gas = self.get_base_fee_per_gas().await?;
        let price = match base_fee_per_gas {
            // post London, multiply by two to prevent changing gas prices
            // from causing failure
            Some(base_gas) => base_gas,
            // pre London
            None => 1u8.into(),
        };
        let limit = min(GAS_LIMIT.into(), balance / price.clone());
        Ok(SimulatedGas { limit, price })
    }

    /// Navigates the block request process to properly identify the base fee no matter
    /// what network (xDai or ETH) is being used. Returns `None` if a pre-London fork
    /// network is in use and `Some(base_fee_per_gas)` if a post London network is in
    /// use
    async fn get_base_fee_per_gas(&self) -> Result<Option<Uint256>, Web3Error> {
        let eth = self.eth_get_latest_block().await;
        let xdai = self.xdai_get_latest_block().await;
        // we don't know what network we're on, so we request both blocks and
        // see which one succeeds. This could in theory be removed if we
        // combine the eth and xdai blocks or require some sort of flag on init
        // for the web30 struct
        match (eth, xdai) {
            // this case is confusing, I'm pretty sure, but not 100% sure that
            // it's impossible. That being said we better handle it just to be safe
            // if we have some polyglot block that is interpretable through both types
            // this entire section contains a lot of guesswork for cases that will probably
            // never happen
            (Ok(eth_block), Ok(xdai_block)) => {
                warn!("Found polyglot blocks! {:?} {:?}", eth_block, xdai_block);
                match (eth_block.base_fee_per_gas, xdai_block.base_fee_per_gas) {
                    // polyglot block, these values should be identical, but take the max
                    (Some(base_gas_a), Some(base_gas_b)) => Ok(Some(max(base_gas_a, base_gas_b))),
                    // this is event more crazy than a polyglot block, the field name is the same
                    // nevertheless we should take the value that exists
                    (Some(base_gas), None) | (None, Some(base_gas)) => Ok(Some(base_gas)),

                    (None, None) => Ok(None),
                }
            }
            (Err(_), Ok(block)) => Ok(block.base_fee_per_gas),
            (Ok(block), Err(_)) => Ok(block.base_fee_per_gas),
            // if both error it's probably the same error so lets pick the first
            // and return it
            (Err(e), Err(_)) => Err(e),
        }
    }

    /// Waits for the next Ethereum block to be produced
    pub async fn wait_for_next_block(&self, timeout: Duration) -> Result<(), Web3Error> {
        let start = Instant::now();
        let mut last_height: Option<Uint256> = None;
        while Instant::now() - start < timeout {
            match (self.eth_block_number().await, last_height.clone()) {
                (Ok(n), None) => last_height = Some(n),
                (Ok(block_height), Some(last_height)) => {
                    if block_height > last_height {
                        return Ok(());
                    }
                }
                // errors should not exit early
                (Err(_), _) => {}
            }
        }
        Err(Web3Error::NoBlockProduced { time: timeout })
    }
}
struct SimulatedGas {
    limit: Uint256,
    price: Uint256,
}

#[test]
fn test_chain_id() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    let web3_xdai = Web3::new("https://dai.althea.net", Duration::from_secs(5));
    runner.block_on(async move {
        assert_eq!(Some(Uint256::from(1u8)), web3.eth_chainid().await.unwrap());
        assert_eq!(
            Some(Uint256::from(100u8)),
            web3_xdai.eth_chainid().await.unwrap()
        );
    })
}

#[test]
fn test_net_version() {
    use actix::System;
    let runner = System::new();
    let web3_xdai = Web3::new("https://dai.althea.net", Duration::from_secs(5));
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    runner.block_on(async move {
        assert_eq!(1u64, web3.net_version().await.unwrap());
        assert_eq!(100u64, web3_xdai.net_version().await.unwrap());
    })
}
#[ignore]
#[test]
fn test_complex_response() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    let txid1 = "0x8b9ef028f99016cd3cb8d4168df7491a0bf44f08b678d37f63ab61e782c500ab"
        .parse()
        .unwrap();
    runner.block_on(async move {
        let val = web3.eth_get_transaction_by_hash(txid1).await;
        let val = val.expect("Actix failure");
        let response = val.expect("Failed to parse transaction response");
        assert!(response.block_number.unwrap() > 10u32.into());
    })
}

#[test]
fn test_transaction_count_response() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    let address: Address = "0x04668ec2f57cc15c381b461b9fedab5d451c8f7f"
        .parse()
        .unwrap();
    runner.block_on(async move {
        let val = web3.eth_get_transaction_count(address).await;
        let val = val.unwrap();
        assert!(val > 0u32.into());
    });
}

#[test]
fn test_block_response() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://eth.altheamesh.com", Duration::from_secs(5));
    runner.block_on(async move {
        let val = web3.eth_get_latest_block().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());

        let val = web3.eth_get_latest_block_full().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());
    });
}

#[test]
fn test_dai_block_response() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://dai.althea.net", Duration::from_secs(5));
    runner.block_on(async move {
        let val = web3.xdai_get_latest_block().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());
    });
}
