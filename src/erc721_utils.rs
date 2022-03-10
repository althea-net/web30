//! This module contains utility functions for interacting with ERC20 tokens and contracts
use crate::jsonrpc::error::Web3Error;
use crate::{client::Web3, types::SendTxOption};
use clarity::{abi::encode_call, PrivateKey as EthPrivateKey};
use clarity::{Address, Uint256, abi::Token};
use num::Bounded;
use std::time::Duration;
use tokio::time::timeout as future_timeout;
use clarity::Address as EthAddress;

pub static ERC20_GAS_LIMIT: u128 = 100_000;

impl Web3 {
    // /// Approves a given contract to spend erc20 funds from the given address from the erc20 contract provided.
    // /// What exactly this does can be hard to grok, essentially when you want contract A to be able to spend
    // /// your erc20 contract funds you need to call 'approve' on the ERC20 contract with your own address and A's
    // /// address so that in the future when you call contract A it can manipulate your ERC20 balances.
    // /// This function performs that action and waits for it to complete for up to Timeout duration
    // /// `options` takes a vector of `SendTxOption` for configuration
    // /// unlike the lower level eth_send_transaction() this call builds
    // /// the transaction abstracting away details like chain id, gas,
    // /// and network id.
    pub async fn approve_erc721_transfers(
        &self,
        erc721: Address,
        eth_private_key: EthPrivateKey,
        target_contract: Address,
        token_id: Uint256,
        timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let own_address = eth_private_key.to_address();
        // function approve(address _approved, uint256 _tokenId) 
        let payload = encode_call(
            "approve(address,uint256)",
            &[target_contract.into(), Token::Uint(token_id.clone())],
        )?;

        let txid = self
            .send_transaction(
                erc721,
                payload,
                0u32.into(),
                own_address,
                eth_private_key,
                options,
            )
            .await?;

        // wait for transaction to enter the chain if the user has requested it
        if let Some(timeout) = timeout {
            future_timeout(
                timeout,
                self.wait_for_transaction(txid.clone(), timeout, None),
            )
            .await??;
        }

        Ok(txid)
    }

    // /// Send an erc20 token to the target address, optionally wait until it enters the blockchain
    // /// `options` takes a vector of `SendTxOption` for configuration
    // /// unlike the lower level eth_send_transaction() this call builds
    // /// the transaction abstracting away details like chain id, gas,
    // /// and network id.
    // /// WARNING: you must specify networkID in situations where a single
    // /// node is operating no more than one chain. Otherwise it is possible
    // /// for the full node to trick the client into signing transactions
    // /// on unintended chains potentially to their benefit
    // pub async fn erc20_send(
    //     &self,
    //     amount: Uint256,
    //     recipient: Address,
    //     erc20: Address,
    //     sender_private_key: EthPrivateKey,
    //     wait_timeout: Option<Duration>,
    //     options: Vec<SendTxOption>,
    // ) -> Result<Uint256, Web3Error> {
    //     let sender_address = sender_private_key.to_address();

    //     // if the user sets a gas limit we should honor it, if they don't we
    //     // should add the default
    //     let mut has_gas_limit = false;
    //     let mut options = options;
    //     for option in options.iter() {
    //         if let SendTxOption::GasLimit(_) = option {
    //             has_gas_limit = true;
    //             break;
    //         }
    //     }
    //     if !has_gas_limit {
    //         options.push(SendTxOption::GasLimit(ERC20_GAS_LIMIT.into()));
    //     }

    //     let tx_hash = self
    //         .send_transaction(
    //             erc20,
    //             encode_call(
    //                 "transfer(address,uint256)",
    //                 &[recipient.into(), amount.clone().into()],
    //             )?,
    //             0u32.into(),
    //             sender_address,
    //             sender_private_key,
    //             options,
    //         )
    //         .await?;

    //     if let Some(timeout) = wait_timeout {
    //         future_timeout(
    //             timeout,
    //             self.wait_for_transaction(tx_hash.clone(), timeout, None),
    //         )
    //         .await??;
    //     }

    //     Ok(tx_hash)
    // }

    pub async fn get_erc721_name(
        &self,
        erc721: Address,
        caller_address: Address,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("name()", &[])?;
        let name = self
            .simulate_transaction(erc721, 0u8.into(), payload, caller_address, None)
            .await?;

        match String::from_utf8(name) {
            Ok(mut val) => {
                // the value returned is actually in Ethereum ABI encoded format
                // stripping control characters is an easy way to strip off the encoding
                val.retain(|v| !v.is_control());
                let val = val.trim().to_string();
                Ok(val)
            }
            Err(_e) => Err(Web3Error::ContractCallError(
                "name is not valid utf8".to_string(),
            )),
        }
    }

    pub async fn get_erc721_symbol(
        &self,
        erc721: Address,
        caller_address: Address,
    ) -> Result<String, Web3Error> {
        info!("in get_erc721_symbol, looking at address {}", erc721);
        let payload = encode_call("symbol()", &[])?;
        let symbol = self
            .simulate_transaction(erc721, 0u8.into(), payload, caller_address, None)
            .await?;

        match String::from_utf8(symbol) {
            Ok(mut val) => {
                // the value returned is actually in Ethereum ABI encoded format
                // stripping control characters is an easy way to strip off the encoding
                val.retain(|v| !v.is_control());
                let val = val.trim().to_string();
                Ok(val)
            }
            Err(_e) => Err(Web3Error::ContractCallError(
                "name is not valid utf8".to_string(),
            )),
        }
    }

    pub async fn get_erc721_supply(
        &self,
        erc721: Address,
        caller_address: Address,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("totalSupply()", &[])?;
        let decimals = self
            .simulate_transaction(erc721, 0u8.into(), payload, caller_address, None)
            .await?;

        Ok(Uint256::from_bytes_be(match decimals.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from ERC721 Total Supply".to_string(),
                ))
            }
        }))
    }

    pub async fn get_erc721_owner_of(
        &self,
        erc721: Address,
        own_address: Address,
        token_id: Uint256,
    ) -> Result<EthAddress, Web3Error> {
        let payload = encode_call(
            "ownerOf(uint256)",
            &[Token::Uint(token_id.clone())],
        )?;

        let val = self
        .simulate_transaction(erc721, 0u8.into(), payload, own_address, None)
        .await?;

        let mut data: [u8; 20] = Default::default();
        data.copy_from_slice(&val[12..]);
        let owner_address = EthAddress::from_slice(&data);

        match owner_address {
            Ok(address_response) => Ok(address_response),
            Err(e) => Err(Web3Error::BadResponse(e.to_string())),
        }
    }

    pub async fn check_erc721_approved(
        &self,
        erc721: Address,
        own_address: Address,
        token_id: Uint256,
    ) -> Result<EthAddress, Web3Error> {
        let payload = encode_call(
            "getApproved(uint256)",
            &[Token::Uint(token_id.clone())],
        )?;

        let val = self
        .simulate_transaction(erc721, 0u8.into(), payload, own_address, None)
        .await?;

        let mut data: [u8; 20] = Default::default();
        data.copy_from_slice(&val[12..]);
        let owner_address = EthAddress::from_slice(&data);

        match owner_address {
            Ok(address_response) => Ok(address_response),
            Err(e) => Err(Web3Error::BadResponse(e.to_string())),
        }
    }

}

#[test]
fn test_erc721_metadata() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    let bayc_address = "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D"
        .parse()
        .unwrap();
    // random coinbase address hoping it always has eth to 'pay' for this call
    let caller_address = "0x503828976D22510aad0201ac7EC88293211D23Da"
        .parse()
        .unwrap();
    runner.block_on(async move {
        let num: Uint256 = 1000u32.into();
        assert!(
            web3.get_erc721_supply(bayc_address, caller_address)
                .await
                .unwrap()
                > num
        );
        assert_eq!(
            web3.get_erc721_symbol(bayc_address, caller_address)
                .await
                .unwrap(),
            "BAYC"
        );
        assert_eq!(
            web3.get_erc721_name(bayc_address, caller_address)
                .await
                .unwrap(),
            "BoredApeYachtClub"
        );
    })
}
