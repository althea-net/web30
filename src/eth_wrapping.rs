use clarity::abi::Token;
use clarity::Address;
use clarity::{abi::encode_call, PrivateKey, Uint256};

use crate::amm::WETH_CONTRACT_ADDRESS;
use crate::{client::Web3, jsonrpc::error::Web3Error};

// Performs wrapping and unwrapping of eth, along with balance checking
impl Web3 {
    pub async fn wrap_eth(
        &self,
        amount: Uint256,
        secret: PrivateKey,
        weth_address: Option<Address>,
    ) -> Result<Uint256, Web3Error> {
        let own_address = secret.to_public_key().unwrap();
        let sig = "deposit()";
        let tokens = [];
        let payload = encode_call(sig, &tokens).unwrap();
        let weth_address = weth_address.unwrap_or(*WETH_CONTRACT_ADDRESS);
        self.send_transaction(weth_address, payload, amount, own_address, secret, vec![])
            .await
    }

    pub async fn unwrap_eth(
        &self,
        amount: Uint256,
        secret: PrivateKey,
        weth_address: Option<Address>,
    ) -> Result<Uint256, Web3Error> {
        let own_address = secret.to_public_key().unwrap();
        let sig = "withdraw(uint256)";
        let tokens = [Token::Uint(amount)];
        let payload = encode_call(sig, &tokens).unwrap();
        let weth_address = weth_address.unwrap_or(*WETH_CONTRACT_ADDRESS);
        self.send_transaction(
            weth_address,
            payload,
            0u16.into(),
            own_address,
            secret,
            vec![],
        )
        .await
    }
}
