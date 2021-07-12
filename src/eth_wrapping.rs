use clarity::abi::Token;
use clarity::{abi::encode_call, PrivateKey, Uint256};

use crate::amm::WETH_CONTRACT_ADDRESS;
use crate::{client::Web3, jsonrpc::error::Web3Error};

// Performs wrapping and unwrapping of eth, along with balance checking
impl Web3 {
    pub async fn wrap_eth(
        &self,
        amount: Uint256,
        secret: PrivateKey,
    ) -> Result<Uint256, Web3Error> {
        let own_address = secret.to_public_key().unwrap();
        let sig = "deposit()";
        let tokens = [];
        let payload = encode_call(sig, &tokens).unwrap();
        self.send_transaction(
            *WETH_CONTRACT_ADDRESS,
            payload,
            amount,
            own_address,
            secret,
            vec![],
        )
        .await
    }

    pub async fn unwrap_eth(
        &self,
        amount: Uint256,
        secret: PrivateKey,
    ) -> Result<Uint256, Web3Error> {
        let own_address = secret.to_public_key().unwrap();
        let sig = "withdraw(uint256)";
        let tokens = [Token::Uint(amount)];
        let payload = encode_call(sig, &tokens).unwrap();
        self.send_transaction(
            *WETH_CONTRACT_ADDRESS,
            payload,
            0u16.into(),
            own_address,
            secret,
            vec![],
        )
        .await
    }
}
