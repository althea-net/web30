// Performs interactions with AMMs (Automated Market Makers) on ethereum
use crate::{client::Web3, jsonrpc::error::Web3Error, types::SendTxOption};
use clarity::{
    abi::{Token, encode_call},
    constants::{TT160M1, TT24M1},
    Address, PrivateKey, Uint256,
};

lazy_static! {
    pub static ref UNISWAP_QUOTER_ADDRESS: Address =
        Address::parse_and_validate("0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6").unwrap();
    pub static ref DAI_CONTRACT_ADDRESS: Address =
        Address::parse_and_validate("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
    pub static ref WETH_CONTRACT_ADDRESS: Address =
        Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
}

impl Web3 {
    // Returns the number of token_out obtainable for amount of token_in + fee_uint24 via Uniswap
    // Uniswap's v3 documentation states "Liquidity providers may initially create pools at three fee levels:
    // 0.05% (500), 0.30% (3000), and 1% (10000). More fee levels may be added by UNI governance."
    // Calls quoteExactInputSingle(address,address,uint24,uint256,uint160) on uniswap_quoter or a default uniswap address
    #[allow(clippy::too_many_arguments)]
    pub async fn get_uniswap_price(
        &self,
        caller_address: Address,
        token_in: Address,                     // The token held
        token_out: Address,                    // The desired token
        fee_uint24: Uint256,                   // Actually a uint24 on the callee side
        amount: Uint256,                       // The amount of tokens offered up
        sqrt_price_limit_x96_uint160: Uint256, // Actually a uint160 on the callee side
        uniswap_quoter: Option<Address>, // The default quoter will be used if none is provided
    ) -> Result<Uint256, Web3Error> {
        let quoter = get_quoter_or_default(uniswap_quoter);

        if bad_fee(&fee_uint24) {
            return Err(Web3Error::BadInput(
                "Bad fee input to swap price - value too large for uint24".to_string(),
            ));
        }

        if bad_sqrt_price_limit(&sqrt_price_limit_x96_uint160) {
            return Err(Web3Error::BadInput(
                "Bad sqrt_price_limit_x96 input to swap price - value too large for uint160"
                    .to_string(),
            ));
        }

        let tokens: [Token; 5] = [
            Token::Address(token_in),
            Token::Address(token_out),
            Token::Uint(fee_uint24),
            Token::Uint(amount),
            Token::Uint(sqrt_price_limit_x96_uint160),
        ];

        println!("tokens is  {:?}", tokens);
        let result = self
            .contract_call(
                quoter,
                "quoteExactInputSingle(address,address,uint24,uint256,uint160)",
                &tokens,
                caller_address,
                None,
            )
            .await?;
        println!("result is {:?}", result);
        Ok(Uint256::from_bytes_be(match result.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from swap price".to_string(),
                ))
            }
        }))
    }

    // Performs a swap using uniswap by calling exactInputSingle(struct) on quoter or a default uniswap address
    pub async fn swap_uniswap(
        &self,
        eth_private_key: PrivateKey,           // The address swapping tokens
        token_in: Address,                     // The token held
        token_out: Address,                    // The desired token
        fee_uint24: Uint256,                   // Actually a uint24 on the callee side
        amount: Uint256,                       // The amount of tokens offered up
        deadline: Uint256,                     // A deadline by which the swap must happen
        amount_out_min: Uint256,               // The minimum output tokens to receive in a swap
        sqrt_price_limit_x96_uint160: Uint256, // Actually a uint160 on the callee side
        uniswap_quoter: Option<Address>,       // The default quoter will be used if None is provided
        options: Option<Vec<SendTxOption>>,    // Options for send_transaction
    ) -> Result<Uint256, Web3Error> {
        if bad_fee(&fee_uint24) {
            return Err(Web3Error::BadInput(
                "Bad fee input to swap_uniswap - value too large for uint24".to_string(),
            ));
        }

        if bad_sqrt_price_limit(&sqrt_price_limit_x96_uint160) {
            return Err(Web3Error::BadInput(
                "Bad sqrt_price_limit_x96 input to swap_uniswap - value too large for uint160"
                    .to_string(),
            ));
        }

        let own_address = eth_private_key.to_public_key().unwrap();
        let quoter = get_quoter_or_default(uniswap_quoter);
        //struct ExactInputSingleParams { // The uniswap exactInputSingle argument
        //    address tokenIn;
        //    address tokenOut;
        //    uint24 fee;
        //    address recipient;
        //    uint256 deadline;
        //    uint256 amountIn;
        //    uint256 amountOutMinimum;
        //    uint160 sqrtPriceLimitX96;
        //}
        let tokens: Vec<Token> = vec![
            Token::Address(token_in),
            Token::Address(token_out),
            Token::Uint(fee_uint24),
            Token::Address(own_address),
            Token::Uint(deadline),
            Token::Uint(amount),
            Token::Uint(amount_out_min),
            Token::Uint(sqrt_price_limit_x96_uint160)
        ];
        let tokens = [Token::Struct(tokens)];
        let payload = encode_call("exactInputSingle(struct)", &tokens).unwrap();
        let options = match options {
            Some(vec) => vec,
            None => vec![]
        };

        println!("payload is  {:?}", payload);
        let result = self
            .send_transaction(
                quoter,
                payload,
                0u32.into(),
                own_address,
                eth_private_key,
                options,
            )
            .await?;
        println!("result is {:?}", result);
        Ok(result)
    }
}

// Returns the quoter specified, or a default one
fn get_quoter_or_default(uniswap_quoter: Option<Address>) -> Address {
    match uniswap_quoter {
        Some(val) => val,
        None => *UNISWAP_QUOTER_ADDRESS,
    }
}

// Checks that the input fee value is within the limits of uint24
fn bad_fee(fee: &Uint256) -> bool {
    return *fee > *TT24M1;
}

// Checks that the input sqrt_price_limit value is within the limits of uint160
fn bad_sqrt_price_limit(sqrt_price_limit: &Uint256) -> bool {
    return *sqrt_price_limit > *TT160M1;
}

#[test]
fn get_uniswap_price_test() {
    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("debug")).init(); // Change to debug for logs
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    let caller_address =
        Address::parse_and_validate("0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c").unwrap();
    let amount = Uint256::from(1_000_000_000_000_000_000u64);
    let fee = Uint256::from(500u16);
    let sqrt_price_limit_x96_uint160 = Uint256::from(0u16);

    runner.block_on(async move {
        let price = web3
            .get_uniswap_price(
                caller_address,
                *WETH_CONTRACT_ADDRESS,
                *DAI_CONTRACT_ADDRESS,
                fee.clone(),
                amount.clone(),
                sqrt_price_limit_x96_uint160.clone(),
                None,
            )
            .await;
        let weth2dai = price.unwrap();
        debug!("weth->dai price is {}", weth2dai);
        assert!(weth2dai > 0u32.into());
        let price = web3
            .get_uniswap_price(
                caller_address,
                *DAI_CONTRACT_ADDRESS,
                *WETH_CONTRACT_ADDRESS,
                fee.clone(),
                weth2dai,
                sqrt_price_limit_x96_uint160,
                None,
            )
            .await;
        let dai2weth = price.unwrap();
        debug!("dai->weth price is {}", &dai2weth);
        let amount_float: f64 = (amount.to_string()).parse().unwrap();
        let dai2weth_float: f64 = (dai2weth.to_string()).parse().unwrap();
        // If we were to swap, we should get within 5% back what we originally put in to account for slippage and fees
        assert!((0.95 * amount_float) < dai2weth_float && dai2weth_float < (1.05 * amount_float));
    });
}
