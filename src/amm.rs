// Performs interactions with AMMs (Automated Market Makers) on ethereum
use crate::{client::Web3, jsonrpc::error::Web3Error, types::SendTxOption};
use clarity::{
    abi::{encode_call, Token},
    constants::{TT160M1, TT24M1},
    Address, PrivateKey, Uint256,
};
use num::BigUint;

/// Default padding multiplied to uniswap exchange gas limit values due to variablity of gas limit values
/// between iterations
pub const DEFAULT_GAS_LIMIT_MULT: f32 = 1.2;

lazy_static! {
    /// Uniswap V3's Quoter interface for checking current swap prices, from prod Ethereum
    pub static ref UNISWAP_QUOTER_ADDRESS: Address =
        Address::parse_and_validate("0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6").unwrap();
    /// Uniswap V3's Router interface for swapping tokens, from prod Ethereum
    pub static ref UNISWAP_ROUTER_ADDRESS: Address =
        Address::parse_and_validate("0xE592427A0AEce92De3Edee1F18E0157C05861564").unwrap();
    /// The DAI V2 Token's address, on prod Ethereum
    pub static ref DAI_CONTRACT_ADDRESS: Address =
        Address::parse_and_validate("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
    /// The Wrapped Ether's address, on prod Ethereum
    pub static ref WETH_CONTRACT_ADDRESS: Address =
        Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
}

impl Web3 {
    /// Checks Uniswap v3 to get the amount of `token_out` obtainable for `amount`
    /// of `token_in`
    ///
    /// # Arguments
    ///
    /// * `caller_address` - The ethereum address making the request
    /// * `token_in` - The address of an ERC20 token to offer up
    /// * `token_out` - The address of an ERC20 token to receive
    /// * `fee_uint24` - Optional fee level of the `token_in`<->`token_out` pool to query - limited to uint24 in size.
    ///    Defaults to the medium pool fee of 0.05%
    ///    The initial pools are 0.05% (500), 0.3% (3000), and 1% (10000) but more may be added
    /// * `sqrt_price_limit_x96_uint160` - Optional square root price limit
    /// * `uniswap_quoter` - Optional address of the Uniswap v3 quoter to contact
    ///
    /// # Examples
    /// ```rust,ignore
    /// use std::time::Duration;
    /// use std::str::FromStr;
    /// use clarity::Address;
    /// use clarity::Uint256;
    /// use web30::amm::*;
    /// use web30::client::Web3;
    /// let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    /// let result = web3.get_uniswap_price(
    ///     Address::parse_and_validate("0x1111111111111111111111111111111111111111").unwrap(),
    ///     *WETH_CONTRACT_ADDRESS,
    ///     *DAI_CONTRACT_ADDRESS,
    ///     Some(500u16.into()),
    ///     Uint256::from_str("1000000000000000000"), // 1 WETH
    ///     Some(uniswap_sqrt_price(1u8.into(), 2023u16.into())), // Sample 1 Eth ->  2k Dai swap rate
    ///     Some(*UNISWAP_QUOTER_ADDRESS),
    /// );
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn get_uniswap_price(
        &self,
        caller_address: Address,
        token_in: Address,                             // The token held
        token_out: Address,                            // The desired token
        fee_uint24: Option<Uint256>,                   // Actually a uint24 on the callee side
        amount: Uint256,                               // The amount of tokens offered up
        sqrt_price_limit_x96_uint160: Option<Uint256>, // Actually a uint160 on the callee side
        uniswap_quoter: Option<Address>, // The default quoter will be used if none is provided
    ) -> Result<Uint256, Web3Error> {
        let quoter = uniswap_quoter.unwrap_or(*UNISWAP_QUOTER_ADDRESS);

        let fee_uint24 = fee_uint24.unwrap_or_else(|| 500u32.into());
        if bad_fee(&fee_uint24) {
            return Err(Web3Error::BadInput(
                "Bad fee input to swap price - value too large for uint24".to_string(),
            ));
        }

        let sqrt_price_limit_x96_uint160 = sqrt_price_limit_x96_uint160.unwrap_or_default();
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

        debug!("tokens is  {:?}", tokens);
        let payload = encode_call(
            "quoteExactInputSingle(address,address,uint24,uint256,uint160)",
            &tokens,
        )?;
        let result = self
            .simulate_transaction(quoter, 0u8.into(), payload, caller_address, None)
            .await?;
        debug!("result is {:?}", result);
        Ok(Uint256::from_bytes_be(match result.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from swap price".to_string(),
                ))
            }
        }))
    }

    /// Performs an exact input single pool swap via Uniswap v3, exchanging `amount` of `token_in` for `token_out`
    ///
    /// # Arguments
    /// * `eth_private_key` - The private key of the holder of `token_in` who will receive `token_out`
    /// * `token_in` - The address of the ERC20 token to exchange for `token_out`
    /// * `token_out` - The address of the ERC20 token to receive
    /// * `fee_uint24` - Optional fee level of the `token_in`<->`token_out` pool to query - limited to uint24 in size.
    ///    Defaults to the medium pool fee of 0.3%
    ///    The initial pools are 0.05% (500), 0.3% (3000), and 1% (10000) but more may be added
    /// * `amount` - The amount of `token_in` to exchange for as much `token_out` as possible
    /// * `deadline` - Optional deadline to the swap before it is cancelled, 10 minutes if None
    /// * `amount_out_min` - Optional minimum amount of `token_out` to receive or the swap is cancelled, ignored if None
    /// * `sqrt_price_limit_x96_64` - Optional square root price limit, ignored if None
    /// * `uniswap_router` - Optional address of the Uniswap v3 SwapRouter to contact
    /// * `options` - Optional arguments for the Transaction, see send_transaction()
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    /// use clarity::PrivateKey;
    /// use web30::amm::*;
    /// use web30::client::Web3;
    /// let web3 = Web3::new("http://localhost:8545", Duration::from_secs(5));
    /// let result = web3.swap_uniswap(
    ///     "0x1111111111111111111111111111111111111111111111111111111111111111".parse().unwrap(),
    ///     *WETH_CONTRACT_ADDRESS,
    ///     *DAI_CONTRACT_ADDRESS,
    ///     Some(500u16.into()),
    ///     1000000000000000000u128.into(), // 1 WETH
    ///     Some(60u8.into()), // Wait 1 minute
    ///     Some(2020000000000000000000u128.into()), // Expect >= 2020 DAI
    ///     Some(uniswap_sqrt_price(1u8.into(), 2023u16.into())), // Sample 1 Eth ->  2k Dai swap rate
    ///     Some(*UNISWAP_ROUTER_ADDRESS),
    ///     None,
    /// );
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn swap_uniswap(
        &self,
        eth_private_key: PrivateKey,     // The address swapping tokens
        token_in: Address,               // The token held
        token_out: Address,              // The desired token
        fee_uint24: Option<Uint256>,     // Actually a uint24 on the callee side
        amount: Uint256,                 // The amount of tokens offered up
        deadline: Option<Uint256>,       // A deadline by which the swap must happen
        amount_out_min: Option<Uint256>, // The minimum output tokens to receive in a swap
        sqrt_price_limit_x96_uint160: Option<Uint256>, // Actually a uint160 on the callee side
        uniswap_router: Option<Address>, // The default router will be used if None is provided
        options: Option<Vec<SendTxOption>>, // Options for send_transaction
    ) -> Result<Uint256, Web3Error> {
        let fee_uint24 = fee_uint24.unwrap_or_else(|| 3000u16.into());
        if bad_fee(&fee_uint24) {
            return Err(Web3Error::BadInput(
                "Bad fee input to swap_uniswap - value too large for uint24".to_string(),
            ));
        }

        let sqrt_price_limit_x96_uint160 = sqrt_price_limit_x96_uint160.unwrap_or_default();
        if bad_sqrt_price_limit(&sqrt_price_limit_x96_uint160) {
            return Err(Web3Error::BadInput(
                "Bad sqrt_price_limit_x96 input to swap_uniswap - value too large for uint160"
                    .to_string(),
            ));
        }

        let eth_address = eth_private_key.to_public_key().unwrap();
        let router = uniswap_router.unwrap_or(*UNISWAP_ROUTER_ADDRESS);
        let deadline = match deadline {
            // Default to latest block + 10 minutes
            None => self.eth_get_latest_block().await.unwrap().timestamp + (10u64 * 60u64).into(),
            Some(val) => val,
        };
        let amount_out_min = amount_out_min.unwrap_or_default();
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
            token_in.into(),
            token_out.into(),
            fee_uint24.into(),
            eth_address.into(),
            deadline.into(),
            amount.into(),
            amount_out_min.into(),
            sqrt_price_limit_x96_uint160.into(),
        ];
        let tokens = [Token::Struct(tokens)];
        let payload = encode_call(
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
            &tokens,
        )
        .unwrap();

        // default gas limit multiplier
        let mut options = options.unwrap_or_default();
        let glm = DEFAULT_GAS_LIMIT_MULT;
        let set_glm = options_contains_glm(&options);

        if !set_glm {
            options.push(SendTxOption::GasLimitMultiplier(glm));
        }

        let _token_in_approval = self
            .approve_erc20_transfers(token_in, eth_private_key, router, None, vec![])
            .await
            .unwrap();
        debug!("token_in approved");

        debug!("payload is  {:?}", payload);
        let result = self
            .send_transaction(
                router,
                payload,
                0u32.into(),
                eth_address,
                eth_private_key,
                options,
            )
            .await?;
        debug!("result is {:?}", result);
        Ok(result)
    }

    /// Performs an exact input single pool swap via Uniswap v3, exchanging `amount` of eth directly for `token_out`
    ///
    /// IMPORTANT: normally Uniswap v3 only works with ERC20 tokens, but in the case of transfers involving wETH, they will
    /// wrap the ETH for you before the swap. Using this method you will be charged the additional gas required to wrap
    /// the input `amount` of ETH. If you will be calling this method multiple times, it is likely cheaper to wrap a lot of ETH
    /// and calling swap_uniswap() instead.
    ///
    /// # Arguments
    /// * `eth_private_key` - The private key of the holder of `token_in` who will receive `token_out`
    /// * `token_out` - The address of the ERC20 token to receive
    /// * `fee_uint24` - Optional fee level of the `token_in`<->`token_out` pool to query - limited to uint24 in size.
    ///    Defaults to the medium pool fee of 0.3%
    ///    The initial pools are 0.05% (500), 0.3% (3000), and 1% (10000) but more may be added
    /// * `amount` - The amount of `token_in` to exchange for as much `token_out` as possible
    /// * `deadline` - Optional deadline to the swap before it is cancelled, 10 minutes if None
    /// * `amount_out_min` - Optional minimum amount of `token_out` to receive or the swap is cancelled, ignored if None
    /// * `sqrt_price_limit_x96_64` - Optional square root price limit, ignored if None
    /// * `uniswap_router` - Optional address of the Uniswap v3 SwapRouter to contact
    /// * `options` - Optional arguments for the Transaction, see send_transaction()
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    /// use clarity::PrivateKey;
    /// use web30::amm::*;
    /// use web30::client::Web3;
    /// let web3 = Web3::new("http://localhost:8545", Duration::from_secs(5));
    /// let result = web3.swap_uniswap_eth_in(
    ///     "0x1111111111111111111111111111111111111111111111111111111111111111".parse().unwrap(),
    ///     *DAI_CONTRACT_ADDRESS,
    ///     Some(500u16.into()),
    ///     1000000000000000000u128.into(), // 1 WETH
    ///     Some(60u8.into()), // Wait 1 minute
    ///     Some(2020000000000000000000u128.into()), // Expect >= 2020 DAI
    ///     Some(uniswap_sqrt_price(1u8.into(), 2023u16.into())), // Sample 1 Eth ->  2k Dai swap rate
    ///     Some(*UNISWAP_ROUTER_ADDRESS),
    ///     None,
    /// );
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn swap_uniswap_eth_in(
        &self,
        eth_private_key: PrivateKey,     // the address swapping tokens
        token_out: Address,              // the desired token
        fee_uint24: Option<Uint256>,     // actually a uint24 on the callee side
        amount: Uint256,                 // the amount of tokens offered up
        deadline: Option<Uint256>,       // a deadline by which the swap must happen
        amount_out_min: Option<Uint256>, // the minimum output tokens to receive in a swap
        sqrt_price_limit_x96_uint160: Option<Uint256>, // actually a uint160 on the callee side
        uniswap_router: Option<Address>, // the default router will be used if none is provided
        options: Option<Vec<SendTxOption>>, // options for send_transaction
    ) -> Result<Uint256, Web3Error> {
        let token_in = *WETH_CONTRACT_ADDRESS; // Uniswap requires WETH to be one of the swap tokens for ETH swaps
        let fee_uint24 = fee_uint24.unwrap_or_else(|| 3000u16.into());
        if bad_fee(&fee_uint24) {
            return Err(Web3Error::BadInput(
                "Bad fee input to swap_uniswap_eth_in - value too large for uint24".to_string(),
            ));
        }

        let sqrt_price_limit_x96_uint160 = sqrt_price_limit_x96_uint160.unwrap_or_default();
        if bad_sqrt_price_limit(&sqrt_price_limit_x96_uint160) {
            return Err(Web3Error::BadInput(
                "Bad sqrt_price_limit_x96 input to swap_uniswap_eth_in - value too large for uint160"
                    .to_string(),
            ));
        }

        let eth_address = eth_private_key.to_public_key().unwrap();
        let router = uniswap_router.unwrap_or(*UNISWAP_ROUTER_ADDRESS);
        let deadline = match deadline {
            // Default to latest block + 10 minutes
            None => self.eth_get_latest_block().await.unwrap().timestamp + (10u64 * 60u64).into(),
            Some(val) => val,
        };
        let amount_out_min = amount_out_min.unwrap_or_default();
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
            token_in.into(),
            token_out.into(),
            fee_uint24.into(),
            eth_address.into(),
            deadline.into(),
            amount.clone().into(),
            amount_out_min.into(),
            sqrt_price_limit_x96_uint160.into(),
        ];
        let tokens = [Token::Struct(tokens)];
        let payload = encode_call(
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
            &tokens,
        )
        .unwrap();

        // default gas limit multiplier
        let mut options = options.unwrap_or_default();
        let glm = DEFAULT_GAS_LIMIT_MULT;
        let set_glm = options_contains_glm(&options);

        if !set_glm {
            options.push(SendTxOption::GasLimitMultiplier(glm));
        }

        debug!("payload is  {:?}", payload);
        let result = self
            .send_transaction(
                router,
                payload,
                amount.clone(),
                eth_address,
                eth_private_key,
                options,
            )
            .await?;
        debug!("result is {:?}", result);
        Ok(result)
    }
}

/// Helper function that tells us wheter the options parameter has a GasLimitMultiplier set or not
fn options_contains_glm(options: &[SendTxOption]) -> bool {
    for option in options {
        match option {
            SendTxOption::GasLimitMultiplier(_) => return true,
            _ => continue,
        }
    }

    false
}

// Checks that the input fee value is within the limits of uint24
fn bad_fee(fee: &Uint256) -> bool {
    *fee > *TT24M1
}

// Checks that the input sqrt_price_limit value is within the limits of uint160
fn bad_sqrt_price_limit(sqrt_price_limit: &Uint256) -> bool {
    *sqrt_price_limit > *TT160M1
}

/// Computes the sqrt price of a pool given token_1's liquidity and token_0's liquidity
/// When used as the sqrt price limit, this calculates the maximum price that a swap
/// is allowed to push the pool to by changing the underlying liquidity
/// Attempts to encode the result as a Q64.96 (a rational number with 64 bits of
/// numerator precision, 96 bits of denominator precision) by copying the
/// javascript implementation
pub fn uniswap_sqrt_price(amount_1: Uint256, amount_0: Uint256) -> Uint256 {
    // Uniswap's javascript implementation with arguments amount1 and amount0
    //   const numerator = JSBI.leftShift(JSBI.BigInt(amount1), JSBI.BigInt(192))
    //   const denominator = JSBI.BigInt(amount0)
    //   const ratioX192 = JSBI.divide(numerator, denominator)
    //   return sqrt(ratioX192)

    let numerator: BigUint = amount_1.0 << 192;
    let denominator: BigUint = amount_0.0;
    let ratio_x192 = numerator / denominator;
    Uint256(BigUint::sqrt(&ratio_x192))
}
#[ignore]
#[test]
fn get_uniswap_price_test() {
    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("warn")).init(); // Change to debug for logs
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
                Some(fee.clone()),
                amount.clone(),
                Some(sqrt_price_limit_x96_uint160.clone()),
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
                Some(fee.clone()),
                weth2dai,
                Some(sqrt_price_limit_x96_uint160),
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

#[test]
// Avoid accidentally spending funds or failing when not running hardhat
#[ignore]
// Note: If you specify a live eth node in Web3::new() and a real private key below, real funds will be used.
// Run this test with the local hardhat environment running
// Swaps WETH for DAI then back again
fn swap_hardhat_test() {
    // this key is the private key for the public key defined in tests/assets/ETHGenesis.json
    // where the full node / miner sends its rewards. Therefore it's always going
    // to have a lot of ETH to pay for things like contract deployments
    let miner_private_key: PrivateKey =
        "0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7"
            .parse()
            .unwrap();
    let miner_address: Address = miner_private_key.to_public_key().unwrap();

    use crate::client::Web3;
    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("warn")).init(); // Change to debug for logs
    let runner = System::new();

    let web3 = Web3::new("http://localhost:8545", Duration::from_secs(300));
    let amount = Uint256::from(1000000000000000000u64); // 1 weth
    let amount_out_min: Uint256 = 0u8.into();
    let fee = Uint256::from(500u16);

    let sqrt_price_limit_x96_uint160: Uint256 = 0u8.into();
    runner.block_on(async move {
        let block = web3.eth_get_latest_block().await.unwrap();
        let deadline = block.timestamp + (10u32 * 60u32 * 100000u32).into();

        let success = web3.wrap_eth(amount.clone(), miner_private_key, None).await;
        if let Ok(b) = success {
            info!("Wrapped eth: {}", b);
        } else {
            panic!("Failed to wrap eth before testing uniswap");
        }
        let initial_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        let initial_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();

        info!(
            "Initial WETH: {}, Initial DAI: {}",
            initial_weth, initial_dai
        );

        let result = web3
            .swap_uniswap(
                miner_private_key,
                *WETH_CONTRACT_ADDRESS,
                *DAI_CONTRACT_ADDRESS,
                Some(fee.clone()),
                amount.clone(),
                Some(deadline.clone()),
                Some(amount_out_min.clone()),
                Some(sqrt_price_limit_x96_uint160.clone()),
                None,
                None,
            )
            .await;
        if result.is_err() {
            panic!("Error performing first swap: {:?}", result.err());
        }
        let executing_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        let executing_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        info!(
            "Executing WETH: {}, Executing DAI: {}",
            executing_weth, executing_dai
        );

        let dai_gained = executing_dai.clone() - initial_dai.clone();
        assert!(dai_gained > 0u8.into());
        let result = web3
            .swap_uniswap(
                miner_private_key,
                *DAI_CONTRACT_ADDRESS,
                *WETH_CONTRACT_ADDRESS,
                Some(fee.clone()),
                dai_gained.clone(),
                Some(deadline.clone()),
                Some(amount_out_min.clone()),
                Some(sqrt_price_limit_x96_uint160.clone()),
                None,
                None,
            )
            .await;
        if result.is_err() {
            panic!("Error performing second swap: {:?}", result.err());
        }
        let final_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        let final_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        info!("Final WETH: {}, Final DAI: {}", final_weth, final_dai);
        let final_dai_delta = final_dai - initial_dai;
        assert!(final_dai_delta == 0u8.into()); // We should have gained little to no dai

        let weth_gained: f64 = (final_weth - executing_weth).to_string().parse().unwrap();
        let original_amount: f64 = (amount).to_string().parse().unwrap();
        // we should not have lost or gained much
        assert!(0.95 * original_amount < weth_gained && weth_gained < 1.05 * original_amount);
    });
}

#[test]
// Avoid accidentally spending funds or failing when not running hardhat
#[ignore]
// Note: If you specify a live eth node in Web3::new() and a real private key below, real funds will be used.
// Run this test with the local hardhat environment running
// Swaps WETH for DAI then back again
fn swap_hardhat_eth_in_test() {
    // this key is the private key for the public key defined in tests/assets/ETHGenesis.json
    // where the full node / miner sends its rewards. Therefore it's always going
    // to have a lot of ETH to pay for things like contract deployments
    let miner_private_key: PrivateKey =
        "0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7"
            .parse()
            .unwrap();
    let miner_address: Address = miner_private_key.to_public_key().unwrap();

    use crate::client::Web3;
    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("warn")).init(); // Change to debug for logs
    let runner = System::new();

    let web3 = Web3::new("http://localhost:8545", Duration::from_secs(300));
    let amount = Uint256::from(1000000000000000000u64); // 1 weth
    let amount_out_min: Uint256 = 0u8.into();
    let fee = Uint256::from(500u16);

    let sqrt_price_limit_x96_uint160: Uint256 = 0u8.into();
    runner.block_on(async move {
        let block = web3.eth_get_latest_block().await.unwrap();
        let deadline = block.timestamp + (10u32 * 60u32 * 100000u32).into();

        let initial_eth = web3.eth_get_balance(miner_address).await.unwrap();
        let initial_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        let initial_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();

        info!(
            "Initial ETH: {}, Initial WETH: {}, Initial DAI: {}",
            initial_eth, initial_weth, initial_dai
        );
        let result = web3
            .swap_uniswap_eth_in(
                miner_private_key,
                *DAI_CONTRACT_ADDRESS,
                Some(fee.clone()),
                amount.clone(),
                Some(deadline.clone()),
                Some(amount_out_min.clone()),
                Some(sqrt_price_limit_x96_uint160.clone()),
                None,
                None,
            )
            .await;
        if result.is_err() {
            panic!("Error performing first swap: {:?}", result.err());
        }
        let final_eth = web3.eth_get_balance(miner_address).await.unwrap();
        let final_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        let final_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address)
            .await
            .unwrap();
        info!(
            "Final ETH: {}, Final WETH: {}, Final DAI: {}",
            final_eth, final_weth, final_dai
        );

        let dai_gained = final_dai - initial_dai;
        // At the point the chain is frozen for the relay market test,
        // we expect to receive expect to receive about 2,300 dai
        let two_k_dai = 2000 * 1_000_000_000_000_000_000u128;
        let one_eth = 1_000_000_000_000_000_000u128;
        assert!(
            dai_gained > two_k_dai.into(),
            "dai_gained = {} <= 2000 * 10^18",
            dai_gained
        );
        let eth_lost = initial_eth - final_eth;
        assert!(
            eth_lost > one_eth.into(),
            "eth_lost = {} <= 1 * 10^18",
            eth_lost
        );

        assert!(
            final_weth == initial_weth,
            "Did not expect to modify wETH balance. Started with {} ended with {}",
            initial_weth,
            final_weth
        );

        info!(
            "Effectively swapped {} eth for {} dai",
            eth_lost, dai_gained
        );
    });
}
