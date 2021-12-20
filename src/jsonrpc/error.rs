use clarity::Error as ClarityError;
use clarity::Uint256;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::num::ParseIntError;
use std::time::Duration;
use tokio::time::error::Elapsed;

#[derive(Debug)]
pub enum Web3Error {
    BadResponse(String),
    JsonRpcError(reqwest::Error),
    InsufficientGas {
        balance: Uint256,
        base_gas: Uint256,
        gas_required: Uint256,
    },
    BadInput(String),
    EventNotFound(String),
    CouldNotRemoveFilter(String),
    ClarityError(ClarityError),
    ContractCallError(String),
    TransactionTimeout,
    NoBlockProduced {
        time: Duration,
    },
}

impl From<ParseIntError> for Web3Error {
    fn from(error: ParseIntError) -> Self {
        Web3Error::BadResponse(format!("{}", error))
    }
}

impl From<ClarityError> for Web3Error {
    fn from(error: ClarityError) -> Self {
        Web3Error::ClarityError(error)
    }
}

impl From<Elapsed> for Web3Error {
    fn from(_error: Elapsed) -> Self {
        Web3Error::TransactionTimeout
    }
}

impl From<reqwest::Error> for Web3Error {
    fn from(error: reqwest::Error) -> Self {
        Web3Error::JsonRpcError(error)
    }
}

impl From<serde_json::Error> for Web3Error {
    fn from(error: serde_json::Error) -> Self {
        Web3Error::BadResponse(error.to_string())
    }
}

impl Display for Web3Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            Web3Error::BadResponse(val) => write!(f, "Web3 bad response {}", val),
            Web3Error::BadInput(val) => write!(f, "Web3 bad input {}", val),
            Web3Error::JsonRpcError(val) => write!(f, "Web3 JsonRpc Failed {}", val),
            Web3Error::EventNotFound(val) => write!(f, "Web3 Failed to find event {}", val),
            Web3Error::ClarityError(val) => write!(f, "ClarityError {}", val),
            Web3Error::TransactionTimeout => write!(f, "Transaction did not enter chain in time"),
            Web3Error::NoBlockProduced { time } => {
                write!(
                    f,
                    "No Ethereum block was produced for {} seconds",
                    time.as_secs()
                )
            }
            Web3Error::InsufficientGas {
                balance,
                base_gas,
                gas_required,
            } => {
                write!(f, "Block has base_fee_per_gas {} and transaction requires {} gas. Your balance of {} < {}. Transaction impossible",
            base_gas, gas_required, balance, base_gas.clone() * gas_required.clone())
            }
            Web3Error::ContractCallError(val) => {
                write!(f, "Error performing Ethereum contract call {}", val)
            }
            Web3Error::CouldNotRemoveFilter(val) => {
                write!(f, "Web3 Failed to remove filter from server {}", val)
            }
        }
    }
}

impl Error for Web3Error {}
