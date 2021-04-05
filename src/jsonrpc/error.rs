use awc::error::SendRequestError as ActixError;
use clarity::Error as ClarityError;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::num::ParseIntError;
use tokio::time::error::Elapsed;

#[derive(Debug)]
pub enum Web3Error {
    BadResponse(String),
    FailedToSend(ActixError),
    JsonRpcError {
        code: i64,
        message: String,
        data: String,
    },
    BadInput(String),
    EventNotFound(String),
    CouldNotRemoveFilter(String),
    ClarityError(ClarityError),
    ContractCallError(String),
    TransactionTimeout,
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

impl Display for Web3Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            Web3Error::BadResponse(val) => write!(f, "Web3 bad response {}", val),
            Web3Error::BadInput(val) => write!(f, "Web3 bad input {}", val),
            Web3Error::FailedToSend(val) => write!(f, "Web3 Failed to send {}", val),
            Web3Error::EventNotFound(val) => write!(f, "Web3 Failed to find event {}", val),
            Web3Error::ClarityError(val) => write!(f, "ClarityError {}", val),
            Web3Error::TransactionTimeout => write!(f, "Transaction did not enter chain in time"),
            Web3Error::ContractCallError(val) => {
                write!(f, "Error performing Ethereum contract call {}", val)
            }
            Web3Error::CouldNotRemoveFilter(val) => {
                write!(f, "Web3 Failed to remove filter from server {}", val)
            }
            Web3Error::JsonRpcError {
                code,
                message,
                data,
            } => write!(
                f,
                "Web3 Response error code {} message {} data {:?}",
                code, message, data
            ),
        }
    }
}

impl Error for Web3Error {}
