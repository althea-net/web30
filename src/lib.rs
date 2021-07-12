#![warn(clippy::all)]
#![allow(clippy::pedantic)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod amm;
pub mod client;
mod erc20_utils;
pub mod eth_wrapping;
mod event_utils;
pub mod jsonrpc;
pub mod types;

pub use event_utils::address_to_event;
