#![warn(clippy::all)]
#![allow(clippy::pedantic)]

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate clarity;
extern crate futures;
extern crate num256;
#[macro_use]
extern crate failure;
extern crate actix_web;
extern crate futures_timer;
extern crate tokio;
#[macro_use]
extern crate log;
extern crate bytes;
#[cfg(test)]
#[macro_use]
extern crate assert_json_diff;

pub mod client;
pub mod jsonrpc;
pub mod types;
