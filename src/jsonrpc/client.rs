use crate::jsonrpc::error::Web3Error;
use crate::jsonrpc::request::Request as JsonRpcRequest;
use crate::jsonrpc::response::Response as JsonResponse;
use crate::mem::get_buffer_size;
use hyper::body::{Bytes, HttpBody};
use hyper::client::HttpConnector;
use hyper::{header, Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;

pub struct HttpClient {
    id_counter: Arc<Mutex<RefCell<u64>>>,
    url: String,
    client: Client<HttpsConnector<HttpConnector>>,
}

impl HttpClient {
    pub fn new(url: &str) -> Self {
        let https = HttpsConnector::new();

        Self {
            id_counter: Arc::new(Mutex::new(RefCell::new(0u64))),
            url: url.into(),
            client: Client::builder().build(https),
        }
    }

    fn next_id(&self) -> u64 {
        let counter = self.id_counter.clone();
        let counter = counter.lock().expect("id error");
        let mut value = counter.borrow_mut();
        *value += 1;
        *value
    }

    async fn aggregate_bytes(&self, request: Request<Body>) -> Result<Bytes, Web3Error> {
        let request_size_limit = get_buffer_size();
        let res = self.client.request(request).await?;

        trace!("response headers {:?}", res.headers());
        trace!("using buffer size of {}", request_size_limit);

        let response_size = res.size_hint().lower() as usize;

        if response_size > request_size_limit {
            return Err(Web3Error::BadResponse(format!(
                "Size Limit {} and Response size {} Web3 Error",
                request_size_limit, response_size
            )));
        }

        hyper::body::to_bytes(res.into_body())
            .await
            .map_err(Into::into)
    }

    pub async fn request_method<T: Serialize, R: 'static>(
        &self,
        method: &str,
        params: T,
        timeout: Duration,
    ) -> Result<R, Web3Error>
    where
        for<'de> R: Deserialize<'de>,
        R: std::fmt::Debug,
    {
        let payload = JsonRpcRequest::new(self.next_id(), method, params);
        let payload = serde_json::to_vec(&payload)?;

        let req = Request::builder()
            .method(Method::POST)
            .header(header::CONTENT_TYPE, "application/json")
            .uri(&self.url)
            .body(payload.into())
            .expect("expected really body");

        // race between the Timeout and the Request - with slight bias towards the request itself
        let result: Result<Bytes, Web3Error> = tokio::select! {
            biased;

            bytes = self.aggregate_bytes(req) => Ok(bytes?),
            _ = time::sleep(timeout) => Err(Web3Error::BadResponse("Request Timed Out".into()))
        };

        let data: JsonResponse<R> = serde_json::from_slice(&result?)?;
        trace!("got web3 response {:#?}", data);

        Ok(data.result)
    }
}
