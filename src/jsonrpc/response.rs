use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response<R> {
    pub id: Value,
    pub jsonrpc: String,
    pub result: R,
}

#[test]
fn test_response() {
    let response: Response<u64> =
        serde_json::from_str(r#"{"jsonrpc": "2.0", "result": 19, "id": 1}"#).unwrap();
    assert_eq!(response.id.as_u64().unwrap(), 1);
    assert_eq!(response.result, 19)
}
