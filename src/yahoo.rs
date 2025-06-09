use yahoo_finance_api as yahoo;

pub async fn fetch_stock_quotes(symbol: &str) -> Result<yahoo::YResponse, yahoo::YahooError> {
    let provider = yahoo::YahooConnector::new().unwrap();

    provider.get_latest_quotes(symbol, "1d").await
}
