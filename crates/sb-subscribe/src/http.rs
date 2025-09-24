pub async fn fetch_text(url: &str) -> Result<String, crate::model::SubsError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| crate::model::SubsError::Fetch(e.to_string()))?;
    let s = resp
        .text()
        .await
        .map_err(|e| crate::model::SubsError::Fetch(e.to_string()))?;
    Ok(s)
}
