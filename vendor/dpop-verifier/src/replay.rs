use crate::DpopError;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct ReplayContext<'a> {
    pub jkt: Option<&'a str>,
    pub htm: Option<&'a str>,
    pub htu: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub iat: i64,
}

/// Implement this in your app for DB/Redis/etc.
/// Return Ok(true) if this jti was inserted the first time; Ok(false) if already present (replay).
#[async_trait]
pub trait ReplayStore {
    async fn insert_once(
        &mut self,
        jti_hash: [u8; 32],
        ctx: ReplayContext<'_>,
    ) -> Result<bool, DpopError>;
}
