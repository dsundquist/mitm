use async_trait::async_trait;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;

pub struct Mitm;

#[async_trait]
impl ProxyHttp for Mitm {
    /// For this small example, we don't need context storage
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
        // println!("upstream peer is: {self.upstream:?}");

        // Set SNI to blank, which ignores any SNI checks for the Certificate?
        let peer = Box::new(HttpPeer::new(
            "127.0.0.1:443",
            true,
            "localhost".to_string(),
        ));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request
            .insert_header("Host", "one.one.one.one")
            .unwrap();
        Ok(())
    }
}
