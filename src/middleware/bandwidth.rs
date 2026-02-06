use salvo::prelude::*;

/// Bandwidth throttling middleware placeholder.
/// True per-request bandwidth limiting requires a streaming body wrapper.
/// For now this is a no-op middleware that can be extended later.
pub struct BandwidthMiddleware;

#[handler]
impl BandwidthMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        ctrl.call_next(req, depot, res).await;
        // Bandwidth limiting would go here with a streaming body wrapper.
        // Salvo's response model doesn't easily support chunk-paced output
        // like Iron's WriteBody did, so this is left as a TODO for when
        // a streaming response adapter is implemented.
    }
}
