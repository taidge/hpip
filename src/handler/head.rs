use salvo::prelude::*;

/// HEAD is handled by Salvo automatically when a GET handler is registered.
/// Salvo strips the body for HEAD requests. We register GET handlers and
/// Salvo takes care of HEAD automatically.
///
/// However if we need explicit HEAD handling in the future, we add it here.
#[handler]
pub async fn handle_head(_req: &mut Request, _depot: &mut Depot, _res: &mut Response) {
    // Salvo handles HEAD automatically by running GET and stripping body
}
