//! A canister that calls the registry canister, for the PocketIC tests of
//! callers that are canisters (SPEC §3.7, Q1 and Q2). It forwards one call
//! with the cycles it is told to attach, and returns the reply or the reject.

use candid::Principal;
use ic_cdk::call::Call;
use serde_bytes::ByteBuf;

#[ic_cdk::update]
async fn forward(
    callee: Principal,
    method: String,
    arg: ByteBuf,
    cycles: u128,
) -> Result<ByteBuf, String> {
    Call::unbounded_wait(callee, &method)
        .with_raw_args(&arg)
        .with_cycles(cycles)
        .await
        .map(|response| ByteBuf::from(response.into_bytes()))
        .map_err(|error| error.to_string())
}
