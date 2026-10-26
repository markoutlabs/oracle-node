//! The canister's runtime context: the state and price cells, the clock, the
//! caller, and the address arguments.

use std::cell::RefCell;

use oracle_wire::Address;

use crate::prices::Prices;
use crate::state::State;

thread_local! {
    pub(crate) static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    // Not in `STATE`: a signing round writes back a copy of `STATE` after an
    // await, which would drop the pushes accepted during it.
    pub(crate) static PRICES: RefCell<Prices> = RefCell::new(Prices::default());
}

pub(crate) fn now_secs() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
}

pub(crate) fn now_ns() -> u64 {
    ic_cdk::api::time()
}

pub(crate) fn with_prices<R>(f: impl FnOnce(&mut Prices) -> R) -> R {
    PRICES.with(|cell| f(&mut cell.borrow_mut()))
}

pub(crate) fn read_prices<R>(f: impl FnOnce(&Prices) -> R) -> R {
    PRICES.with(|cell| f(&cell.borrow()))
}

/// Gives the price checks the registry that was just published.
pub(crate) fn adopt_registry() {
    if let Some(registry) = read_state(State::verified_registry) {
        with_prices(|prices| prices.set_registry(registry));
    }
}

pub(crate) fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| {
        f(cell
            .borrow_mut()
            .as_mut()
            .expect("the canister is initialised"))
    })
}

pub(crate) fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow().as_ref().expect("the canister is initialised")))
}

pub(crate) fn address(text: &str) -> Result<Address, String> {
    text.parse()
        .map_err(|error| format!("address `{text}`: {error}"))
}

pub(crate) fn is_governance() -> bool {
    ic_cdk::api::is_controller(&ic_cdk::api::msg_caller())
}

/// The guard on every update method but `push`. The anonymous principal is
/// never a controller.
pub(crate) fn governance_only() -> Result<(), String> {
    if is_governance() {
        Ok(())
    } else {
        Err("only governance (a canister controller) may do this".to_owned())
    }
}

/// The guard on `push`. Ingress from the anonymous identity always passes
/// `inspect_message`, and a canister's call never has that caller.
pub(crate) fn anonymous_only() -> Result<(), String> {
    if ic_cdk::api::msg_caller() == candid::Principal::anonymous() {
        Ok(())
    } else {
        Err("push takes ingress from the anonymous identity only".to_owned())
    }
}
