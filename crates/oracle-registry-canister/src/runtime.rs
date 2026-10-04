//! The canister's runtime context: the state cell, the clock and the caller.

use std::cell::RefCell;

use crate::state::State;

thread_local! {
    pub(crate) static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

pub(crate) fn now_secs() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
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

pub(crate) fn is_governance() -> bool {
    ic_cdk::api::is_controller(&ic_cdk::api::msg_caller())
}

/// The guard on every update method. The anonymous principal is never a controller.
pub(crate) fn governance_only() -> Result<(), String> {
    if is_governance() {
        Ok(())
    } else {
        Err("only governance (a canister controller) may do this".to_owned())
    }
}
