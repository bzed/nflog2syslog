//! nflog2syslog library: NFLOG -> dissection -> JSON -> syslog.
//!
//! Pipeline (see PLAN.md):
//!
//! netlink recv thread -> [bounded q1] -> dissect/format worker
//!                                          -> [bounded q2] -> sink thread
//!
//! Every queue is bounded and fed with try_send, so a slow syslog
//! collector causes counted drops instead of a stalled kernel socket.

pub mod cli;
pub mod dissect;
pub mod format;
pub mod receiver;
pub mod sinks;
pub mod stats;
pub mod wire;
