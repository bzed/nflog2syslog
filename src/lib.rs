// Copyright 2026 Bernd Zeimetz <bernd@bzed.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
pub mod metrics;
pub mod receiver;
pub mod sinks;
pub mod stats;
pub mod wire;
