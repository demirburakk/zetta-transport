use crate::error::ZtError;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TerminationReason {
    StreamReset { stream_id: u32, error_code: u64 },
    ConnectionClosed { error_code: u64, reason: String },
    IdleTimeout,
}

#[derive(Debug, Default)]
pub(crate) struct Termination {
    reason: Mutex<Option<TerminationReason>>,
}

impl Termination {
    pub(crate) fn set(&self, reason: TerminationReason) {
        let mut current = self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.is_none() {
            *current = Some(reason);
        }
    }

    pub(crate) fn reason(&self) -> Option<TerminationReason> {
        self.reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn error(&self) -> Option<ZtError> {
        self.reason().map(|reason| match reason {
            TerminationReason::StreamReset {
                stream_id,
                error_code,
            } => ZtError::StreamReset {
                stream_id,
                error_code,
            },
            TerminationReason::ConnectionClosed { error_code, reason } => {
                ZtError::ConnectionClosedByPeer { error_code, reason }
            }
            TerminationReason::IdleTimeout => ZtError::IdleTimeout,
        })
    }

    pub(crate) fn io_error(&self) -> Option<std::io::Error> {
        self.error().map(|error| {
            let kind = if matches!(error, ZtError::IdleTimeout) {
                std::io::ErrorKind::TimedOut
            } else {
                std::io::ErrorKind::ConnectionAborted
            };
            std::io::Error::new(kind, error)
        })
    }
}
