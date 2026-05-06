//! Ctrl-C / SIGTERM flip a shared flag that all runtime tasks observe,
//! allowing them to detach interfaces and flush state cleanly before exit.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

#[derive(Clone)]
pub struct ShutdownSignal {
    flag: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn trigger(&self) {
        if !self.flag.swap(true, Ordering::SeqCst) {
            tracing::debug!("shutdown triggered, notifying waiters");
        }
        self.notify.notify_waiters();
    }

    pub fn is_triggered(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub async fn wait(&self) {
        if self.is_triggered() {
            return;
        }
        self.notify.notified().await;
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ExitHandler {
    actions: Vec<Box<dyn FnOnce() + Send>>,
}

impl ExitHandler {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }

    pub fn register(&mut self, action: impl FnOnce() + Send + 'static) {
        self.actions.push(Box::new(action));
    }

    pub fn execute(self) {
        let n = self.actions.len();
        tracing::debug!(actions = n, "running exit handlers");
        for action in self.actions {
            action();
        }
    }
}

impl Default for ExitHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Install Ctrl-C / SIGTERM handlers that trip `shutdown`. Returned receiver
/// yields once on signal for await-based callers.
pub fn install_signal_handlers(shutdown: ShutdownSignal) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel(1);

    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        ctrl_c.await.ok();
        tracing::info!("received shutdown signal");
        shutdown_clone.trigger();
        let _ = tx.send(()).await;
    });

    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_signal() {
        let signal = ShutdownSignal::new();
        assert!(!signal.is_triggered());
        signal.trigger();
        assert!(signal.is_triggered());
    }

    #[test]
    fn test_shutdown_signal_clone() {
        let signal = ShutdownSignal::new();
        let clone = signal.clone();
        signal.trigger();
        assert!(clone.is_triggered());
    }

    #[test]
    fn test_exit_handler() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let counter = Arc::new(AtomicU32::new(0));

        let mut handler = ExitHandler::new();
        let c1 = counter.clone();
        handler.register(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        });
        let c2 = counter.clone();
        handler.register(move || {
            c2.fetch_add(10, Ordering::SeqCst);
        });

        handler.execute();
        assert_eq!(counter.load(Ordering::SeqCst), 11);
    }

    #[tokio::test]
    async fn test_shutdown_wait() {
        let signal = ShutdownSignal::new();
        let signal_clone = signal.clone();

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            signal_clone.trigger();
        });

        signal.wait().await;
        assert!(signal.is_triggered());
    }
}
