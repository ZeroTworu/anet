use super::colibri::ColibriMessage;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

pub struct WrtcChannel {
    pub endpoint_id: String,
    tx: mpsc::Sender<ColibriMessage>,
    rx: Arc<Mutex<mpsc::Receiver<ColibriMessage>>>,
}

impl Clone for WrtcChannel {
    fn clone(&self) -> Self {
        Self {
            endpoint_id: self.endpoint_id.clone(),
            tx: self.tx.clone(),
            rx: Arc::clone(&self.rx),
        }
    }
}

impl WrtcChannel {
    pub fn new(
        endpoint_id: String,
        tx: mpsc::Sender<ColibriMessage>,
        rx: mpsc::Receiver<ColibriMessage>,
    ) -> Self {
        Self {
            endpoint_id,
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Send a Colibri message over the DataChannel.
    pub async fn send(&self, msg: ColibriMessage) -> anyhow::Result<()> {
        self.tx
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("DataChannel send channel closed"))
    }

    /// Receive the next incoming Colibri message.
    pub async fn recv(&self) -> Option<ColibriMessage> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }
}
