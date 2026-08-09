use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

pub trait ProtocolRunner: Send + Sync {
    fn name(&self) -> &'static str;
    fn start(&self) -> BoxFuture<'_>;
}

pub struct ProtocolRegistry {
    runners: Vec<Box<dyn ProtocolRunner>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            runners: Vec::new(),
        }
    }

    pub fn register(mut self, runner: impl ProtocolRunner + 'static) -> Self {
        self.runners.push(Box::new(runner));
        self
    }

    pub async fn run_all(self) -> Result<()> {
        let mut handles = Vec::new();
        for runner in self.runners {
            let name = runner.name();
            handles.push(tokio::spawn(async move {
                runner.start().await.map_err(|err| {
                    tracing::error!(protocol = name, error = %err, "protocol runner failed");
                    err
                })
            }));
        }

        for handle in handles {
            handle.await??;
        }

        Ok(())
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
