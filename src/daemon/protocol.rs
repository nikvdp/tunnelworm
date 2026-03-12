use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum InputCommand {
    AllocateCode { #[serde(default)] code_length: Option<usize> },
    SetCode { code: String },
    Local { listen: String, connect: String },
    Remote { listen: String, connect: String },
    SessionClose { #[serde(default)] timeout: Option<u64> },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OutputEvent {
    Welcome { welcome: String },
    CodeAllocated { code: String },
    PeerConnected { verifier: String, versions: Value },
    Listening { listen: String, connect: String },
    Error { message: String },
    Closed {},
}
