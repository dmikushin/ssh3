use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh3-keys: cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("ssh3-keys: {path}: cannot parse OpenSSH key: {source}")]
    KeyParse {
        path: PathBuf,
        #[source]
        source: ssh_key::Error,
    },

    #[error(
        "ssh3-keys: {path} is passphrase-protected; passphrase prompts are not yet supported — load the key into ssh-agent instead"
    )]
    EncryptedKey { path: PathBuf },

    #[error("ssh3-keys: unsupported key algorithm {0} (supported: ed25519, ecdsa-sha2-nistp256/384, rsa)")]
    UnsupportedAlgorithm(String),

    #[error("ssh3-keys: cannot convert key to PKCS#8: {0}")]
    Pkcs8(String),

    #[error("ssh3-keys: certificate generation failed: {0}")]
    Cert(#[from] rcgen::Error),

    #[error("ssh3-keys: certificate/SPKI parse failed: {0}")]
    Spki(String),

    #[error("ssh3-keys: {file}:{line}: {msg}")]
    Syntax {
        file: PathBuf,
        line: usize,
        msg: String,
    },

    #[error("ssh3-keys: ssh-agent at {sock}: {msg}")]
    Agent { sock: PathBuf, msg: String },

    #[error("ssh3-keys: SSH_AUTH_SOCK is not set; no ssh-agent to talk to")]
    NoAgent,

    #[error("ssh3-keys: ssh-agent at {sock} does not hold the key from {pub_path} ({fingerprint})")]
    AgentKeyMissing {
        sock: PathBuf,
        pub_path: PathBuf,
        fingerprint: String,
    },

    #[error("ssh3-keys: signing failed: {0}")]
    Sign(String),

    #[error("ssh3-keys: auth signature verification failed: {0}")]
    AuthVerify(String),

    #[error("ssh3-keys: encoding: {0}")]
    Encoding(#[from] ssh_encoding::Error),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
