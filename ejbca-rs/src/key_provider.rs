use std::{
    io::{Read, Write},
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration as StdDuration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use rcgen::{KeyPair, PublicKeyData, SigningKey, SubjectPublicKeyInfo};
use ring::{aead, pbkdf2};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::error;
use uuid::Uuid;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroize;

use crate::{
    config::Settings,
    error::{AppError, AppResult},
    storage::CaRecord,
};

const FILE_PREFIX: &str = "file:";
const COMMAND_PREFIX: &str = "command:";
const ENCRYPTED_PREFIX: &str = "encrypted:";
const CA_KEY_ENCRYPTION_ENV: &str = "EJBCA_RS_CA_KEY_ENCRYPTION_SECRET";
const CA_KEY_ENCRYPTION_KDF_ITERATIONS: u32 = 210_000;
const CA_KEY_ENCRYPTION_AAD: &[u8] = b"ejbca-rs-ca-key-v1";
const COMMAND_SIGNER_DEFAULT_TIMEOUT_MS: u64 = 10_000;
const COMMAND_SIGNER_MAX_TIMEOUT_MS: u64 = 60_000;
const COMMAND_SIGNER_DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024;
const COMMAND_SIGNER_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const COMMAND_SIGNER_STDERR_LOG_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaKeyProviderKind {
    Database,
    File,
    Command,
}

impl CaKeyProviderKind {
    pub fn parse(value: &str) -> AppResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "db" | "database" | "local-db" => Ok(Self::Database),
            "file" | "filesystem" | "fs" => Ok(Self::File),
            "command" | "external-command" | "external" => Ok(Self::Command),
            other => Err(AppError::BadRequest(format!(
                "지원하지 않는 CA key provider입니다: {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandSignerConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedKeyRef {
    version: u8,
    algorithm: String,
    kdf: String,
    iterations: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub enum CaSigningKey {
    Local(KeyPair),
    Command(CommandSigningKey),
}

#[derive(Clone, Debug)]
pub struct CommandSigningKey {
    public_key: SubjectPublicKeyInfo,
    config: CommandSignerConfig,
}

impl PublicKeyData for CaSigningKey {
    fn der_bytes(&self) -> &[u8] {
        match self {
            Self::Local(key_pair) => key_pair.der_bytes(),
            Self::Command(key) => key.der_bytes(),
        }
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            Self::Local(key_pair) => key_pair.algorithm(),
            Self::Command(key) => key.algorithm(),
        }
    }
}

impl SigningKey for CaSigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        match self {
            Self::Local(key_pair) => key_pair.sign(msg),
            Self::Command(key) => key.sign(msg),
        }
    }
}

impl PublicKeyData for CommandSigningKey {
    fn der_bytes(&self) -> &[u8] {
        self.public_key.der_bytes()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.public_key.algorithm()
    }
}

impl SigningKey for CommandSigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        sign_with_command(&self.config, msg, self.algorithm())
    }
}

pub async fn persist_new_ca_key(
    settings: &Settings,
    ca_id: &str,
    key_pair: &KeyPair,
) -> AppResult<String> {
    match CaKeyProviderKind::parse(&settings.ca_key_provider)? {
        CaKeyProviderKind::Database => {
            let pem = key_pair.serialize_pem();
            if ca_key_encryption_enabled() {
                encrypted_key_ref_from_pem(&pem)
            } else {
                Ok(pem)
            }
        }
        CaKeyProviderKind::File => {
            let key_dir = ca_key_dir(settings);
            fs::create_dir_all(&key_dir).await.map_err(|err| {
                AppError::Internal(format!("CA key 디렉터리를 만들 수 없습니다: {err}"))
            })?;
            let path = key_dir.join(format!("{ca_id}.pem"));
            write_private_key_file(&path, key_pair.serialize_pem()).await?;
            Ok(format!("{FILE_PREFIX}{}", path.display()))
        }
        CaKeyProviderKind::Command => Err(AppError::BadRequest(
            "command key provider는 기존 외부 CA 인증서를 import 할 때 사용합니다".to_string(),
        )),
    }
}

pub async fn load_ca_signing_key(ca: &CaRecord) -> AppResult<CaSigningKey> {
    if ca.key_pem.starts_with(COMMAND_PREFIX) {
        return Ok(CaSigningKey::Command(command_signing_key(ca)?));
    }
    Ok(CaSigningKey::Local(load_ca_key_pair(&ca.key_pem).await?))
}

pub async fn load_ca_key_pair(key_ref: &str) -> AppResult<KeyPair> {
    let material = if let Some(path) = key_ref.strip_prefix(FILE_PREFIX) {
        fs::read_to_string(path).await.map_err(|err| {
            AppError::Internal(format!("CA key 파일을 읽을 수 없습니다: {path}: {err}"))
        })?
    } else {
        key_ref.to_string()
    };
    let pem = if material.starts_with(ENCRYPTED_PREFIX) {
        decrypt_private_key_ref(&material)?
    } else {
        material
    };
    KeyPair::from_pem(&pem).map_err(AppError::from)
}

pub fn provider_label(key_ref: &str) -> &'static str {
    if key_ref.starts_with(FILE_PREFIX) {
        "file"
    } else if key_ref.starts_with(COMMAND_PREFIX) {
        "command"
    } else if key_ref.starts_with(ENCRYPTED_PREFIX) {
        "database-encrypted"
    } else {
        "database"
    }
}

pub fn encrypted_key_ref_from_pem(pem: &str) -> AppResult<String> {
    KeyPair::from_pem(pem).map_err(AppError::from)?;
    let mut secret = ca_key_encryption_secret_required()?;
    let result = encrypt_private_key_pem_with_secret(pem, secret.as_bytes());
    secret.zeroize();
    result
}

pub fn command_key_ref(config: &CommandSignerConfig) -> AppResult<String> {
    if config.command.trim().is_empty() {
        return Err(AppError::BadRequest(
            "command signer 명령은 비어 있을 수 없습니다".to_string(),
        ));
    }
    let json = serde_json::to_vec(config)
        .map_err(|err| AppError::Internal(format!("command signer 설정 직렬화 실패: {err}")))?;
    Ok(format!("{COMMAND_PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

pub fn validate_key_ref(key_ref: &str) -> AppResult<()> {
    if key_ref.starts_with(COMMAND_PREFIX) {
        parse_command_key_ref(key_ref)?;
    } else if key_ref.starts_with(ENCRYPTED_PREFIX) {
        let pem = decrypt_private_key_ref(key_ref)?;
        KeyPair::from_pem(&pem).map_err(AppError::from)?;
    }
    Ok(())
}

fn command_signing_key(ca: &CaRecord) -> AppResult<CommandSigningKey> {
    let config = parse_command_key_ref(&ca.key_pem)?;
    let spki = ca_subject_public_key_info(ca)?;
    Ok(CommandSigningKey {
        public_key: spki,
        config,
    })
}

fn parse_command_key_ref(key_ref: &str) -> AppResult<CommandSignerConfig> {
    let encoded = key_ref
        .strip_prefix(COMMAND_PREFIX)
        .ok_or_else(|| AppError::BadRequest("command key reference 형식이 아닙니다".to_string()))?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|err| {
        AppError::BadRequest(format!("command key reference base64 디코딩 실패: {err}"))
    })?;
    let config: CommandSignerConfig = serde_json::from_slice(&bytes).map_err(|err| {
        AppError::BadRequest(format!("command key reference JSON 파싱 실패: {err}"))
    })?;
    if config.command.trim().is_empty() {
        return Err(AppError::BadRequest(
            "command signer 명령은 비어 있을 수 없습니다".to_string(),
        ));
    }
    Ok(config)
}

fn ca_key_encryption_enabled() -> bool {
    crate::config::configured_ca_key_encryption_secret()
        .or_else(|| std::env::var(CA_KEY_ENCRYPTION_ENV).ok())
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

fn ca_key_encryption_secret_required() -> AppResult<String> {
    let secret = crate::config::configured_ca_key_encryption_secret()
        .or_else(|| std::env::var(CA_KEY_ENCRYPTION_ENV).ok())
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "암호화된 CA key를 사용하려면 ca_key_encryption_secret 설정 또는 {CA_KEY_ENCRYPTION_ENV} 환경변수가 필요합니다"
            ))
        })?;
    if secret.is_empty() {
        return Err(AppError::BadRequest(
            "ca_key_encryption_secret 설정이 비어 있습니다".to_string(),
        ));
    }
    Ok(secret)
}

fn encrypt_private_key_pem_with_secret(pem: &str, secret: &[u8]) -> AppResult<String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key_bytes = derive_ca_key_encryption_key(secret, &salt)?;
    let key = aead_key(&key_bytes)?;
    let mut ciphertext = pem.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(CA_KEY_ENCRYPTION_AAD),
        &mut ciphertext,
    )
    .map_err(|_| AppError::Internal("CA private key 암호화 실패".to_string()))?;
    key_bytes.zeroize();

    let envelope = EncryptedKeyRef {
        version: 1,
        algorithm: "AES-256-GCM".to_string(),
        kdf: "PBKDF2-HMAC-SHA256".to_string(),
        iterations: CA_KEY_ENCRYPTION_KDF_ITERATIONS,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    let json = serde_json::to_vec(&envelope).map_err(|err| {
        AppError::Internal(format!("암호화된 CA key envelope 직렬화 실패: {err}"))
    })?;
    Ok(format!(
        "{ENCRYPTED_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(json)
    ))
}

fn decrypt_private_key_ref(key_ref: &str) -> AppResult<String> {
    let mut secret = ca_key_encryption_secret_required()?;
    let result = decrypt_private_key_ref_with_secret(key_ref, secret.as_bytes());
    secret.zeroize();
    result
}

fn decrypt_private_key_ref_with_secret(key_ref: &str, secret: &[u8]) -> AppResult<String> {
    let envelope = parse_encrypted_key_ref(key_ref)?;
    if envelope.version != 1
        || envelope.algorithm != "AES-256-GCM"
        || envelope.kdf != "PBKDF2-HMAC-SHA256"
    {
        return Err(AppError::BadRequest(
            "지원하지 않는 암호화 CA key envelope입니다".to_string(),
        ));
    }
    let salt = decode_envelope_bytes("salt", &envelope.salt)?;
    let nonce = decode_envelope_bytes("nonce", &envelope.nonce)?;
    if nonce.len() != 12 {
        return Err(AppError::BadRequest(
            "암호화 CA key nonce 길이가 올바르지 않습니다".to_string(),
        ));
    }
    let mut ciphertext = decode_envelope_bytes("ciphertext", &envelope.ciphertext)?;
    let mut key_bytes = derive_ca_key_encryption_key_with_iterations(
        secret,
        &salt,
        envelope.iterations.clamp(100_000, 2_000_000),
    )?;
    let key = aead_key(&key_bytes)?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce);
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce_bytes),
            aead::Aad::from(CA_KEY_ENCRYPTION_AAD),
            &mut ciphertext,
        )
        .map_err(|_| AppError::BadRequest("암호화 CA key 복호화 실패".to_string()))?;
    let pem = String::from_utf8(plaintext.to_vec())
        .map_err(|_| AppError::BadRequest("복호화된 CA key가 UTF-8 PEM이 아닙니다".to_string()))?;
    key_bytes.zeroize();
    ciphertext.zeroize();
    Ok(pem)
}

fn parse_encrypted_key_ref(key_ref: &str) -> AppResult<EncryptedKeyRef> {
    let encoded = key_ref.strip_prefix(ENCRYPTED_PREFIX).ok_or_else(|| {
        AppError::BadRequest("encrypted key reference 형식이 아닙니다".to_string())
    })?;
    let json = URL_SAFE_NO_PAD.decode(encoded).map_err(|err| {
        AppError::BadRequest(format!("encrypted key reference base64 디코딩 실패: {err}"))
    })?;
    serde_json::from_slice(&json).map_err(|err| {
        AppError::BadRequest(format!("encrypted key reference JSON 파싱 실패: {err}"))
    })
}

fn decode_envelope_bytes(label: &str, value: &str) -> AppResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|err| AppError::BadRequest(format!("암호화 CA key {label} 디코딩 실패: {err}")))
}

fn derive_ca_key_encryption_key(secret: &[u8], salt: &[u8]) -> AppResult<[u8; 32]> {
    derive_ca_key_encryption_key_with_iterations(secret, salt, CA_KEY_ENCRYPTION_KDF_ITERATIONS)
}

fn derive_ca_key_encryption_key_with_iterations(
    secret: &[u8],
    salt: &[u8],
    iterations: u32,
) -> AppResult<[u8; 32]> {
    let iterations = NonZeroU32::new(iterations).ok_or_else(|| {
        AppError::BadRequest("CA key 암호화 KDF iteration은 1 이상이어야 합니다".to_string())
    })?;
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        secret,
        &mut key,
    );
    Ok(key)
}

fn aead_key(key_bytes: &[u8; 32]) -> AppResult<aead::LessSafeKey> {
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
        .map_err(|_| AppError::Internal("CA key 암호화 키 초기화 실패".to_string()))?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn ca_subject_public_key_info(ca: &CaRecord) -> AppResult<SubjectPublicKeyInfo> {
    let (_, cert) = X509Certificate::from_der(&ca.cert_der)
        .map_err(|err| AppError::BadRequest(format!("CA 인증서 DER 파싱 실패: {err}")))?;
    SubjectPublicKeyInfo::from_der(cert.tbs_certificate.subject_pki.raw)
        .map_err(|err| AppError::BadRequest(format!("CA SubjectPublicKeyInfo 파싱 실패: {err}")))
}

fn sign_with_command(
    config: &CommandSignerConfig,
    msg: &[u8],
    algorithm: &rcgen::SignatureAlgorithm,
) -> Result<Vec<u8>, rcgen::Error> {
    let temp_id = Uuid::new_v4();
    let input_path = std::env::temp_dir().join(format!("ejbca-rs-sign-{temp_id}.tbs"));
    let output_path = std::env::temp_dir().join(format!("ejbca-rs-sign-{temp_id}.sig"));
    let algorithm_name = format!("{algorithm:?}");

    let uses_input_file = config.args.iter().any(|arg| arg.contains("{input}"));
    let uses_output_file = config.args.iter().any(|arg| arg.contains("{output}"));
    let timeout = command_signer_timeout(config);
    let max_output_bytes = command_signer_max_output_bytes(config);
    let args = config
        .args
        .iter()
        .map(|arg| {
            arg.replace("{input}", &input_path.to_string_lossy())
                .replace("{output}", &output_path.to_string_lossy())
                .replace("{algorithm}", &algorithm_name)
        })
        .collect::<Vec<_>>();

    if uses_input_file && let Err(err) = std::fs::write(&input_path, msg) {
        error!("command signer 입력 파일 생성 실패: {err}");
        return Err(rcgen::Error::RemoteKeyError);
    }

    let mut command = Command::new(&config.command);
    command
        .args(&args)
        .stdin(if uses_input_file {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(if uses_output_file {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            error!("command signer 실행 실패: {err}");
            cleanup_command_files(&input_path, &output_path);
            return Err(rcgen::Error::RemoteKeyError);
        }
    };

    if !uses_input_file
        && let Some(stdin) = child.stdin.as_mut()
        && let Err(err) = stdin.write_all(msg)
    {
        error!("command signer stdin 쓰기 실패: {err}");
        kill_child(&mut child);
        cleanup_command_files(&input_path, &output_path);
        return Err(rcgen::Error::RemoteKeyError);
    }
    drop(child.stdin.take());

    let stdout_reader = if uses_output_file {
        None
    } else {
        child
            .stdout
            .take()
            .map(|stdout| read_limited_stream(stdout, max_output_bytes))
    };
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| read_limited_stream(stderr, COMMAND_SIGNER_STDERR_LOG_BYTES));

    let status = match wait_with_timeout(&mut child, timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            error!(
                timeout_ms = timeout.as_millis() as u64,
                "command signer timeout으로 프로세스를 종료했습니다"
            );
            kill_child(&mut child);
            join_reader(stdout_reader, "stdout");
            join_reader(stderr_reader, "stderr");
            cleanup_command_files(&input_path, &output_path);
            return Err(rcgen::Error::RemoteKeyError);
        }
        Err(err) => {
            error!("command signer 완료 대기 실패: {err}");
            kill_child(&mut child);
            join_reader(stdout_reader, "stdout");
            join_reader(stderr_reader, "stderr");
            cleanup_command_files(&input_path, &output_path);
            return Err(rcgen::Error::RemoteKeyError);
        }
    };

    let stdout = match join_reader(stdout_reader, "stdout") {
        Some(Ok(captured)) => captured,
        Some(Err(())) => {
            cleanup_command_files(&input_path, &output_path);
            return Err(rcgen::Error::RemoteKeyError);
        }
        None => CapturedOutput::default(),
    };
    let stderr = match join_reader(stderr_reader, "stderr") {
        Some(Ok(captured)) => captured,
        Some(Err(())) => {
            cleanup_command_files(&input_path, &output_path);
            return Err(rcgen::Error::RemoteKeyError);
        }
        None => CapturedOutput::default(),
    };

    if !status.success() {
        error!(
            status = ?status,
            stderr = %captured_text(&stderr),
            "command signer가 실패했습니다"
        );
        cleanup_command_files(&input_path, &output_path);
        return Err(rcgen::Error::RemoteKeyError);
    }

    let signature = if uses_output_file {
        match read_signature_file(&output_path, max_output_bytes) {
            Ok(signature) => signature,
            Err(()) => {
                cleanup_command_files(&input_path, &output_path);
                return Err(rcgen::Error::RemoteKeyError);
            }
        }
    } else {
        if stdout.total_bytes > max_output_bytes {
            error!(
                max_output_bytes,
                actual_bytes = stdout.total_bytes,
                "command signer stdout 서명이 허용 크기를 초과했습니다"
            );
            cleanup_command_files(&input_path, &output_path);
            return Err(rcgen::Error::RemoteKeyError);
        }
        stdout.bytes
    };
    cleanup_command_files(&input_path, &output_path);

    if signature.is_empty() {
        error!("command signer가 빈 서명을 반환했습니다");
        return Err(rcgen::Error::RemoteKeyError);
    }
    Ok(signature)
}

#[derive(Default)]
struct CapturedOutput {
    bytes: Vec<u8>,
    total_bytes: usize,
}

fn command_signer_timeout(config: &CommandSignerConfig) -> StdDuration {
    let millis = config
        .timeout_ms
        .unwrap_or(COMMAND_SIGNER_DEFAULT_TIMEOUT_MS)
        .clamp(1, COMMAND_SIGNER_MAX_TIMEOUT_MS);
    StdDuration::from_millis(millis)
}

fn command_signer_max_output_bytes(config: &CommandSignerConfig) -> usize {
    config
        .max_output_bytes
        .unwrap_or(COMMAND_SIGNER_DEFAULT_MAX_OUTPUT_BYTES)
        .clamp(1, COMMAND_SIGNER_MAX_OUTPUT_BYTES)
}

fn read_limited_stream<R>(
    mut reader: R,
    store_limit: usize,
) -> thread::JoinHandle<std::io::Result<CapturedOutput>>
where
    R: Read + Send + 'static,
{
    // signer가 큰 출력을 내도 pipe는 계속 비우고, 메모리에 보관하는 바이트만 제한한다.
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(store_limit.min(8192));
        let mut total_bytes = 0usize;
        let mut buffer = [0u8; 8192];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total_bytes = total_bytes.saturating_add(count);
            let remaining = store_limit.saturating_sub(bytes.len());
            if remaining > 0 {
                bytes.extend_from_slice(&buffer[..count.min(remaining)]);
            }
        }
        Ok(CapturedOutput { bytes, total_bytes })
    })
}

fn wait_with_timeout(
    child: &mut Child,
    timeout: StdDuration,
) -> std::io::Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(None);
        }
        thread::sleep((timeout - elapsed).min(StdDuration::from_millis(10)));
    }
}

fn join_reader(
    reader: Option<thread::JoinHandle<std::io::Result<CapturedOutput>>>,
    stream_name: &str,
) -> Option<Result<CapturedOutput, ()>> {
    let reader = reader?;
    Some(match reader.join() {
        Ok(Ok(captured)) => Ok(captured),
        Ok(Err(err)) => {
            error!("command signer {stream_name} 읽기 실패: {err}");
            Err(())
        }
        Err(_) => {
            error!("command signer {stream_name} reader thread panic");
            Err(())
        }
    })
}

fn read_signature_file(path: &Path, max_output_bytes: usize) -> Result<Vec<u8>, ()> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        error!("command signer output 파일 metadata 읽기 실패: {err}");
    })?;
    if metadata.len() > max_output_bytes as u64 {
        error!(
            max_output_bytes,
            actual_bytes = metadata.len(),
            "command signer output 파일이 허용 크기를 초과했습니다"
        );
        return Err(());
    }
    std::fs::read(path).map_err(|err| {
        error!("command signer output 파일 읽기 실패: {err}");
    })
}

fn captured_text(output: &CapturedOutput) -> String {
    let mut text = String::from_utf8_lossy(&output.bytes).to_string();
    if output.total_bytes > output.bytes.len() {
        text.push_str(&format!(
            "... <truncated {} bytes>",
            output.total_bytes - output.bytes.len()
        ));
    }
    text
}

fn kill_child(child: &mut Child) {
    #[cfg(unix)]
    terminate_process_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_process_group(pid: u32) {
    let group = format!("-{pid}");
    let _ = Command::new("kill").args(["-TERM", "--", &group]).status();
    thread::sleep(StdDuration::from_millis(50));
    let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
}

fn cleanup_command_files(input_path: &Path, output_path: &Path) {
    let _ = std::fs::remove_file(input_path);
    let _ = std::fs::remove_file(output_path);
}

fn ca_key_dir(settings: &Settings) -> PathBuf {
    settings
        .ca_key_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&settings.data_dir).join("keys"))
}

async fn write_private_key_file(path: &Path, pem: String) -> AppResult<()> {
    #[cfg(unix)]
    {
        use tokio::io::AsyncWriteExt;

        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .await
            .map_err(|err| {
                AppError::Internal(format!(
                    "CA private key 파일을 만들 수 없습니다: {}: {err}",
                    path.display()
                ))
            })?;
        file.write_all(pem.as_bytes()).await.map_err(|err| {
            AppError::Internal(format!(
                "CA private key 파일에 쓸 수 없습니다: {}: {err}",
                path.display()
            ))
        })?;
        file.flush().await.map_err(|err| {
            AppError::Internal(format!(
                "CA private key 파일 flush 실패: {}: {err}",
                path.display()
            ))
        })?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, pem).await.map_err(|err| {
            AppError::Internal(format!(
                "CA private key 파일을 쓸 수 없습니다: {}: {err}",
                path.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::time::{Duration as TestDuration, Instant as TestInstant};

    #[test]
    fn parses_provider_aliases() {
        assert_eq!(
            CaKeyProviderKind::parse("database").unwrap(),
            CaKeyProviderKind::Database
        );
        assert_eq!(
            CaKeyProviderKind::parse("fs").unwrap(),
            CaKeyProviderKind::File
        );
        assert_eq!(
            CaKeyProviderKind::parse("external-command").unwrap(),
            CaKeyProviderKind::Command
        );
    }

    #[test]
    fn infers_provider_label_from_reference() {
        assert_eq!(provider_label("-----BEGIN PRIVATE KEY-----"), "database");
        assert_eq!(provider_label("file:/secure/ca.pem"), "file");
        assert_eq!(provider_label("command:abc"), "command");
        assert_eq!(provider_label("encrypted:abc"), "database-encrypted");
    }

    #[test]
    fn encodes_and_decodes_command_key_ref() {
        let config = CommandSignerConfig {
            command: "/usr/local/bin/kms-sign".to_string(),
            args: vec!["--key".to_string(), "ca".to_string()],
            timeout_ms: Some(5000),
            max_output_bytes: Some(8192),
        };
        let reference = command_key_ref(&config).unwrap();
        let parsed = parse_command_key_ref(&reference).unwrap();
        assert_eq!(parsed.command, config.command);
        assert_eq!(parsed.args, config.args);
        assert_eq!(parsed.timeout_ms, config.timeout_ms);
        assert_eq!(parsed.max_output_bytes, config.max_output_bytes);
    }

    #[test]
    fn encrypts_and_decrypts_private_key_reference() {
        let key_pair = KeyPair::generate().unwrap();
        let pem = key_pair.serialize_pem();
        let reference = encrypt_private_key_pem_with_secret(&pem, b"test-secret").unwrap();

        assert!(reference.starts_with(ENCRYPTED_PREFIX));
        assert!(!reference.contains("BEGIN PRIVATE KEY"));

        let decrypted = decrypt_private_key_ref_with_secret(&reference, b"test-secret").unwrap();
        let parsed = KeyPair::from_pem(&decrypted).unwrap();
        assert_eq!(parsed.der_bytes(), key_pair.der_bytes());
        assert!(decrypt_private_key_ref_with_secret(&reference, b"wrong-secret").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn command_signer_accepts_small_stdout_signature() {
        let key_pair = KeyPair::generate().unwrap();
        let config = CommandSignerConfig {
            command: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "printf signature".to_string(),
                "sh".to_string(),
                "{input}".to_string(),
            ],
            timeout_ms: Some(1000),
            max_output_bytes: Some(64),
        };
        let signature = sign_with_command(&config, b"tbs", key_pair.algorithm()).unwrap();
        assert_eq!(signature, b"signature");
    }

    #[cfg(unix)]
    #[test]
    fn command_signer_timeout_kills_slow_process() {
        let key_pair = KeyPair::generate().unwrap();
        let config = CommandSignerConfig {
            command: "/bin/sleep".to_string(),
            args: vec!["2".to_string()],
            timeout_ms: Some(50),
            max_output_bytes: Some(1024),
        };
        let started = TestInstant::now();
        let result = sign_with_command(&config, b"tbs", key_pair.algorithm());
        assert!(result.is_err());
        assert!(started.elapsed() < TestDuration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn command_signer_timeout_terminates_child_process_group() {
        let key_pair = KeyPair::generate().unwrap();
        let config = CommandSignerConfig {
            command: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "sleep 2".to_string()],
            timeout_ms: Some(50),
            max_output_bytes: Some(1024),
        };
        let started = TestInstant::now();
        let result = sign_with_command(&config, b"tbs", key_pair.algorithm());
        assert!(result.is_err());
        assert!(started.elapsed() < TestDuration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn command_signer_rejects_oversized_stdout_signature() {
        let key_pair = KeyPair::generate().unwrap();
        let config = CommandSignerConfig {
            command: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "head -c 33 /dev/zero".to_string(),
                "sh".to_string(),
                "{input}".to_string(),
            ],
            timeout_ms: Some(1000),
            max_output_bytes: Some(32),
        };
        let result = sign_with_command(&config, b"tbs", key_pair.algorithm());
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn command_signer_rejects_oversized_output_file_signature() {
        let key_pair = KeyPair::generate().unwrap();
        let config = CommandSignerConfig {
            command: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "head -c 33 /dev/zero > \"$1\"".to_string(),
                "sh".to_string(),
                "{output}".to_string(),
                "{input}".to_string(),
            ],
            timeout_ms: Some(1000),
            max_output_bytes: Some(32),
        };
        let result = sign_with_command(&config, b"tbs", key_pair.algorithm());
        assert!(result.is_err());
    }
}
