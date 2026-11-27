use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{
    self, Auth, ChannelOpenHandle, Handler, Msg, PublicKeyOffer, Session, VerifiedPublicKey,
};
use russh::{Channel, ChannelId, ChannelReadHalf, ChannelWriteHalf, MethodKind, Pty};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

const AUTH_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SESSIONS: usize = 16;

pub(super) type Dimensions = (u16, u16);
pub(super) type Exit = Pin<Box<dyn Future<Output = io::Result<u32>> + Send>>;
pub(super) type Output = Arc<ChannelWriteHalf<Msg>>;
pub(super) type Process = Box<dyn FnOnce(ChannelReadHalf, Output) -> Exit + Send>;
pub(super) type Launch =
    fn(Program<'_>, Option<watch::Receiver<Dimensions>>) -> io::Result<Process>;

pub(super) enum Program<'a> {
    Shell,
    Exec(&'a str),
    Sftp,
}

pub(super) fn private_key(seed: &[u8; 32]) -> Result<PrivateKey> {
    Ok(PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(seed)),
        "",
    )?)
}

pub(super) fn public_key(key: &PrivateKey) -> [u8; 32] {
    key.public_key()
        .key_data()
        .ed25519()
        .expect("host keys are generated as Ed25519 keys")
        .0
}

pub(super) async fn serve(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    user: String,
    host: PrivateKey,
    client_key: [u8; 32],
    launch: Launch,
) -> Result<()> {
    let config = Arc::new(server::Config {
        methods: [MethodKind::PublicKey].as_slice().into(),
        keys: vec![host],
        window_size: 256 * 1024,
        channel_buffer_size: 16,
        max_auth_attempts: 4,
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let (authenticated, ready) = oneshot::channel();
    let handler = Connection {
        user,
        client_key,
        authenticated: Some(authenticated),
        channels: HashMap::new(),
        launch,
    };
    let deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
    let mut session = tokio::time::timeout_at(deadline, server::run_stream(config, io, handler))
        .await
        .context("SSH identification timed out")??;
    tokio::select! {
        result = &mut session => result,
        result = tokio::time::timeout_at(deadline, ready) => {
            result.context("SSH authentication timed out")?.context("SSH authentication closed")?;
            session.await
        }
    }
}

struct Connection {
    user: String,
    client_key: [u8; 32],
    authenticated: Option<oneshot::Sender<()>>,
    channels: HashMap<ChannelId, ChannelState>,
    launch: Launch,
}

struct ChannelState {
    start: Option<oneshot::Sender<Process>>,
    task: JoinHandle<()>,
    terminal: Option<watch::Sender<Dimensions>>,
}

impl Drop for ChannelState {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Connection {
    fn key_auth(&self, user: &str, key: &PublicKey, algorithm: &Algorithm) -> Auth {
        if user == self.user
            && algorithm == &Algorithm::Ed25519
            && key
                .key_data()
                .ed25519()
                .is_some_and(|key| key.0 == self.client_key)
        {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }

    fn start(&mut self, id: ChannelId, program: Program<'_>, session: &mut Session) -> Result<()> {
        let Some(channel) = self.channels.get_mut(&id) else {
            return Ok(());
        };
        let Some(start) = channel.start.take() else {
            return Ok(session.channel_failure(id)?);
        };
        if matches!(program, Program::Sftp) && channel.terminal.is_some() {
            channel.start = Some(start);
            return Ok(session.channel_failure(id)?);
        }
        let terminal = channel.terminal.as_ref().map(watch::Sender::subscribe);
        match (self.launch)(program, terminal) {
            Ok(process) => {
                session.channel_success(id)?;
                let _ = start.send(process);
            }
            Err(_) => {
                channel.start = Some(start);
                session.channel_failure(id)?;
            }
        }
        Ok(())
    }
}

/// Russh delivers requests and data to the per-channel queue as well as to
/// Handler. Drain it even before exec/shell/SFTP, so traffic on an unopened
/// program cannot block authentication or other channels.
async fn run_channel(mut channel: Channel<Msg>, mut start: oneshot::Receiver<Process>) {
    let process = loop {
        tokio::select! {
            biased;
            process = &mut start => match process {
                Ok(process) => break process,
                Err(_) => return,
            },
            message = channel.wait() => {
                if message.is_none() {
                    return;
                }
            }
        }
    };
    let (input, output) = channel.split();
    let output = Arc::new(output);
    let status = process(input, output.clone()).await.unwrap_or(1);
    let _ = output.exit_status(status).await;
    let _ = output.eof().await;
    let _ = output.close().await;
}

impl Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: PublicKeyOffer<'_>,
    ) -> Result<Auth> {
        Ok(self.key_auth(user, key.public_key, key.algorithm))
    }

    async fn auth_publickey(&mut self, user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth> {
        Ok(self.key_auth(user, key.public_key, key.algorithm))
    }

    async fn auth_succeeded(&mut self, _: &mut Session) -> Result<()> {
        if let Some(authenticated) = self.authenticated.take() {
            let _ = authenticated.send(());
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        if self.authenticated.is_none() && self.channels.len() < MAX_SESSIONS {
            let id = channel.id();
            let (start, receiver) = oneshot::channel();
            let task = tokio::spawn(run_channel(channel, receiver));
            self.channels.insert(
                id,
                ChannelState {
                    start: Some(start),
                    task,
                    terminal: None,
                },
            );
            reply.accept().await;
        }
        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> Result<()> {
        self.channels.remove(&id);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        id: ChannelId,
        _: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        if let Some(channel) = self.channels.get_mut(&id)
            && channel.start.is_some()
            && channel.terminal.is_none()
        {
            channel.terminal = Some(watch::channel(dimensions(cols, rows)).0);
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        session: &mut Session,
    ) -> Result<()> {
        if let Some(terminal) = self
            .channels
            .get(&id)
            .and_then(|state| state.terminal.as_ref())
        {
            terminal.send_replace(dimensions(cols, rows));
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<()> {
        self.start(id, Program::Shell, session)
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        match std::str::from_utf8(command) {
            Ok(command) => self.start(id, Program::Exec(command), session),
            Err(_) => Ok(session.channel_failure(id)?),
        }
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<()> {
        if name == "sftp" {
            self.start(id, Program::Sftp, session)
        } else {
            Ok(session.channel_failure(id)?)
        }
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: &str,
        session: &mut Session,
    ) -> Result<()> {
        Ok(session.channel_failure(id)?)
    }

    async fn x11_request(
        &mut self,
        id: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        session: &mut Session,
    ) -> Result<()> {
        Ok(session.channel_failure(id)?)
    }
}

fn dimensions(cols: u32, rows: u32) -> Dimensions {
    let dim = |n: u32| n.clamp(1, i16::MAX as u32) as u16;
    (dim(cols), dim(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client;
    use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
    use russh::{ChannelMsg, Disconnect};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CLIENT_SEED: [u8; 32] = [2; 32];

    struct Client([u8; 32]);

    impl client::Handler for Client {
        type Error = anyhow::Error;

        async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
            Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. }
                if key.key_data().ed25519().is_some_and(|key| key.0 == self.0)))
        }
    }

    fn echo(program: Program<'_>, _: Option<watch::Receiver<Dimensions>>) -> io::Result<Process> {
        let status = match program {
            Program::Shell => 3,
            Program::Exec("exit") => 7,
            Program::Sftp => 0,
            Program::Exec(_) => return Err(io::ErrorKind::InvalidInput.into()),
        };
        Ok(Box::new(move |mut input, output| {
            Box::pin(async move {
                let mut bytes = Vec::new();
                input.make_reader().read_to_end(&mut bytes).await?;
                output.make_writer().write_all(&bytes).await?;
                Ok(status)
            })
        }))
    }

    async fn connection() -> Result<(client::Handle<Client>, JoinHandle<Result<()>>)> {
        let (server, client) = tokio::io::duplex(64 * 1024);
        let host = private_key(&[1; 32])?;
        let pin = public_key(&host);
        let client_key = public_key(&private_key(&CLIENT_SEED)?);
        let worker = tokio::spawn(serve(server, "RegularUser".into(), host, client_key, echo));
        let client = client::connect_stream(Arc::default(), client, Client(pin)).await?;
        Ok((client, worker))
    }

    async fn auth(
        client: &mut client::Handle<Client>,
        user: &str,
        seed: &[u8; 32],
    ) -> Result<bool> {
        let key = PrivateKeyWithHashAlg::new(Arc::new(private_key(seed)?), None);
        Ok(client.authenticate_publickey(user, key).await?.success())
    }

    #[tokio::test]
    async fn windows_ssh_authenticates_only_exact_user_and_key() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            for (user, key, expected) in [
                ("regularuser", CLIENT_SEED, false),
                ("RegularUser", [3; 32], false),
                ("RegularUser", CLIENT_SEED, true),
            ] {
                let (mut client, worker) = connection().await?;
                assert_eq!(auth(&mut client, user, &key).await?, expected);
                client.disconnect(Disconnect::ByApplication, "", "").await?;
                let _ = worker.await?;
            }
            let (mut client, worker) = connection().await?;
            assert!(
                !client
                    .authenticate_password("RegularUser", "password")
                    .await?
                    .success()
            );
            client.disconnect(Disconnect::ByApplication, "", "").await?;
            let _ = worker.await?;
            Ok(())
        })
        .await?
    }

    #[tokio::test]
    async fn windows_ssh_session_channels_are_independent_and_do_not_forward() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (mut client, worker) = connection().await?;
            assert!(auth(&mut client, "RegularUser", &CLIENT_SEED).await?);
            assert!(
                client
                    .channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 1000)
                    .await
                    .is_err()
            );
            assert!(client.tcpip_forward("127.0.0.1", 0).await.is_err());

            let mut exec = client.channel_open_session().await?;
            for _ in 0..32 {
                // Fill more than the channel queue before a process starts.
                exec.set_env(false, "TEST", "value").await?;
            }
            exec.agent_forward(true).await?;
            assert!(matches!(exec.wait().await, Some(ChannelMsg::Failure)));
            let mut sftp = client.channel_open_session().await?;
            exec.exec(true, b"exit".to_vec()).await?;
            sftp.request_subsystem(true, "sftp").await?;
            assert!(matches!(exec.wait().await, Some(ChannelMsg::Success)));
            assert!(matches!(sftp.wait().await, Some(ChannelMsg::Success)));
            exec.data_bytes(b"exec input".as_slice()).await?;
            sftp.data_bytes(b"sftp input".as_slice()).await?;
            exec.eof().await?;
            sftp.eof().await?;
            for (mut channel, input, status) in [
                (exec, b"exec input".as_slice(), 7),
                (sftp, b"sftp input".as_slice(), 0),
            ] {
                let mut bytes = Vec::new();
                let mut exit = None;
                while let Some(message) = channel.wait().await {
                    match message {
                        ChannelMsg::Data { data } => bytes.extend_from_slice(&data),
                        ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                        ChannelMsg::Close => break,
                        _ => {}
                    }
                }
                assert_eq!(bytes, input);
                assert_eq!(exit, Some(status));
            }
            client.disconnect(Disconnect::ByApplication, "", "").await?;
            let _ = worker.await?;
            Ok(())
        })
        .await?
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_ssh_worker_executes_with_private_stdio() -> Result<()> {
        use super::super::{
            Prepared, ssh_account, system_executable, worker_executable, worker_ready,
        };
        use zeroize::Zeroizing;

        let exe = match worker_executable() {
            Ok(exe) => exe,
            Err(_) if std::env::var_os("CI").is_none() => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut bootstrap = Zeroizing::new([0; 64]);
        bootstrap[..32].copy_from_slice(&[1; 32]);
        bootstrap[32..].copy_from_slice(&public_key(&private_key(&CLIENT_SEED)?));
        let dir = tempfile::tempdir()?;
        let (mut stream, worker) = Prepared { exe, bootstrap }.start(dir.path())?;
        tokio::time::timeout(Duration::from_secs(15), async {
            worker_ready(&mut stream).await?;
            let pin = public_key(&private_key(&[1; 32])?);
            let mut client = client::connect_stream(Arc::default(), stream, Client(pin)).await?;
            let user = ssh_account()?;
            assert!(auth(&mut client, &user, &CLIENT_SEED).await?);

            let mut exec = client.channel_open_session().await?;
            exec.exec(true, "echo massrelay-test& echo stderr-test>&2& exit /b 7")
                .await?;
            assert!(matches!(exec.wait().await, Some(ChannelMsg::Success)));
            exec.eof().await?;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut exit = None;
            while let Some(message) = exec.wait().await {
                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { ext: 1, data } => stderr.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            assert!(String::from_utf8_lossy(&stdout).contains("massrelay-test"));
            assert!(String::from_utf8_lossy(&stderr).contains("stderr-test"));
            assert_eq!(exit, Some(7));

            if system_executable(r"OpenSSH\sftp-server.exe").is_ok() {
                let mut sftp = client.channel_open_session().await?;
                sftp.request_subsystem(true, "sftp").await?;
                assert!(matches!(sftp.wait().await, Some(ChannelMsg::Success)));
                sftp.data_bytes([0, 0, 0, 5, 1, 0, 0, 0, 3].as_slice())
                    .await?;
                let mut header = [0; 9];
                sftp.make_reader().read_exact(&mut header).await?;
                assert_eq!(header[4..], [2, 0, 0, 0, 3]);
                sftp.eof().await?;
            }
            client.disconnect(Disconnect::ByApplication, "", "").await?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        worker.reap().await;
        Ok(())
    }
}
