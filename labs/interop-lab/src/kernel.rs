use crate::case_spec::{ApiAccess, KernelLaunchSpec};
use crate::snapshot::KernelKind;
use crate::util::resolve_with_env;
use anyhow::{anyhow, Context, Result};
use reqwest::StatusCode;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub struct KernelSession {
    pub api: ApiAccess,
    pub child: Option<Child>,
    pub stdout_task: Option<tokio::task::JoinHandle<()>>,
    pub stderr_task: Option<tokio::task::JoinHandle<()>>,
}

impl KernelSession {
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        if let Some(task) = self.stdout_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }
        Ok(())
    }
}

pub async fn launch_kernel(
    kind: KernelKind,
    spec: &KernelLaunchSpec,
    logs_dir: &Path,
) -> Result<KernelSession> {
    let api = ApiAccess {
        base_url: resolve_with_env(&spec.api.base_url),
        secret: spec.api.secret.as_ref().map(|v| resolve_with_env(v)),
    };

    if spec.command.is_none() {
        wait_until_ready(&api, &spec.ready_path, spec.startup_timeout_ms).await?;
        return Ok(KernelSession {
            api,
            child: None,
            stdout_task: None,
            stderr_task: None,
        });
    }

    let command = spec
        .command
        .as_deref()
        .map(resolve_with_env)
        .ok_or_else(|| anyhow!("kernel command missing"))?;

    let mut cmd = Command::new(command);
    for arg in &spec.args {
        cmd.arg(resolve_with_env(arg));
    }

    for (k, v) in &spec.env {
        cmd.env(k, resolve_with_env(v));
    }

    if let Some(workdir) = &spec.workdir {
        cmd.current_dir(workdir);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().with_context(|| "starting kernel process")?;

    let stdout_path = logs_dir
        .join(format!("{:?}.stdout.log", kind))
        .to_string_lossy()
        .to_string();
    let stderr_path = logs_dir
        .join(format!("{:?}.stderr.log", kind))
        .to_string_lossy()
        .to_string();

    let stdout_task = child.stdout.take().map(|stdout| {
        let path = stdout_path.clone();
        tokio::spawn(async move {
            if let Ok(mut file) = tokio::fs::File::create(path).await {
                let mut reader = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let payload = format!("{line}\n");
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut file, payload.as_bytes()).await;
                }
            }
        })
    });

    let stderr_task = child.stderr.take().map(|stderr| {
        let path = stderr_path.clone();
        tokio::spawn(async move {
            if let Ok(mut file) = tokio::fs::File::create(path).await {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let payload = format!("{line}\n");
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut file, payload.as_bytes()).await;
                }
            }
        })
    });

    wait_until_ready(&api, &spec.ready_path, spec.startup_timeout_ms).await?;

    Ok(KernelSession {
        api,
        child: Some(child),
        stdout_task,
        stderr_task,
    })
}

pub async fn wait_until_ready(api: &ApiAccess, ready_path: &str, timeout_ms: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(100));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .with_context(|| "building readiness http client")?;
    let normalized_path = if ready_path.starts_with('/') {
        ready_path.to_string()
    } else {
        format!("/{ready_path}")
    };

    while Instant::now() < deadline {
        let url = format!("{}{}", api.base_url.trim_end_matches('/'), normalized_path);
        let mut request = client.get(url);
        if let Some(secret) = &api.secret {
            request = request.bearer_auth(secret);
        }
        match request.send().await {
            Ok(response)
                if response.status().is_success()
                    || response.status() == StatusCode::NO_CONTENT
                    || response.status() == StatusCode::UNAUTHORIZED =>
            {
                return Ok(());
            }
            Ok(_) => {}
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Err(anyhow!(
        "kernel not ready within {} ms at {}{}",
        timeout_ms,
        api.base_url,
        normalized_path
    ))
}
