use crate::app_error::{AppError, AppResult};
use std::io::ErrorKind;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn ensure_command_available(command: &str) -> AppResult<()> {
    Command::new(command)
        .arg("--help")
        .status()
        .map_err(|err| {
            if err.kind() == ErrorKind::NotFound {
                AppError::command_unavailable(command, "依赖检查", err.to_string())
            } else if err.kind() == ErrorKind::PermissionDenied {
                AppError::command_permission_denied(command, "依赖检查", err.to_string())
            } else {
                AppError::command_execution_failed(command, "依赖检查", err.to_string())
            }
        })?;

    Ok(())
}

pub fn run_command<F, T>(command: &str, context: &str, configure: F) -> AppResult<CommandOutput>
where
    F: FnOnce(&mut Command) -> T,
{
    let mut command_builder = Command::new(command);
    configure(&mut command_builder);

    let output = command_builder.output().map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            AppError::command_unavailable(command, context, err.to_string())
        } else if err.kind() == ErrorKind::PermissionDenied {
            AppError::command_permission_denied(command, context, err.to_string())
        } else if err.kind() == ErrorKind::TimedOut {
            AppError::command_timeout(command, context, err.to_string())
        } else {
            AppError::command_execution_failed(command, context, err.to_string())
        }
    })?;

    Ok(CommandOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn run_command_required<F, T>(
    command: &str,
    context: &str,
    configure: F,
) -> AppResult<CommandOutput>
where
    F: FnOnce(&mut Command) -> T,
{
    let output = run_command(command, context, configure)?;

    if output.status != 0 {
        return Err(AppError::command_failed(
            command,
            context,
            output.status,
            output.stderr.clone(),
        ));
    }

    Ok(output)
}

pub fn run_command_with_timeout<F, T>(
    command: &str,
    context: &str,
    configure: F,
    timeout: Duration,
) -> AppResult<CommandOutput>
where
    F: FnOnce(&mut Command) -> T,
{
    let mut command_builder = Command::new(command);
    configure(&mut command_builder);
    let mut child = command_builder
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            if err.kind() == ErrorKind::NotFound {
                AppError::command_unavailable(command, context, err.to_string())
            } else if err.kind() == ErrorKind::PermissionDenied {
                AppError::command_permission_denied(command, context, err.to_string())
            } else {
                AppError::command_execution_failed(command, context, err.to_string())
            }
        })?;

    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|err| {
            AppError::command_execution_failed(command, context, err.to_string())
        })? {
            Some(status) => {
                let mut stdout = String::new();
                let mut stderr = String::new();

                if let Some(mut out) = child.stdout.take() {
                    out.read_to_string(&mut stdout).unwrap_or_default();
                }
                if let Some(mut err) = child.stderr.take() {
                    err.read_to_string(&mut stderr).unwrap_or_default();
                }

                let _ = child.wait();

                return Ok(CommandOutput {
                    status: status.code().unwrap_or(-1),
                    stdout,
                    stderr,
                });
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AppError::command_timeout(
                        command,
                        context,
                        "执行超时，已终止子进程",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_ensure_command_available_not_found() {
        let err = ensure_command_available("definitely_not_exists_cmd_12345").unwrap_err();
        assert!(matches!(err, AppError::CommandUnavailable { .. }));
        assert!(err.to_string().contains("不可用"));
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_command_available_permission_denied() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut path = env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("portly_cmd_exec_perm_test_{suffix}.sh"));
        fs::write(&path, "#!/bin/sh\necho no-permission-test\n").unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0),
        )
        .unwrap();

        let err = ensure_command_available(path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, AppError::CommandPermissionDenied { .. }));
        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn test_run_command_permission_denied() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut path = env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("portly_cmd_exec_run_permission_{suffix}.sh"));
        fs::write(&path, "#!/bin/sh\necho no-permission-test\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();

        let err = run_command(path.to_str().unwrap(), "执行权限测试", |_| {}).unwrap_err();
        assert!(matches!(err, AppError::CommandPermissionDenied { .. }));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_ensure_command_available_current_binary_ok() {
        let exe = env::current_exe().unwrap();
        let exe = exe.to_string_lossy();
        let err = ensure_command_available(&exe);
        assert!(err.is_ok());
    }

    #[test]
    fn test_run_command_not_found() {
        let err = run_command("definitely_not_exists_cmd_12345", "不存在命令测试", |_| {}).unwrap_err();

        assert!(matches!(err, AppError::CommandUnavailable { .. }));
        if let AppError::CommandUnavailable {
            command,
            context,
            ..
        } = err
        {
            assert_eq!(command, "definitely_not_exists_cmd_12345");
            assert_eq!(context, "不存在命令测试");
        } else {
            panic!("expect CommandUnavailable variant");
        }
    }

    #[test]
    fn test_run_command_required_not_found() {
        let err =
            run_command_required("definitely_not_exists_cmd_12345", "不存在命令测试", |_| {}).unwrap_err();

        assert!(matches!(err, AppError::CommandUnavailable { .. }));
        if let AppError::CommandUnavailable {
            command,
            context,
            ..
        } = err
        {
            assert_eq!(command, "definitely_not_exists_cmd_12345");
            assert_eq!(context, "不存在命令测试");
        } else {
            panic!("expect CommandUnavailable variant");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_with_timeout_not_found() {
        let err = run_command_with_timeout(
            "definitely_not_exists_cmd_12345",
            "超时命令不存在测试",
            |_| {},
            Duration::from_millis(500),
        )
        .unwrap_err();

        assert!(matches!(err, AppError::CommandUnavailable { .. }));
        if let AppError::CommandUnavailable {
            command,
            context,
            ..
        } = err
        {
            assert_eq!(command, "definitely_not_exists_cmd_12345");
            assert_eq!(context, "超时命令不存在测试");
        } else {
            panic!("expect CommandUnavailable variant");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_with_timeout_not_found() {
        let err = run_command_with_timeout(
            "definitely_not_exists_cmd_12345",
            "超时命令不存在测试",
            |_| {},
            Duration::from_millis(500),
        )
        .unwrap_err();

        assert!(matches!(err, AppError::CommandUnavailable { .. }));
        if let AppError::CommandUnavailable {
            command,
            context,
            ..
        } = err
        {
            assert_eq!(command, "definitely_not_exists_cmd_12345");
            assert_eq!(context, "超时命令不存在测试");
        } else {
            panic!("expect CommandUnavailable variant");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_run_command_with_timeout_permission_denied() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut path = env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("portly_cmd_exec_timeout_perm_{suffix}.sh"));
        fs::write(&path, "#!/bin/sh\necho timeout-permission-test\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();

        let err = run_command_with_timeout(
            path.to_str().unwrap(),
            "超时权限拒绝测试",
            |_| {},
            Duration::from_millis(500),
        )
        .unwrap_err();
        let _ = fs::remove_file(path);

        assert!(matches!(err, AppError::CommandPermissionDenied { .. }));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_stdout() {
        let output = run_command("sh", "输出测试", |cmd| {
            cmd.args(["-c", "printf 'hello'"]);
        })
        .unwrap();
        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, "hello");
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_stdout() {
        let output = run_command("cmd", "输出测试", |cmd| {
            cmd.args(["/C", "echo", "hello"]);
        })
        .unwrap();
        assert_eq!(output.status, 0);
        assert!(output.stdout.contains("hello"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_required_error() {
        let err = run_command_required("sh", "失败测试", |cmd| {
            cmd.args(["-c", "exit 1"]);
        })
        .unwrap_err();
        assert!(matches!(err, AppError::CommandFailed { .. }));
        if let AppError::CommandFailed { exit_code, .. } = err {
            assert_ne!(exit_code, 0);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_required_nonstandard_exit_code() {
        let err = run_command_required("sh", "非标准退出码测试", |cmd| {
            cmd.args(["-c", "exit 123"]);
        })
        .unwrap_err();

        if let AppError::CommandFailed { exit_code, .. } = err {
            assert_eq!(exit_code, 123);
        } else {
            panic!("expect CommandFailed variant");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_with_empty_output() {
        let output = run_command("sh", "空输出测试", |cmd| {
            cmd.args(["-c", ""]);
        })
        .unwrap();

        assert_eq!(output.status, 0);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_required_error_with_empty_stderr() {
        let err = run_command_required("sh", "空标准错误失败测试", |cmd| {
            cmd.args(["-c", "exit 1"]);
        })
        .unwrap_err();

        if let AppError::CommandFailed {
            exit_code,
            stderr,
            ..
        } = err
        {
            assert_eq!(exit_code, 1);
            assert!(stderr.is_empty());
        } else {
            panic!("expect CommandFailed variant");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_with_timeout_success() {
        let output = run_command_with_timeout(
            "sh",
            "超时测试成功",
            |cmd| {
                cmd.args(["-c", "printf 'hello-with-timeout'"]);
            },
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, "hello-with-timeout");
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_with_timeout() {
        let err = run_command_with_timeout(
            "sh",
            "超时测试",
            |cmd| {
                cmd.args(["-c", "sleep 2"]);
            },
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(matches!(err, AppError::CommandTimeout { .. }));

        match err {
            AppError::CommandTimeout {
                command,
                context,
                ..
            } => {
                assert_eq!(command, "sh");
                assert_eq!(context, "超时测试");
            }
            _ => panic!("expect CommandTimeout variant"),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_command_with_timeout_nonstandard_exit_code() {
        let output = run_command_with_timeout(
            "sh",
            "超时非标准退出码测试",
            |cmd| {
                cmd.args(["-c", "exit 123"]);
            },
            Duration::from_millis(500),
        )
        .unwrap();
        assert_eq!(output.status, 123);
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_with_timeout_success() {
        let output = run_command_with_timeout(
            "cmd",
            "超时测试成功",
            |cmd| {
                cmd.args(["/C", "echo", "hello-with-timeout"]);
            },
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(output.status, 0);
        assert!(output.stdout.contains("hello-with-timeout"));
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_required_error() {
        let err = run_command_required("cmd", "失败测试", |cmd| {
            cmd.args(["/C", "exit", "1"]);
        })
        .unwrap_err();
        assert!(matches!(err, AppError::CommandFailed { .. }));
        if let AppError::CommandFailed { exit_code, .. } = err {
            assert_ne!(exit_code, 0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_required_nonstandard_exit_code() {
        let err = run_command_required("cmd", "非标准退出码测试", |cmd| {
            cmd.args(["/C", "exit", "123"]);
        })
        .unwrap_err();

        if let AppError::CommandFailed { exit_code, .. } = err {
            assert_eq!(exit_code, 123);
        } else {
            panic!("expect CommandFailed variant");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_required_error_with_empty_stderr() {
        let err = run_command_required("cmd", "空标准错误失败测试", |cmd| {
            cmd.args(["/C", "exit", "1"]);
        })
        .unwrap_err();

        if let AppError::CommandFailed {
            exit_code,
            ..
        } = err
        {
            assert_eq!(exit_code, 1);
        } else {
            panic!("expect CommandFailed variant");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_run_command_permission_denied_concurrent_calls() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{atomic::AtomicUsize, atomic::Ordering, Arc};
        use std::thread;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut path = env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("portly_cmd_exec_perm_concurrent_{suffix}.sh"));
        fs::write(&path, "#!/bin/sh\necho should-not-run\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();

        let file_path = path.to_string_lossy().to_string();
        let denied_count = Arc::new(AtomicUsize::new(0));
        let runs = 10;
        let mut handles = Vec::new();

        for _ in 0..runs {
            let denied_count = denied_count.clone();
            let file_path = file_path.clone();
            handles.push(thread::spawn(move || {
                let err = run_command(file_path.as_str(), "并发权限测试", |_| {}).unwrap_err();
                if matches!(err, AppError::CommandPermissionDenied { .. }) {
                    denied_count.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let _ = fs::remove_file(path);
        assert_eq!(denied_count.load(Ordering::SeqCst), runs);
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_with_timeout() {
        let err = run_command_with_timeout(
            "cmd",
            "超时测试",
            |cmd| {
                cmd.args(["/C", "ping 127.0.0.1 -n 3 >nul"]);
            },
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(matches!(err, AppError::CommandTimeout { .. }));

        match err {
            AppError::CommandTimeout {
                command,
                context,
                ..
            } => {
                assert_eq!(command, "cmd");
                assert_eq!(context, "超时测试");
            }
            _ => panic!("expect CommandTimeout variant"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_run_command_with_timeout_nonstandard_exit_code() {
        let err = run_command_with_timeout(
            "cmd",
            "超时非标准退出码测试",
            |cmd| {
                cmd.args(["/C", "exit", "123"]);
            },
            Duration::from_millis(500),
        )
        .unwrap_err();

        if let AppError::CommandFailed {
            exit_code, ..
        } = err
        {
            assert_eq!(exit_code, 123);
        } else {
            panic!("expect CommandFailed variant");
        }
    }
}
