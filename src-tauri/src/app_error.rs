use std::fmt::{self, Display};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone)]
pub enum AppError {
    Validation {
        field: &'static str,
        message: String,
    },
    CommandUnavailable {
        command: String,
        context: String,
        details: String,
    },
    CommandExecutionFailed {
        command: String,
        context: String,
        details: String,
    },
    CommandPermissionDenied {
        command: String,
        context: String,
        details: String,
    },
    CommandTimeout {
        command: String,
        context: String,
        details: String,
    },
    CommandFailed {
        command: String,
        context: String,
        exit_code: i32,
        stderr: String,
    },
    Internal {
        message: String,
    },
}

impl AppError {
    pub fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            field,
            message: message.into(),
        }
    }

    pub fn command_unavailable(
        command: &str,
        context: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::CommandUnavailable {
            command: command.to_string(),
            context: context.into(),
            details: details.into(),
        }
    }

    pub fn command_execution_failed(
        command: &str,
        context: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::CommandExecutionFailed {
            command: command.to_string(),
            context: context.into(),
            details: details.into(),
        }
    }

    pub fn command_permission_denied(
        command: &str,
        context: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::CommandPermissionDenied {
            command: command.to_string(),
            context: context.into(),
            details: details.into(),
        }
    }

    pub fn command_timeout(
        command: &str,
        context: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::CommandTimeout {
            command: command.to_string(),
            context: context.into(),
            details: details.into(),
        }
    }

    pub fn command_failed(
        command: &str,
        context: impl Into<String>,
        exit_code: i32,
        stderr: impl Into<String>,
    ) -> Self {
        let stderr = stderr.into();
        let hint = stderr.to_ascii_lowercase();
        if hint.contains("permission denied") || hint.contains("access is denied") {
            Self::command_permission_denied(command, context, stderr)
        } else if hint.contains("timed out") || hint.contains("timeout") {
            Self::command_timeout(command, context, stderr)
        } else {
            Self::CommandFailed {
                command: command.to_string(),
                context: context.into(),
                exit_code,
                stderr,
            }
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    pub fn as_tauri_message(&self) -> String {
        self.to_string()
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { field, message } => {
                write!(f, "{field} 校验失败：{message}")
            }
            Self::CommandUnavailable {
                command,
                context,
                details,
            } => {
                write!(
                    f,
                    "{command} 在 {context} 场景下不可用（未安装或无执行权限）：{details}"
                )
            }
            Self::CommandExecutionFailed {
                command,
                context,
                details,
            } => {
                write!(f, "{command} 在 {context} 执行失败：{details}")
            }
            Self::CommandPermissionDenied {
                command,
                context,
                details,
            } => {
                write!(f, "{command} 在 {context} 提示权限不足：{details}")
            }
            Self::CommandTimeout {
                command,
                context,
                details,
            } => {
                write!(f, "{command} 在 {context} 执行超时：{details}")
            }
            Self::CommandFailed {
                command,
                context,
                exit_code,
                stderr,
            } => {
                if stderr.is_empty() {
                    write!(f, "{command} 在 {context} 返回非零状态码：{exit_code}")
                } else {
                    write!(f, "{command} 在 {context} 返回非零状态码 {exit_code}：{stderr}")
                }
            }
            Self::Internal { message } => write!(f, "内部错误：{message}"),
        }
    }
}

impl std::error::Error for AppError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_display() {
        let err = AppError::validation("目标地址", "不能为空");
        assert_eq!(err.to_string(), "目标地址 校验失败：不能为空");
    }

    #[test]
    fn test_command_unavailable_display() {
        let err = AppError::command_unavailable("ping", "Ping 测试", "未找到可执行文件");
        let text = err.to_string();
        assert!(text.contains("ping"));
        assert!(text.contains("Ping 测试"));
        assert!(text.contains("未找到可执行文件"));
    }

    #[test]
    fn test_command_failed_may_be_permission_denied() {
        let err = AppError::command_failed("ping", "Ping 测试", 1, "Permission denied");
        assert!(matches!(err, AppError::CommandPermissionDenied { .. }));
    }

    #[test]
    fn test_command_failed_may_be_timeout() {
        let err = AppError::command_failed("ping", "Ping 测试", 1, "Operation timed out");
        assert!(matches!(err, AppError::CommandTimeout { .. }));
    }

    #[test]
    fn test_command_failed_default_keeps_exit_code() {
        let err = AppError::command_failed("ping", "Ping 测试", 2, "some output");
        match err {
            AppError::CommandFailed {
                exit_code,
                command,
                context,
                stderr,
            } => {
                assert_eq!(exit_code, 2);
                assert_eq!(command, "ping");
                assert_eq!(context, "Ping 测试");
                assert_eq!(stderr, "some output");
            }
            _ => panic!("expect CommandFailed variant"),
        }
    }

    #[test]
    fn test_command_timeout_constructor() {
        let err = AppError::command_timeout("ping", "Ping 测试", "timed out");
        match err {
            AppError::CommandTimeout {
                command,
                context,
                details,
            } => {
                assert_eq!(command, "ping");
                assert_eq!(context, "Ping 测试");
                assert_eq!(details, "timed out");
            }
            _ => panic!("expect CommandTimeout variant"),
        }
    }

    #[test]
    fn test_internal_error_to_string() {
        let err = AppError::internal("内部异常");
        assert_eq!(err.to_string(), "内部错误：内部异常");
    }

    #[test]
    fn test_as_tauri_message_alias() {
        let err = AppError::validation("目标地址", "不能为空");
        assert_eq!(err.as_tauri_message(), "目标地址 校验失败：不能为空");
    }
}
