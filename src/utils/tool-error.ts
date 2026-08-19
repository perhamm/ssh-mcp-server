export type ToolErrorCode =
  | "COMMAND_VALIDATION_FAILED"
  | "COMMAND_EXECUTION_ERROR"
  | "OUTPUT_LIMIT_EXCEEDED"
  | "COMMAND_TIMEOUT"
  | "SSH_CONNECTION_FAILED"
  | "SSH_CONNECTION_TIMEOUT"
  | "SSH_AUTHENTICATION_MISSING"
  | "SSH_HOST_KEY_REJECTED"
  | "LOCAL_PATH_NOT_ALLOWED"
  | "LOCAL_PATH_FORBIDDEN"
  | "REMOTE_PATH_NOT_ALLOWED"
  | "REMOTE_PATH_FORBIDDEN"
  | "LOCAL_FILE_READ_FAILED"
  | "LOCAL_FILE_WRITE_FAILED"
  | "OPERATION_TIMEOUT"
  | "SFTP_ERROR"
  | "UNSUPPORTED_IN_SHELL_MODE"
  | "SSH_CONFIGURATION_MISSING"
  | "SSH_HOST_NOT_ALLOWED"
  | "SUDO_NOT_ALLOWED"
  | "SUDO_PASSWORD_MISSING"
  | "TUNNEL_DISABLED"
  | "TUNNEL_NOT_CONFIGURED"
  | "TUNNEL_NOT_FOUND"
  | "TUNNEL_LIMIT_REACHED"
  | "TUNNEL_INVALID_TARGET"
  | "TUNNEL_INVALID_PORT"
  | "TUNNEL_PORT_NOT_ALLOWED"
  | "TUNNEL_BIND_FAILED"
  | "UNKNOWN_ERROR";

export class ToolError extends Error {
  constructor(
    public readonly code: ToolErrorCode,
    message: string,
    public readonly retriable: boolean = false,
  ) {
    super(message);
    this.name = "ToolError";
  }
}

export function toToolError(
  error: unknown,
  fallbackCode: ToolErrorCode,
): ToolError {
  if (error instanceof ToolError) {
    return error;
  }

  if (error instanceof Error) {
    return new ToolError(fallbackCode, error.message, false);
  }

  return new ToolError(fallbackCode, String(error), false);
}
