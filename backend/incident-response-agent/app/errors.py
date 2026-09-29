"""Application errors carrying an HTTP status so the API can report them clearly."""


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict:
        d = {"error": self.code, "message": self.message}
        if self.hint:
            d["hint"] = self.hint
        return d


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_error"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class ConfigError(AppError):
    """A required credential/setting is missing."""
    status_code = 503
    code = "not_configured"


class UpstreamError(AppError):
    """Hindsight or the LLM provider failed."""
    status_code = 502
    code = "upstream_failure"


class DataFileError(AppError):
    """A bundled YAML/JSON file is malformed."""
    status_code = 500
    code = "data_file_error"
