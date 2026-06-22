from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from niquests import Response


class B2Error(Exception):
    def __init__(self, status: int, code: str, message: str, raw: Any = None) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.raw = raw
        super().__init__(f"[{status} {code}] {message}")


class BadRequestError(B2Error):
    pass


class InvalidBucketNameError(BadRequestError):
    pass


class DuplicateBucketNameError(BadRequestError):
    pass


class UnauthorizedError(B2Error):
    pass


class BadAuthTokenError(UnauthorizedError):
    pass


class ExpiredAuthTokenError(UnauthorizedError):
    pass


class ForbiddenError(B2Error):
    pass


class CapExceededError(ForbiddenError):
    pass


class NotFoundError(B2Error):
    pass


class RequestTimeoutError(B2Error):
    pass


class TooManyRequestsError(B2Error):
    pass


class InternalError(B2Error):
    pass


class ServiceUnavailableError(B2Error):
    pass


class B2ClientError(Exception):
    pass


class B2NotYetAuthorizedError(B2ClientError):
    def __init__(
        self, message: str = "Client is not authorized yet. Call authorize_account() before making API requests."
    ) -> None:
        super().__init__(message)


_STATUS_MAP: dict[int, type[B2Error]] = {
    HTTPStatus.BAD_REQUEST: BadRequestError,
    HTTPStatus.UNAUTHORIZED: UnauthorizedError,
    HTTPStatus.FORBIDDEN: ForbiddenError,
    HTTPStatus.NOT_FOUND: NotFoundError,
    HTTPStatus.REQUEST_TIMEOUT: RequestTimeoutError,
    HTTPStatus.TOO_MANY_REQUESTS: TooManyRequestsError,
    HTTPStatus.INTERNAL_SERVER_ERROR: InternalError,
    HTTPStatus.SERVICE_UNAVAILABLE: ServiceUnavailableError,
}

_CODE_MAP: dict[str, type[B2Error]] = {
    "bad_request": BadRequestError,
    "invalid_bucket_name": InvalidBucketNameError,
    "duplicate_bucket_name": DuplicateBucketNameError,
    "bad_auth_token": BadAuthTokenError,
    "expired_auth_token": ExpiredAuthTokenError,
    "unauthorized": UnauthorizedError,
    "unsupported": UnauthorizedError,
    "cap_exceeded": CapExceededError,
    "storage_cap_exceeded": CapExceededError,
    "transaction_cap_exceeded": CapExceededError,
    "not_found": NotFoundError,
    "file_not_present": NotFoundError,
    "request_timeout": RequestTimeoutError,
    "too_many_requests": TooManyRequestsError,
    "internal_error": InternalError,
    "service_unavailable": ServiceUnavailableError,
}


def from_response(status: int | None, body: Any) -> B2Error:
    status = status if status is not None else -1
    if isinstance(body, dict):
        code = str(body.get("code", "unknown"))
        message = str(body.get("message", body))
        cls = _CODE_MAP.get(code) or _STATUS_MAP.get(status, B2Error)
        return cls(status=status, code=code, message=message, raw=body)

    cls = _STATUS_MAP.get(status, B2Error)
    return cls(status=status, code="unknown", message=str(body), raw=body)


async def raise_if_error(resp: Response) -> None:
    if resp.status_code and HTTPStatus.OK <= resp.status_code < HTTPStatus.MULTIPLE_CHOICES:
        return
    body: Any
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    raise from_response(resp.status_code, body)
