from __future__ import annotations

import asyncio
import logging
from base64 import b64encode
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from niquests import AsyncSession

from b2py.constants import DEFAULT_API_VERSION
from b2py.exceptions import B2NotYetAuthorizedError, from_response
from b2py.models import AuthorizeAccountResponse

if TYPE_CHECKING:
    from b2py.enums import Capability
    from b2py.models import AllowedBucket


def authorize_url(api_version: str = DEFAULT_API_VERSION) -> str:
    return f"https://api.backblazeb2.com/b2api/{api_version}/b2_authorize_account"


logger = logging.getLogger(__name__)


class B2Auth:
    def __init__(self, key_id: str, application_key: str, api_version: str | None = None) -> None:
        self.key_id = key_id
        self.application_key = application_key
        self.api_version = api_version or DEFAULT_API_VERSION

        self._auth: AuthorizeAccountResponse | None = None
        self._lock = asyncio.Lock()

    @property
    def is_authorized(self) -> bool:
        return self._auth is not None

    @property
    def auth(self) -> AuthorizeAccountResponse:
        if self._auth is None:
            raise B2NotYetAuthorizedError
        return self._auth

    @property
    def token(self) -> str:
        return self.auth.authorization_token

    @property
    def account_id(self) -> str:
        return self.auth.account_id

    @property
    def api_url(self) -> str:
        return self.auth.api_info.storage_api.api_url

    @property
    def download_url(self) -> str:
        return self.auth.api_info.storage_api.download_url

    @property
    def s3_url(self) -> str:
        return self.auth.api_info.storage_api.s3_api_url

    @property
    def recommended_part_size(self) -> int:
        return self.auth.api_info.storage_api.recommended_part_size

    @property
    def minimum_part_size(self) -> int:
        return self.auth.api_info.storage_api.absolute_minimum_part_size

    @property
    def capabilities(self) -> list[Capability]:
        return self.auth.api_info.storage_api.allowed_restrictions.capabilities

    @property
    def allowed_buckets(self) -> list[AllowedBucket]:
        return self.auth.api_info.storage_api.allowed_restrictions.buckets

    async def authorize(self, session: AsyncSession | None = None) -> AuthorizeAccountResponse:
        async with self._lock:
            return await self._do_authorize(session)

    async def ensure(self, session: AsyncSession | None = None) -> AuthorizeAccountResponse:
        if self._auth is not None:
            return self._auth
        async with self._lock:
            if self._auth is not None:
                return self._auth
            return await self._do_authorize(session)

    async def _do_authorize(self, session: AsyncSession | None) -> AuthorizeAccountResponse:
        credentials = f"{self.key_id}:{self.application_key}".encode()
        headers = {"Authorization": f"Basic {b64encode(credentials).decode()}"}
        logger.info("Authorizing B2 account (key id %s...)", self.key_id[:4])

        own_session = session is None
        client = session or AsyncSession()
        try:
            resp = await client.get(authorize_url(self.api_version), headers=headers, timeout=300.0)
        finally:
            if own_session:
                await client.close()

        if resp.status_code != HTTPStatus.OK:
            body: Any
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            raise from_response(resp.status_code, body)

        data = resp.json()
        self._auth = AuthorizeAccountResponse.from_dict(data)
        logger.debug(
            "B2 authorized: api_url=%s, download_url=%s, recommendedPartSize=%d",
            self._auth.api_info.storage_api.api_url,
            self._auth.api_info.storage_api.download_url,
            self._auth.api_info.storage_api.recommended_part_size,
        )
        return self._auth

    async def clear(self) -> None:
        async with self._lock:
            self._auth = None
