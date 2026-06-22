from __future__ import annotations

import logging
import mimetypes
from hashlib import sha1
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self
from urllib.parse import quote

from niquests import AsyncSession

from b2py.enums import BucketType
from b2py.exceptions import B2ClientError, from_response, raise_if_error
from b2py.models import (
    ApplicationKey,
    ApplicationKeyListResponse,
    Bucket,
    BucketEventNotificationRule,
    DeletedFileResponse,
    DownloadAuthorization,
    DownloadedFile,
    FileListResponse,
    FileVersion,
    Part,
    PartsListPage,
    UploadPartUrl,
    UploadUrl,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from b2py.auth import B2Auth
    from b2py.enums import Capability
    from b2py.models import (
        AuthorizeAccountResponse,
        CORSRule,
        DefaultFileRetentionConfiguration,
        FileRetentionValue,
        LifecycleRule,
        RemoteServerSideEncryptionConfiguration,
        ReplicationConfiguration,
        ServerSideEncryptionValue,
    )

logger = logging.getLogger(__name__)


def _guess_mimetype(file_path: Path | str) -> str:
    ct = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    if ct.startswith("text/") or ct == "application/json":
        return f"{ct}; charset=utf-8"
    return ct


def _encode_filename(name: str | Path) -> str:
    raw = name.as_posix() if isinstance(name, Path) else name
    return quote(raw, safe="/")


def _request_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    to_request_dict = getattr(value, "to_request_dict", None)
    if to_request_dict is not None:
        return to_request_dict()
    return value.to_dict()


def _file_info_headers(file_info: dict[str, str] | None) -> dict[str, str]:
    if not file_info:
        return {}
    out: dict[str, str] = {}
    for k, v in file_info.items():
        out[f"X-Bz-Info-{k}"] = quote(str(v), safe="")
    return out


def _download_params(
    file_id: str | None = None,
    b2_content_disposition: str | None = None,
    b2_content_language: str | None = None,
    b2_expires: str | None = None,
    b2_cache_control: str | None = None,
    b2_content_encoding: str | None = None,
    b2_content_type: str | None = None,
) -> dict[str, str]:
    params = {
        "fileId": file_id,
        "b2ContentDisposition": b2_content_disposition,
        "b2ContentLanguage": b2_content_language,
        "b2Expires": b2_expires,
        "b2CacheControl": b2_cache_control,
        "b2ContentEncoding": b2_content_encoding,
        "b2ContentType": b2_content_type,
    }
    return {key: value for key, value in params.items() if value is not None}


async def _post_json(session: AsyncSession, url: str, json: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    resp = await session.post(url, json=json, headers=headers)
    await raise_if_error(resp)
    return resp.json()


async def _get_json(session: AsyncSession, url: str, params: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    clean = {k: v for k, v in params.items() if v is not None}
    resp = await session.get(url, params=clean, headers=headers)
    await raise_if_error(resp)
    return resp.json()


async def _write_stream_to_path(resp: Any, destination: Path, chunk_size: int) -> None:
    try:
        if resp.status_code and resp.status_code >= HTTPStatus.BAD_REQUEST:
            try:
                body = await resp.json()
            except Exception:
                body = await resp.text()
            raise from_response(resp.status_code, body)
        with destination.open("wb") as file_handle:
            async for chunk in await resp.iter_content(chunk_size):
                file_handle.write(chunk)
    finally:
        await resp.close()


class B2Client:
    def __init__(
        self, auth: B2Auth, session: AsyncSession | None = None, timeout: float = 600.0, api_version: str | None = None
    ) -> None:
        self.auth = auth
        self.api_version = api_version or auth.api_version
        self._external_session = session is not None
        self._session = session
        self._timeout = timeout
        self._user_agent = "b2py"

    async def __aenter__(self) -> Self:
        if self._session is None:
            self._session = AsyncSession(timeout=self._timeout, headers={"User-Agent": self._user_agent})
            self._external_session = False
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._session is not None and not self._external_session:
            await self._session.close()
            self._session = None

    @property
    def account_id(self) -> str:
        return self.auth.account_id

    @property
    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": self.auth.token}

    @property
    def session(self) -> AsyncSession:
        if self._session is None:
            self._session = AsyncSession(timeout=self._timeout, headers={"User-Agent": self._user_agent})
            self._external_session = False
        return self._session

    def _api_url(self, endpoint: str) -> str:
        return f"{self.auth.api_url}/b2api/{self.api_version}/{endpoint}"

    def _download_url(self, endpoint: str) -> str:
        return f"{self.auth.download_url}/b2api/{self.api_version}/{endpoint}"

    async def authorize_account(self) -> AuthorizeAccountResponse:
        return await self.auth.authorize(self.session)

    async def ensure_authorized(self) -> AuthorizeAccountResponse:
        return await self.auth.ensure(self.session)

    async def list_buckets(
        self, bucket_id: str | None = None, bucket_name: str | None = None, bucket_types: list[str] | None = None
    ) -> list[Bucket]:
        await self.ensure_authorized()
        body: dict[str, Any] = {"accountId": self.account_id}
        if bucket_id:
            body["bucketId"] = bucket_id
        if bucket_name:
            body["bucketName"] = bucket_name
        if bucket_types:
            body["bucketTypes"] = bucket_types
        url = self._api_url("b2_list_buckets")
        data = await _post_json(session=self.session, url=url, json=body, headers=self.auth_headers)
        return [Bucket.from_dict(b) for b in data.get("buckets", [])]

    async def delete_bucket(self, bucket_id: str) -> Bucket:
        await self.ensure_authorized()
        body = {"accountId": self.account_id, "bucketId": bucket_id}
        url = self._api_url("b2_delete_bucket")
        data = await _post_json(session=self.session, url=url, json=body, headers=self.auth_headers)
        return Bucket.from_dict(data)

    async def create_bucket(
        self,
        bucket_name: str,
        public: bool = False,
        bucket_info: dict[str, Any] | None = None,
        cors_rules: list[CORSRule | dict[str, Any]] | None = None,
        lifecycle_rules: list[LifecycleRule | dict[str, Any]] | None = None,
        file_lock_enabled: bool | None = None,
        default_server_side_encryption: ServerSideEncryptionValue | dict[str, Any] | None = None,
        replication_configuration: ReplicationConfiguration | dict[str, Any] | None = None,
    ) -> Bucket:
        bucket_type = BucketType.ALL_PUBLIC if public else BucketType.ALL_PRIVATE
        await self.ensure_authorized()
        body: dict[str, Any] = {"accountId": self.account_id, "bucketName": bucket_name, "bucketType": bucket_type}
        if bucket_info is not None:
            body["bucketInfo"] = bucket_info
        if cors_rules is not None:
            body["corsRules"] = [_request_dict(r) for r in cors_rules]
        if lifecycle_rules is not None:
            body["lifecycleRules"] = [_request_dict(r) for r in lifecycle_rules]
        if file_lock_enabled is not None:
            body["fileLockEnabled"] = file_lock_enabled
        if default_server_side_encryption is not None:
            body["defaultServerSideEncryption"] = _request_dict(default_server_side_encryption)
        if replication_configuration is not None:
            body["replicationConfiguration"] = _request_dict(replication_configuration)

        url = self._api_url("b2_create_bucket")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return Bucket.from_dict(data)

    async def update_bucket(
        self,
        bucket_id: str,
        bucket_type: Literal[BucketType.ALL_PUBLIC, BucketType.ALL_PRIVATE] | None = None,
        bucket_info: dict[str, Any] | None = None,
        cors_rules: list[CORSRule | dict[str, Any]] | None = None,
        lifecycle_rules: list[LifecycleRule | dict[str, Any]] | None = None,
        default_server_side_encryption: ServerSideEncryptionValue | dict[str, Any] | None = None,
        default_retention: DefaultFileRetentionConfiguration | dict[str, Any] | None = None,
        replication_configuration: ReplicationConfiguration | dict[str, Any] | None = None,
        if_revision_is: int | None = None,
        file_lock_enabled: bool | None = None,
    ) -> Bucket:
        await self.ensure_authorized()
        body: dict[str, Any] = {"accountId": self.account_id, "bucketId": bucket_id}
        if bucket_type is not None:
            body["bucketType"] = bucket_type
        if bucket_info is not None:
            body["bucketInfo"] = bucket_info
        if cors_rules is not None:
            body["corsRules"] = [_request_dict(r) for r in cors_rules]
        if lifecycle_rules is not None:
            body["lifecycleRules"] = [_request_dict(r) for r in lifecycle_rules]
        if default_server_side_encryption is not None:
            body["defaultServerSideEncryption"] = _request_dict(default_server_side_encryption)
        if default_retention is not None:
            body["defaultRetention"] = _request_dict(default_retention)
        if replication_configuration is not None:
            body["replicationConfiguration"] = _request_dict(replication_configuration)
        if file_lock_enabled is not None:
            body["fileLockEnabled"] = file_lock_enabled
        if if_revision_is is not None:
            body["ifRevisionIs"] = if_revision_is

        url = self._api_url("b2_update_bucket")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return Bucket.from_dict(data)

    async def list_file_names(
        self,
        bucket_id: str,
        start_file_name: str | None = None,
        max_file_count: int = 1000,
        prefix: str | None = None,
        delimiter: str | None = None,
    ) -> FileListResponse:
        await self.ensure_authorized()
        params: dict[str, str | int] = {"bucketId": bucket_id, "maxFileCount": max_file_count}
        if start_file_name is not None:
            params["startFileName"] = start_file_name
        if prefix is not None:
            params["prefix"] = prefix
        if delimiter is not None:
            params["delimiter"] = delimiter
        url = self._api_url("b2_list_file_names")
        data = await _get_json(self.session, url, params, self.auth_headers)
        return FileListResponse.from_dict(data)

    async def iter_file_names(
        self, bucket_id: str, prefix: str | None = None, delimiter: str | None = None, page_size: int = 1000
    ) -> AsyncIterator[FileVersion]:
        start = None
        while True:
            page = await self.list_file_names(
                bucket_id, start_file_name=start, max_file_count=page_size, prefix=prefix, delimiter=delimiter
            )
            for f in page.files:
                yield f
            if not page.next_file_name:
                return
            start = page.next_file_name

    async def list_file_versions(
        self,
        bucket_id: str,
        start_file_name: str | None = None,
        start_file_id: str | None = None,
        max_file_count: int = 1000,
        prefix: str | None = None,
        delimiter: str | None = None,
    ) -> FileListResponse:
        await self.ensure_authorized()
        params: dict[str, str | int] = {"bucketId": bucket_id, "maxFileCount": max_file_count}
        if start_file_name is not None:
            params["startFileName"] = start_file_name
        if start_file_id is not None:
            params["startFileId"] = start_file_id
        if prefix is not None:
            params["prefix"] = prefix
        if delimiter is not None:
            params["delimiter"] = delimiter
        url = self._api_url("b2_list_file_versions")
        data = await _get_json(self.session, url, params, self.auth_headers)
        return FileListResponse.from_dict(data)

    async def iter_file_versions(
        self,
        bucket_id: str,
        prefix: str | None = None,
        delimiter: str | None = None,
        page_size: int = 1000,
    ) -> AsyncIterator[FileVersion]:
        start_name: str | None = None
        start_id: str | None = None
        while True:
            page = await self.list_file_versions(
                bucket_id,
                start_file_name=start_name,
                start_file_id=start_id,
                max_file_count=page_size,
                prefix=prefix,
                delimiter=delimiter,
            )
            for f in page.files:
                yield f
            if not page.next_file_name or not page.next_file_id:
                return
            start_name = page.next_file_name
            start_id = page.next_file_id

    async def get_file_info(self, file_id: str) -> FileVersion:
        await self.ensure_authorized()
        url = self._api_url("b2_get_file_info")
        data = await _get_json(self.session, url, {"fileId": file_id}, self.auth_headers)
        return FileVersion.from_dict(data)

    async def list_keys(
        self, max_key_count: int | None = None, start_application_key_id: str | None = None
    ) -> ApplicationKeyListResponse:

        await self.ensure_authorized()
        params: dict[str, str | int] = {"accountId": self.account_id}
        if max_key_count is not None:
            params["maxKeyCount"] = max_key_count
        if start_application_key_id is not None:
            params["startApplicationKeyId"] = start_application_key_id
        url = self._api_url("b2_list_keys")
        data = await _get_json(self.session, url, params, self.auth_headers)
        return ApplicationKeyListResponse.from_dict(data)

    async def iter_keys(self, page_size: int = 100) -> AsyncIterator[ApplicationKey]:
        start_id: str | None = None
        while True:
            page = await self.list_keys(max_key_count=page_size, start_application_key_id=start_id)
            for k in page.keys:
                yield k
            if not page.next_application_key_id:
                return
            start_id = page.next_application_key_id

    async def create_key(
        self,
        key_name: str,
        capabilities: list[Capability],
        valid_duration_in_seconds: int | None = None,
        bucket_ids: list[str] | None = None,
        name_prefix: str | None = None,
    ) -> ApplicationKey:
        await self.ensure_authorized()
        body: dict[str, Any] = {"accountId": self.account_id, "keyName": key_name, "capabilities": capabilities}
        if valid_duration_in_seconds is not None:
            body["validDurationInSeconds"] = valid_duration_in_seconds
        if bucket_ids is not None:
            body["bucketIds"] = bucket_ids
        if name_prefix is not None:
            body["namePrefix"] = name_prefix
        url = self._api_url("b2_create_key")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return ApplicationKey.from_dict(data)

    async def delete_key(self, application_key_id: str) -> ApplicationKey:
        await self.ensure_authorized()
        body = {"applicationKeyId": application_key_id}
        url = self._api_url("b2_delete_key")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return ApplicationKey.from_dict(data)

    async def get_bucket_notification_rules(self, bucket_id: str) -> list[BucketEventNotificationRule]:
        await self.ensure_authorized()
        url = self._api_url("b2_get_bucket_notification_rules")
        data = await _get_json(self.session, url, {"bucketId": bucket_id}, self.auth_headers)
        return [BucketEventNotificationRule.from_dict(r) for r in data.get("eventNotificationRules") or []]

    async def set_bucket_notification_rules(
        self, bucket_id: str, rules: list[BucketEventNotificationRule | dict[str, Any]]
    ) -> list[BucketEventNotificationRule]:
        await self.ensure_authorized()
        body = {"bucketId": bucket_id, "eventNotificationRules": [_request_dict(r) for r in rules]}
        url = self._api_url("b2_set_bucket_notification_rules")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return [BucketEventNotificationRule.from_dict(r) for r in data.get("eventNotificationRules") or []]

    async def get_upload_url(self, bucket_id: str) -> UploadUrl:
        await self.ensure_authorized()
        url = self._api_url("b2_get_upload_url")
        data = await _get_json(self.session, url, {"bucketId": bucket_id}, self.auth_headers)
        return UploadUrl.from_dict(data)

    async def upload_file(
        self,
        upload_url: UploadUrl,
        file_name: str | Path,
        data: bytes | None = None,
        file_path: Path | None = None,
        content_type: str | None = None,
        content_sha1: str | None = None,
        file_info: dict[str, str] | None = None,
        last_modified_millis: int | None = None,
        content_disposition: str | None = None,
        content_language: str | None = None,
        expires: str | None = None,
        cache_control: str | None = None,
        content_encoding: str | None = None,
        custom_upload_timestamp: int | None = None,
        legal_hold: str | None = None,
        retention_mode: str | None = None,
        retention_retain_until_timestamp: int | None = None,
        server_side_encryption: str | None = None,
        sse_c_algorithm: str | None = None,
        sse_c_key_b64: str | None = None,
        sse_c_key_md5_b64: str | None = None,
    ) -> FileVersion:
        if data is None and file_path is None:
            msg = "upload_file requires either data= or file_path="
            raise B2ClientError(msg)
        if data is None and file_path is not None:
            data = file_path.read_bytes()

        assert data is not None

        if content_type is None:
            content_type = _guess_mimetype(file_name)
        if content_sha1 is None:
            content_sha1 = sha1(data).hexdigest()

        headers: dict[str, str] = {
            "Authorization": upload_url.authorization_token,
            "X-Bz-File-Name": _encode_filename(file_name),
            "Content-Type": content_type or _guess_mimetype(file_name),
            "Content-Length": str(len(data)),
            "X-Bz-Content-Sha1": content_sha1,
        }
        if last_modified_millis is not None:
            headers["X-Bz-Info-src_last_modified_millis"] = str(last_modified_millis)
        if content_disposition is not None:
            headers["X-Bz-Info-b2-content-disposition"] = quote(content_disposition, safe="")
        if content_language is not None:
            headers["X-Bz-Info-b2-content-language"] = quote(content_language, safe="")
        if expires is not None:
            headers["X-Bz-Info-b2-expires"] = quote(expires, safe="")
        if cache_control is not None:
            headers["X-Bz-Info-b2-cache-control"] = quote(cache_control, safe="")
        if content_encoding is not None:
            headers["X-Bz-Info-b2-content-encoding"] = quote(content_encoding, safe="")
        if custom_upload_timestamp is not None:
            headers["X-Bz-Custom-Upload-Timestamp"] = str(custom_upload_timestamp)
        if legal_hold is not None:
            headers["X-Bz-File-Legal-Hold"] = legal_hold
        if retention_mode is not None:
            headers["X-Bz-File-Retention-Mode"] = retention_mode
        if retention_retain_until_timestamp is not None:
            headers["X-Bz-File-Retention-Retain-Until-Timestamp"] = str(retention_retain_until_timestamp)
        if server_side_encryption is not None:
            headers["X-Bz-Server-Side-Encryption"] = server_side_encryption
        if sse_c_algorithm is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Algorithm"] = sse_c_algorithm
        if sse_c_key_b64 is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Key"] = sse_c_key_b64
        if sse_c_key_md5_b64 is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Key-Md5"] = sse_c_key_md5_b64
        headers.update(_file_info_headers(file_info))

        resp = await self.session.post(upload_url.upload_url, data=data, headers=headers)
        await raise_if_error(resp)
        return FileVersion.from_dict(resp.json())

    async def delete_file_version(
        self, file_name: str, file_id: str, bypass_governance: bool = False
    ) -> DeletedFileResponse:
        await self.ensure_authorized()
        body: dict[str, Any] = {"fileName": file_name, "fileId": file_id}
        if bypass_governance:
            body["bypassGovernance"] = True
        url = self._api_url("b2_delete_file_version")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return DeletedFileResponse.from_dict(data)

    async def hide_file(self, bucket_id: str, file_name: str) -> FileVersion:
        await self.ensure_authorized()
        body = {"bucketId": bucket_id, "fileName": file_name}
        url = self._api_url("b2_hide_file")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return FileVersion.from_dict(data)

    async def get_download_authorization(
        self,
        bucket_id: str,
        file_name_prefix: str,
        valid_duration_in_seconds: int,
        b2_content_disposition: str | None = None,
        b2_content_language: str | None = None,
        b2_expires: str | None = None,
        b2_cache_control: str | None = None,
        b2_content_encoding: str | None = None,
        b2_content_type: str | None = None,
    ) -> DownloadAuthorization:
        await self.ensure_authorized()
        body: dict[str, Any] = {
            "bucketId": bucket_id,
            "fileNamePrefix": file_name_prefix,
            "validDurationInSeconds": valid_duration_in_seconds,
        }
        if b2_content_disposition is not None:
            body["b2ContentDisposition"] = b2_content_disposition
        if b2_content_language is not None:
            body["b2ContentLanguage"] = b2_content_language
        if b2_expires is not None:
            body["b2Expires"] = b2_expires
        if b2_cache_control is not None:
            body["b2CacheControl"] = b2_cache_control
        if b2_content_encoding is not None:
            body["b2ContentEncoding"] = b2_content_encoding
        if b2_content_type is not None:
            body["b2ContentType"] = b2_content_type

        url = self._api_url("b2_get_download_authorization")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return DownloadAuthorization.from_dict(data)

    def _download_headers(
        self,
        download_auth_token: str | None,
        byte_range: str | None,
        sse_c_algorithm: str | None,
        sse_c_key_b64: str | None,
        sse_c_key_md5_b64: str | None,
    ) -> dict[str, str]:
        headers: dict[str, str] = {"Authorization": download_auth_token or self.auth.token}
        if byte_range is not None:
            headers["Range"] = byte_range
        if sse_c_algorithm is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Algorithm"] = sse_c_algorithm
        if sse_c_key_b64 is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Key"] = sse_c_key_b64
        if sse_c_key_md5_b64 is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Key-Md5"] = sse_c_key_md5_b64
        return headers

    async def download_file_by_id(
        self,
        file_id: str,
        byte_range: str | None = None,
        download_auth_token: str | None = None,
        sse_c_algorithm: str | None = None,
        sse_c_key_b64: str | None = None,
        sse_c_key_md5_b64: str | None = None,
        b2_content_disposition: str | None = None,
        b2_content_language: str | None = None,
        b2_expires: str | None = None,
        b2_cache_control: str | None = None,
        b2_content_encoding: str | None = None,
        b2_content_type: str | None = None,
    ) -> DownloadedFile:
        await self.ensure_authorized()
        url = self._download_url("b2_download_file_by_id")
        headers = self._download_headers(
            download_auth_token=download_auth_token,
            byte_range=byte_range,
            sse_c_algorithm=sse_c_algorithm,
            sse_c_key_b64=sse_c_key_b64,
            sse_c_key_md5_b64=sse_c_key_md5_b64,
        )
        params = _download_params(
            file_id=file_id,
            b2_content_disposition=b2_content_disposition,
            b2_content_language=b2_content_language,
            b2_expires=b2_expires,
            b2_cache_control=b2_cache_control,
            b2_content_encoding=b2_content_encoding,
            b2_content_type=b2_content_type,
        )
        resp = await self.session.get(url, params=params, headers=headers)
        await raise_if_error(resp)
        return DownloadedFile.from_response(resp)

    async def download_file_by_name(
        self,
        bucket_name: str,
        file_name: str,
        byte_range: str | None = None,
        download_auth_token: str | None = None,
        sse_c_algorithm: str | None = None,
        sse_c_key_b64: str | None = None,
        sse_c_key_md5_b64: str | None = None,
        b2_content_disposition: str | None = None,
        b2_content_language: str | None = None,
        b2_expires: str | None = None,
        b2_cache_control: str | None = None,
        b2_content_encoding: str | None = None,
        b2_content_type: str | None = None,
    ) -> DownloadedFile:
        await self.ensure_authorized()
        encoded = quote(file_name, safe="/")
        url = f"{self.auth.download_url}/file/{quote(bucket_name, safe='')}/{encoded}"
        headers = self._download_headers(
            download_auth_token=download_auth_token,
            byte_range=byte_range,
            sse_c_algorithm=sse_c_algorithm,
            sse_c_key_b64=sse_c_key_b64,
            sse_c_key_md5_b64=sse_c_key_md5_b64,
        )
        params = _download_params(
            b2_content_disposition=b2_content_disposition,
            b2_content_language=b2_content_language,
            b2_expires=b2_expires,
            b2_cache_control=b2_cache_control,
            b2_content_encoding=b2_content_encoding,
            b2_content_type=b2_content_type,
        )
        resp = await self.session.get(url, params=params, headers=headers)
        await raise_if_error(resp)
        return DownloadedFile.from_response(resp)

    async def stream_download_by_id(
        self,
        file_id: str,
        destination: Path,
        byte_range: str | None = None,
        download_auth_token: str | None = None,
        chunk_size: int = 1 << 20,
        sse_c_algorithm: str | None = None,
        sse_c_key_b64: str | None = None,
        sse_c_key_md5_b64: str | None = None,
        b2_content_disposition: str | None = None,
        b2_content_language: str | None = None,
        b2_expires: str | None = None,
        b2_cache_control: str | None = None,
        b2_content_encoding: str | None = None,
        b2_content_type: str | None = None,
    ) -> Path:
        await self.ensure_authorized()
        url = self._download_url("b2_download_file_by_id")
        headers = self._download_headers(
            download_auth_token=download_auth_token,
            byte_range=byte_range,
            sse_c_algorithm=sse_c_algorithm,
            sse_c_key_b64=sse_c_key_b64,
            sse_c_key_md5_b64=sse_c_key_md5_b64,
        )
        params = _download_params(
            file_id=file_id,
            b2_content_disposition=b2_content_disposition,
            b2_content_language=b2_content_language,
            b2_expires=b2_expires,
            b2_cache_control=b2_cache_control,
            b2_content_encoding=b2_content_encoding,
            b2_content_type=b2_content_type,
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        resp = await self.session.get(url, params=params, headers=headers, stream=True)
        await _write_stream_to_path(resp, destination, chunk_size)
        return destination

    async def stream_download_by_name(
        self,
        bucket_name: str,
        file_name: str,
        destination: Path,
        byte_range: str | None = None,
        download_auth_token: str | None = None,
        chunk_size: int = 1 << 20,
        sse_c_algorithm: str | None = None,
        sse_c_key_b64: str | None = None,
        sse_c_key_md5_b64: str | None = None,
        b2_content_disposition: str | None = None,
        b2_content_language: str | None = None,
        b2_expires: str | None = None,
        b2_cache_control: str | None = None,
        b2_content_encoding: str | None = None,
        b2_content_type: str | None = None,
    ) -> Path:
        await self.ensure_authorized()
        encoded = quote(file_name, safe="/")
        url = f"{self.auth.download_url}/file/{quote(bucket_name, safe='')}/{encoded}"
        headers = self._download_headers(
            download_auth_token=download_auth_token,
            byte_range=byte_range,
            sse_c_algorithm=sse_c_algorithm,
            sse_c_key_b64=sse_c_key_b64,
            sse_c_key_md5_b64=sse_c_key_md5_b64,
        )
        params = _download_params(
            b2_content_disposition=b2_content_disposition,
            b2_content_language=b2_content_language,
            b2_expires=b2_expires,
            b2_cache_control=b2_cache_control,
            b2_content_encoding=b2_content_encoding,
            b2_content_type=b2_content_type,
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        resp = await self.session.get(url, params=params, headers=headers, stream=True)
        await _write_stream_to_path(resp, destination, chunk_size)
        return destination

    async def start_large_file(
        self,
        bucket_id: str,
        file_name: str | Path,
        content_type: str | None = None,
        file_info: dict[str, str] | None = None,
        custom_upload_timestamp: int | None = None,
        legal_hold: str | None = None,
        file_retention: FileRetentionValue | dict[str, Any] | None = None,
        server_side_encryption: (
            ServerSideEncryptionValue | RemoteServerSideEncryptionConfiguration | dict[str, Any] | None
        ) = None,
    ) -> FileVersion:
        await self.ensure_authorized()

        if content_type is None:
            content_type = _guess_mimetype(file_name)

        body: dict[str, Any] = {
            "bucketId": bucket_id,
            "fileName": file_name.as_posix() if isinstance(file_name, Path) else file_name,
            "contentType": content_type,
        }
        if file_info is not None:
            body["fileInfo"] = file_info
        if custom_upload_timestamp is not None:
            body["customUploadTimestamp"] = custom_upload_timestamp
        if legal_hold is not None:
            body["legalHold"] = legal_hold
        if file_retention is not None:
            body["fileRetention"] = _request_dict(file_retention)
        if server_side_encryption is not None:
            body["serverSideEncryption"] = _request_dict(server_side_encryption)
        url = self._api_url("b2_start_large_file")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return FileVersion.from_dict(data)

    async def get_upload_part_url(self, file_id: str) -> UploadPartUrl:
        await self.ensure_authorized()
        url = self._api_url("b2_get_upload_part_url")
        data = await _get_json(self.session, url, {"fileId": file_id}, self.auth_headers)
        return UploadPartUrl.from_dict(data)

    async def upload_part(
        self,
        upload_part_url: UploadPartUrl,
        part_number: int,
        data: bytes,
        content_sha1: str | None = None,
        sse_c_algorithm: str | None = None,
        sse_c_key_b64: str | None = None,
        sse_c_key_md5_b64: str | None = None,
    ) -> Part:
        if content_sha1 is None:
            content_sha1 = sha1(data).hexdigest()

        headers = {
            "Authorization": upload_part_url.authorization_token,
            "X-Bz-Part-Number": str(part_number),
            "Content-Length": str(len(data)),
            "X-Bz-Content-Sha1": content_sha1,
        }
        if sse_c_algorithm is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Algorithm"] = sse_c_algorithm
        if sse_c_key_b64 is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Key"] = sse_c_key_b64
        if sse_c_key_md5_b64 is not None:
            headers["X-Bz-Server-Side-Encryption-Customer-Key-Md5"] = sse_c_key_md5_b64

        resp = await self.session.post(upload_part_url.upload_url, data=data, headers=headers)
        await raise_if_error(resp)
        return Part.from_dict(resp.json())

    async def copy_part(
        self,
        source_file_id: str,
        large_file_id: str,
        part_number: int,
        byte_range: str | None = None,
        source_server_side_encryption: RemoteServerSideEncryptionConfiguration | dict[str, Any] | None = None,
        destination_server_side_encryption: (
            ServerSideEncryptionValue | RemoteServerSideEncryptionConfiguration | dict[str, Any] | None
        ) = None,
    ) -> Part:
        await self.ensure_authorized()
        body: dict[str, Any] = {"sourceFileId": source_file_id, "largeFileId": large_file_id, "partNumber": part_number}
        if byte_range is not None:
            body["range"] = byte_range
        if source_server_side_encryption is not None:
            body["sourceServerSideEncryption"] = _request_dict(source_server_side_encryption)
        if destination_server_side_encryption is not None:
            body["destinationServerSideEncryption"] = _request_dict(destination_server_side_encryption)
        url = self._api_url("b2_copy_part")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return Part.from_dict(data)

    async def finish_large_file(self, file_id: str, part_sha1_array: list[str]) -> FileVersion:
        await self.ensure_authorized()
        body = {"fileId": file_id, "partSha1Array": part_sha1_array}
        url = self._api_url("b2_finish_large_file")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return FileVersion.from_dict(data)

    async def cancel_large_file(self, file_id: str) -> dict[str, str]:
        await self.ensure_authorized()
        body = {"fileId": file_id}
        url = self._api_url("b2_cancel_large_file")
        return await _post_json(self.session, url, body, self.auth_headers)

    async def list_parts(
        self, file_id: str, start_part_number: int | None = None, max_part_count: int = 1000
    ) -> PartsListPage:
        await self.ensure_authorized()
        params: dict[str, Any] = {"fileId": file_id, "maxPartCount": max_part_count}
        if start_part_number is not None:
            params["startPartNumber"] = start_part_number
        url = self._api_url("b2_list_parts")
        data = await _get_json(self.session, url, params, self.auth_headers)
        return PartsListPage.from_dict(data)

    async def iter_parts(self, file_id: str, *, page_size: int = 1000) -> AsyncIterator[Part]:
        start: int | None = None
        while True:
            page = await self.list_parts(file_id, start_part_number=start, max_part_count=page_size)
            for p in page.parts:
                yield p
            if page.next_part_number is None:
                return
            start = page.next_part_number

    async def list_unfinished_large_files(
        self,
        bucket_id: str,
        name_prefix: str | None = None,
        start_file_id: str | None = None,
        max_file_count: int = 100,
    ) -> FileListResponse:
        await self.ensure_authorized()
        params: dict[str, Any] = {"bucketId": bucket_id, "maxFileCount": max_file_count}
        if name_prefix is not None:
            params["namePrefix"] = name_prefix
        if start_file_id is not None:
            params["startFileId"] = start_file_id
        url = self._api_url("b2_list_unfinished_large_files")
        data = await _get_json(self.session, url, params, self.auth_headers)
        page = FileListResponse.from_dict(data)
        page.next_file_id = data.get("nextFileId")
        return page

    async def iter_unfinished_large_files(
        self,
        bucket_id: str,
        *,
        name_prefix: str | None = None,
        page_size: int = 100,
    ) -> AsyncIterator[FileVersion]:
        start: str | None = None
        while True:
            page = await self.list_unfinished_large_files(
                bucket_id,
                name_prefix=name_prefix,
                start_file_id=start,
                max_file_count=page_size,
            )
            for f in page.files:
                yield f
            if not page.next_file_id:
                return
            start = page.next_file_id

    async def copy_file(
        self,
        source_file_id: str,
        new_file_name: str,
        *,
        destination_bucket_id: str | None = None,
        byte_range: str | None = None,
        metadata_directive: str | None = None,
        content_type: str | None = None,
        file_info: dict[str, str] | None = None,
        file_retention: FileRetentionValue | dict[str, Any] | None = None,
        legal_hold: str | None = None,
        source_server_side_encryption: RemoteServerSideEncryptionConfiguration | dict[str, Any] | None = None,
        destination_server_side_encryption: (
            ServerSideEncryptionValue | RemoteServerSideEncryptionConfiguration | dict[str, Any] | None
        ) = None,
    ) -> FileVersion:
        await self.ensure_authorized()
        body: dict[str, Any] = {"sourceFileId": source_file_id, "fileName": new_file_name}
        if destination_bucket_id is not None:
            body["destinationBucketId"] = destination_bucket_id
        if byte_range is not None:
            body["range"] = byte_range
        if metadata_directive is not None:
            body["metadataDirective"] = metadata_directive
        if content_type is not None:
            body["contentType"] = content_type
        if file_info is not None:
            body["fileInfo"] = file_info
        if file_retention is not None:
            body["fileRetention"] = _request_dict(file_retention)
        if legal_hold is not None:
            body["legalHold"] = legal_hold
        if source_server_side_encryption is not None:
            body["sourceServerSideEncryption"] = _request_dict(source_server_side_encryption)
        if destination_server_side_encryption is not None:
            body["destinationServerSideEncryption"] = _request_dict(destination_server_side_encryption)

        url = self._api_url("b2_copy_file")
        data = await _post_json(self.session, url, body, self.auth_headers)
        return FileVersion.from_dict(data)

    async def update_file_legal_hold(
        self, file_name: str, file_id: str, legal_hold: Literal["on", "off"]
    ) -> dict[str, Any]:
        await self.ensure_authorized()
        body = {"fileName": file_name, "fileId": file_id, "legalHold": legal_hold}
        url = self._api_url("b2_update_file_legal_hold")
        return await _post_json(self.session, url, body, self.auth_headers)

    async def update_file_retention(
        self,
        file_name: str,
        file_id: str,
        file_retention: FileRetentionValue | dict[str, Any],
        bypass_governance: bool = False,
    ) -> dict[str, Any]:
        await self.ensure_authorized()
        body: dict[str, Any] = {
            "fileName": file_name,
            "fileId": file_id,
            "fileRetention": _request_dict(file_retention),
        }
        if bypass_governance:
            body["bypassGovernance"] = True
        url = self._api_url("b2_update_file_retention")
        return await _post_json(self.session, url, body, self.auth_headers)
