from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from b2py.enums import (
    BucketType,
    Capability,
    CORSRuleOperation,
    FileAction,
    FileReplicationStatus,
    FileRetentionMode,
    LegalHoldStatus,
)

if TYPE_CHECKING:
    from niquests import Response


@dataclass
class AllowedBucket:
    id: str
    name: str | None

    @classmethod
    def from_dict(cls, data: dict) -> AllowedBucket:
        return cls(id=data["id"], name=data.get("name"))


@dataclass
class AllowedRestrictions:
    buckets: list[AllowedBucket] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    name_prefix: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> AllowedRestrictions:
        buckets = [AllowedBucket.from_dict(bucket) for bucket in data.get("buckets") or []]
        capabilities = [Capability.from_str(cap) for cap in data.get("capabilities") or []]
        return cls(buckets=buckets, capabilities=capabilities, name_prefix=data.get("namePrefix"))


@dataclass
class StorageApiInfo:
    absolute_minimum_part_size: int
    allowed_restrictions: AllowedRestrictions
    api_url: str
    download_url: str
    recommended_part_size: int
    s3_api_url: str

    @classmethod
    def from_dict(cls, data: dict) -> StorageApiInfo:
        return cls(
            absolute_minimum_part_size=data["absoluteMinimumPartSize"],
            allowed_restrictions=AllowedRestrictions.from_dict(data["allowed"]),
            api_url=data["apiUrl"],
            download_url=data["downloadUrl"],
            recommended_part_size=data["recommendedPartSize"],
            s3_api_url=data["s3ApiUrl"],
        )


@dataclass
class ApiInfo:
    storage_api: StorageApiInfo

    @classmethod
    def from_dict(cls, data: dict) -> ApiInfo:
        return cls(storage_api=StorageApiInfo.from_dict(data["storageApi"]))


@dataclass
class AuthorizeAccountResponse:
    account_id: str
    authorization_token: str
    api_info: ApiInfo
    application_key_expiration_timestamp: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> AuthorizeAccountResponse:
        return cls(
            account_id=data["accountId"],
            application_key_expiration_timestamp=data.get("applicationKeyExpirationTimestamp"),
            authorization_token=data["authorizationToken"],
            api_info=ApiInfo.from_dict(data["apiInfo"]),
        )


# https://www.backblaze.com/docs/cloud-storage-cross-origin-resource-sharing-rules
@dataclass
class CORSRule:
    rule_name: str
    allowed_origins: list[str]
    allowed_operations: list[CORSRuleOperation]
    max_age_seconds: int
    allowed_headers: list[str] = field(default_factory=list)
    expose_headers: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> CORSRule:
        return cls(
            rule_name=data["corsRuleName"],
            allowed_origins=data["allowedOrigins"],
            allowed_operations=[CORSRuleOperation.from_str(op) for op in data["allowedOperations"]],
            max_age_seconds=data["maxAgeSeconds"],
            allowed_headers=data.get("allowedHeaders", []),
            expose_headers=data.get("exposeHeaders", []),
        )

    def to_dict(self) -> dict[str, str | int | list[str]]:
        out: dict[str, str | int | list[str]] = {
            "corsRuleName": self.rule_name,
            "allowedOrigins": self.allowed_origins,
            "allowedOperations": [op.value for op in self.allowed_operations],
            "maxAgeSeconds": self.max_age_seconds,
        }
        if self.allowed_headers:
            out["allowedHeaders"] = self.allowed_headers
        if self.expose_headers:
            out["exposeHeaders"] = self.expose_headers
        return out


@dataclass
class FileRetentionPeriod:
    duration: int
    unit: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRetentionPeriod:
        return cls(duration=int(data["duration"]), unit=str(data["unit"]))

    def to_dict(self) -> dict[str, str | int]:
        return {"duration": self.duration, "unit": self.unit}


@dataclass
class DefaultFileRetentionConfiguration:
    mode: str | None
    period: FileRetentionPeriod | None

    @classmethod
    def from_dict(cls, data: dict) -> DefaultFileRetentionConfiguration:
        period = data.get("period")
        return cls(
            mode=data.get("mode"),
            period=FileRetentionPeriod.from_dict(period) if period is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "period": self.period.to_dict() if self.period is not None else None}

    def to_request_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mode": self.mode}
        if self.period is not None:
            out["period"] = self.period.to_dict()
        return out


@dataclass
class FileLockValue:
    default_retention: DefaultFileRetentionConfiguration | None
    is_file_lock_enabled: bool

    @classmethod
    def from_dict(cls, data: dict) -> FileLockValue:
        return cls(
            default_retention=(
                DefaultFileRetentionConfiguration.from_dict(data["defaultRetention"])
                if data.get("defaultRetention")
                else None
            ),
            is_file_lock_enabled=data["isFileLockEnabled"],
        )


# https://www.backblaze.com/docs/en/cloud-storage-object-lock
# readBucketRetentions capability required to read value
@dataclass
class FileLockConfiguration:
    is_client_authorized_to_read: bool
    value: FileLockValue | None = None

    @classmethod
    def from_dict(cls, data: dict) -> FileLockConfiguration:
        return cls(
            is_client_authorized_to_read=data["isClientAuthorizedToRead"],
            value=FileLockValue.from_dict(data["value"]) if data.get("value") else None,
        )


@dataclass
class ServerSideEncryptionValue:
    algorithm: str | None
    mode: str | None

    @classmethod
    def from_dict(cls, data: dict) -> ServerSideEncryptionValue:
        return cls(algorithm=data.get("algorithm"), mode=data.get("mode"))

    def to_dict(self) -> dict[str, str | None]:
        return {"algorithm": self.algorithm, "mode": self.mode}

    def to_request_dict(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {"mode": self.mode}
        if self.algorithm is not None:
            out["algorithm"] = self.algorithm
        return out


@dataclass
class RemoteServerSideEncryptionConfiguration:
    mode: str
    algorithm: str
    customer_key: str | None = None
    customer_key_md5: str | None = None

    def to_dict(self) -> dict[str, str]:
        out = {"mode": self.mode, "algorithm": self.algorithm}
        if self.customer_key is not None:
            out["customerKey"] = self.customer_key
        if self.customer_key_md5 is not None:
            out["customerKeyMd5"] = self.customer_key_md5
        return out


# https://www.backblaze.com/docs/en/cloud-storage-server-side-encryption
# readBucketEncryption capability required to read value
@dataclass
class DefaultServerSideEncryptionConfiguration:
    is_client_authorized_to_read: bool
    value: ServerSideEncryptionValue | None = None

    @classmethod
    def from_dict(cls, data: dict) -> DefaultServerSideEncryptionConfiguration:
        value = data.get("value")
        return cls(
            is_client_authorized_to_read=data["isClientAuthorizedToRead"],
            value=ServerSideEncryptionValue.from_dict(value) if isinstance(value, dict) else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "isClientAuthorizedToRead": self.is_client_authorized_to_read,
            "value": self.value.to_dict() if self.value is not None else None,
        }


# https://www.backblaze.com/docs/cloud-storage-lifecycle-rules
@dataclass
class LifecycleRule:
    file_name_prefix: str
    days_from_uploading_to_hiding: int | None = None
    days_from_hiding_to_deleting: int | None = None
    days_from_starting_to_canceling_unfinished_large_files: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> LifecycleRule:
        return cls(
            file_name_prefix=data["fileNamePrefix"],
            days_from_uploading_to_hiding=data.get("daysFromUploadingToHiding"),
            days_from_hiding_to_deleting=data.get("daysFromHidingToDeleting"),
            days_from_starting_to_canceling_unfinished_large_files=data.get(
                "daysFromStartingToCancelingUnfinishedLargeFiles"
            ),
        )

    def to_dict(self) -> dict[str, str | int]:
        out: dict[str, str | int] = {"fileNamePrefix": self.file_name_prefix}
        if self.days_from_uploading_to_hiding is not None:
            out["daysFromUploadingToHiding"] = self.days_from_uploading_to_hiding
        if self.days_from_hiding_to_deleting is not None:
            out["daysFromHidingToDeleting"] = self.days_from_hiding_to_deleting
        if self.days_from_starting_to_canceling_unfinished_large_files is not None:
            out["daysFromStartingToCancelingUnfinishedLargeFiles"] = (
                self.days_from_starting_to_canceling_unfinished_large_files
            )
        return out


@dataclass
class ReplicationRule:
    destination_bucket_id: str
    file_name_prefix: str
    include_existing_files: bool
    is_enabled: bool
    priority: int
    replication_rule_name: str

    @classmethod
    def from_dict(cls, data: dict) -> ReplicationRule:
        return cls(
            destination_bucket_id=data["destinationBucketId"],
            file_name_prefix=data["fileNamePrefix"],
            include_existing_files=data["includeExistingFiles"],
            is_enabled=data["isEnabled"],
            priority=data["priority"],
            replication_rule_name=data["replicationRuleName"],
        )

    def to_dict(self) -> dict[str, str | int | bool]:
        return {
            "destinationBucketId": self.destination_bucket_id,
            "fileNamePrefix": self.file_name_prefix,
            "includeExistingFiles": self.include_existing_files,
            "isEnabled": self.is_enabled,
            "priority": self.priority,
            "replicationRuleName": self.replication_rule_name,
        }


@dataclass
class AsReplicationSource:
    replication_rules: list[ReplicationRule] = field(default_factory=list)
    source_application_key_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> AsReplicationSource:
        replication_rules = [ReplicationRule.from_dict(rule) for rule in data.get("replicationRules") or []]
        return cls(
            replication_rules=replication_rules,
            source_application_key_id=data.get("sourceApplicationKeyId"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"replicationRules": [rule.to_dict() for rule in self.replication_rules]}
        if self.source_application_key_id is not None:
            out["sourceApplicationKeyId"] = self.source_application_key_id
        return out


@dataclass
class AsReplicationDestination:
    source_to_destination_key_mapping: dict[str, str]

    @classmethod
    def from_dict(cls, data: dict) -> AsReplicationDestination:
        return cls(source_to_destination_key_mapping=dict(data["sourceToDestinationKeyMapping"]))

    def to_dict(self) -> dict[str, dict[str, str]]:
        return {"sourceToDestinationKeyMapping": self.source_to_destination_key_mapping}


# https://www.backblaze.com/docs/cloud-storage-create-a-cloud-replication-rule-with-the-native-api#file-name-prefixes
@dataclass
class ReplicationConfiguration:
    as_replication_source: AsReplicationSource | None = None
    as_replication_destination: AsReplicationDestination | None = None
    is_client_authorized_to_read: bool | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ReplicationConfiguration:
        is_client_authorized_to_read = data.get("isClientAuthorizedToRead")
        value = data.get("value") if "value" in data else data
        if not isinstance(value, dict):
            return cls(is_client_authorized_to_read=is_client_authorized_to_read)
        return cls(
            as_replication_source=AsReplicationSource.from_dict(value["asReplicationSource"])
            if value.get("asReplicationSource")
            else None,
            as_replication_destination=AsReplicationDestination.from_dict(value["asReplicationDestination"])
            if value.get("asReplicationDestination")
            else None,
            is_client_authorized_to_read=is_client_authorized_to_read,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.as_replication_source is not None:
            out["asReplicationSource"] = self.as_replication_source.to_dict()
        if self.as_replication_destination is not None:
            out["asReplicationDestination"] = self.as_replication_destination.to_dict()
        return out


@dataclass
class Bucket:
    account_id: str
    bucket_id: str
    bucket_name: str
    bucket_type: BucketType
    bucket_info: dict[str, Any]
    revision: int
    cors_rules: list[CORSRule] = field(default_factory=list)
    file_lock_configuration: FileLockConfiguration | None = None
    default_server_side_encryption_configuration: DefaultServerSideEncryptionConfiguration | None = None
    lifecycle_rules: list[LifecycleRule] = field(default_factory=list)
    replication_configuration: ReplicationConfiguration | None = None
    options: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> Bucket:
        cors_rules = [CORSRule.from_dict(rule) for rule in data.get("corsRules", [])]
        file_lock_configuration = (
            FileLockConfiguration.from_dict(data["fileLockConfiguration"])
            if data.get("fileLockConfiguration")
            else None
        )
        default_sse = data.get("defaultServerSideEncryption")
        default_server_side_encryption_configuration = (
            DefaultServerSideEncryptionConfiguration.from_dict(default_sse) if default_sse is not None else None
        )
        lifecycle_rules = [LifecycleRule.from_dict(rule) for rule in data.get("lifecycleRules", [])]
        replication_configuration = (
            ReplicationConfiguration.from_dict(data["replicationConfiguration"])
            if data.get("replicationConfiguration")
            else None
        )
        return cls(
            account_id=data["accountId"],
            bucket_id=data["bucketId"],
            bucket_name=data["bucketName"],
            bucket_type=BucketType.from_str(data["bucketType"]),
            bucket_info=data.get("bucketInfo", {}),
            revision=int(data["revision"]),
            cors_rules=cors_rules,
            file_lock_configuration=file_lock_configuration,
            default_server_side_encryption_configuration=default_server_side_encryption_configuration,
            lifecycle_rules=lifecycle_rules,
            replication_configuration=replication_configuration,
            options=data.get("options") or [],
        )


@dataclass
class FileRetentionValue:
    mode: FileRetentionMode | None
    retain_until_timestamp: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> FileRetentionValue:
        mode = data.get("mode")
        retain_until_timestamp = data.get("retainUntilTimestamp")
        return cls(
            mode=FileRetentionMode.from_str(mode) if mode is not None else None,
            retain_until_timestamp=(int(retain_until_timestamp) if retain_until_timestamp is not None else None),
        )

    def to_dict(self) -> dict[str, str | int | None]:
        return {
            "mode": self.mode.value if self.mode is not None else None,
            "retainUntilTimestamp": self.retain_until_timestamp,
        }

    def to_request_dict(self) -> dict[str, str | int | None]:
        out: dict[str, str | int | None] = {"mode": self.mode.value if self.mode is not None else None}
        if self.retain_until_timestamp is not None:
            out["retainUntilTimestamp"] = self.retain_until_timestamp
        return out


@dataclass
class FileRetention:
    is_client_authorized_to_read: bool
    value: FileRetentionValue | None = None

    @classmethod
    def from_dict(cls, data: dict) -> FileRetention:
        value = data.get("value")
        return cls(
            is_client_authorized_to_read=data["isClientAuthorizedToRead"],
            value=FileRetentionValue.from_dict(value) if isinstance(value, dict) else None,
        )


@dataclass
class FileLegalHold:
    is_client_authorized_to_read: bool
    value: LegalHoldStatus | None

    @classmethod
    def from_dict(cls, data: dict) -> FileLegalHold:
        return cls(
            is_client_authorized_to_read=data["isClientAuthorizedToRead"],
            value=LegalHoldStatus.from_str(data["value"]) if data.get("value") is not None else None,
        )


@dataclass
class FileServerSideEncryptionStatus:
    algorithm: str | None = None
    mode: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> FileServerSideEncryptionStatus:
        return cls(algorithm=data.get("algorithm"), mode=data.get("mode"))


@dataclass
class FileVersion:
    account_id: str
    action: FileAction
    bucket_id: str
    content_length: int
    file_info: dict[str, Any]
    file_name: str
    upload_timestamp: int
    content_sha1: str | None = None
    content_md5: str | None = None
    content_type: str | None = None
    file_id: str | None = None
    file_retention: FileRetention | None = None
    legal_hold: FileLegalHold | None = None
    replication_status: FileReplicationStatus | None = None
    server_side_encryption: ServerSideEncryptionValue | None = None

    @classmethod
    def from_dict(cls, data: dict) -> FileVersion:
        file_retention = FileRetention.from_dict(data["fileRetention"]) if data.get("fileRetention") else None
        legal_hold = FileLegalHold.from_dict(data["legalHold"]) if data.get("legalHold") else None
        replication_status = (
            FileReplicationStatus.from_str(data["replicationStatus"]) if data.get("replicationStatus") else None
        )
        server_side_encryption_data = data.get("serverSideEncryption")
        server_side_encryption = (
            ServerSideEncryptionValue.from_dict(server_side_encryption_data)
            if isinstance(server_side_encryption_data, dict)
            else None
        )
        return cls(
            account_id=data["accountId"],
            action=FileAction.from_str(data["action"]),
            bucket_id=data["bucketId"],
            content_length=int(data["contentLength"]),
            content_sha1=data.get("contentSha1"),
            content_md5=data.get("contentMd5"),
            content_type=data.get("contentType"),
            file_id=data.get("fileId"),
            file_info=data.get("fileInfo", {}),
            file_name=data["fileName"],
            file_retention=file_retention,
            legal_hold=legal_hold,
            replication_status=replication_status,
            server_side_encryption=server_side_encryption,
            upload_timestamp=int(data["uploadTimestamp"]),
        )


@dataclass
class FileListResponse:
    files: list[FileVersion] = field(default_factory=list)
    next_file_name: str | None = None  # both list_file_names and list_file_versions
    next_file_id: str | None = None  # only for list_file_versions endpoint

    @classmethod
    def from_dict(cls, data: dict) -> FileListResponse:
        files = [FileVersion.from_dict(file) for file in data.get("files", [])]
        return cls(files=files, next_file_name=data.get("nextFileName"), next_file_id=data.get("nextFileId"))


@dataclass
class ApplicationKey:
    account_id: str
    application_key_id: str
    bucket_ids: list[str]
    capabilities: list[Capability]
    key_name: str
    expiration_timestamp: int | None = None
    name_prefix: str | None = None
    options: list[str] = field(default_factory=list)
    application_key: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ApplicationKey:
        return cls(
            account_id=data["accountId"],
            application_key_id=data["applicationKeyId"],
            bucket_ids=data.get("bucketIds") or [],
            capabilities=[Capability.from_str(cap) for cap in data.get("capabilities", [])],
            expiration_timestamp=(
                int(data["expirationTimestamp"]) if data.get("expirationTimestamp") is not None else None
            ),
            key_name=data["keyName"],
            name_prefix=data.get("namePrefix"),
            options=data.get("options", []),
            application_key=data.get("applicationKey"),
        )


@dataclass
class ApplicationKeyListResponse:
    keys: list[ApplicationKey] = field(default_factory=list)
    next_application_key_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ApplicationKeyListResponse:
        keys = [ApplicationKey.from_dict(key) for key in data.get("keys", [])]
        return cls(keys=keys, next_application_key_id=data.get("nextApplicationKeyId"))


@dataclass
class BucketEventNotificationCustomHeader:
    name: str
    value: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BucketEventNotificationCustomHeader:
        return cls(name=str(data["name"]), value=str(data["value"]))

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


# https://www.backblaze.com/apidocs/b2-get-bucket-notification-rules
@dataclass
class BucketEventNotificationTargetConfiguration:
    target_type: str
    url: str
    custom_headers: list[BucketEventNotificationCustomHeader] | None = None
    hmac_sha256_signing_secret: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> BucketEventNotificationTargetConfiguration:
        return cls(
            target_type=data["targetType"],
            url=data["url"],
            custom_headers=[
                BucketEventNotificationCustomHeader.from_dict(header) for header in (data.get("customHeaders") or [])
            ]
            or None,
            hmac_sha256_signing_secret=data.get("hmacSha256SigningSecret"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"targetType": self.target_type, "url": self.url}
        if self.custom_headers is not None:
            out["customHeaders"] = [header.to_dict() for header in self.custom_headers]
        if self.hmac_sha256_signing_secret is not None:
            out["hmacSha256SigningSecret"] = self.hmac_sha256_signing_secret
        return out


@dataclass
class BucketEventNotificationRule:
    name: str
    event_types: list[str]
    object_name_prefix: str
    is_enabled: bool
    target_configuration: BucketEventNotificationTargetConfiguration
    is_suspended: bool | None = None
    suspension_reason: str | None = None
    max_events_per_batch: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> BucketEventNotificationRule:
        target_configuration = BucketEventNotificationTargetConfiguration.from_dict(data["targetConfiguration"])
        return cls(
            name=data["name"],
            event_types=data["eventTypes"],
            object_name_prefix=data["objectNamePrefix"],
            is_enabled=data["isEnabled"],
            target_configuration=target_configuration,
            is_suspended=data.get("isSuspended"),
            suspension_reason=data.get("suspensionReason"),
            max_events_per_batch=data.get("maxEventsPerBatch"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "eventTypes": self.event_types,
            "objectNamePrefix": self.object_name_prefix,
            "isEnabled": self.is_enabled,
            "targetConfiguration": self.target_configuration.to_dict(),
        }
        if self.is_suspended is not None:
            out["isSuspended"] = self.is_suspended
        if self.suspension_reason is not None:
            out["suspensionReason"] = self.suspension_reason
        if self.max_events_per_batch is not None:
            out["maxEventsPerBatch"] = self.max_events_per_batch
        return out

    def to_request_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "eventTypes": self.event_types,
            "objectNamePrefix": self.object_name_prefix,
            "isEnabled": self.is_enabled,
            "targetConfiguration": self.target_configuration.to_dict(),
        }
        if self.max_events_per_batch is not None:
            out["maxEventsPerBatch"] = self.max_events_per_batch
        return out


@dataclass
class UploadUrl:
    bucket_id: str
    upload_url: str
    authorization_token: str

    @classmethod
    def from_dict(cls, data: dict) -> UploadUrl:
        return cls(
            bucket_id=data["bucketId"], upload_url=data["uploadUrl"], authorization_token=data["authorizationToken"]
        )


@dataclass
class UploadPartUrl:
    file_id: str
    upload_url: str
    authorization_token: str

    @classmethod
    def from_dict(cls, data: dict) -> UploadPartUrl:
        return cls(file_id=data["fileId"], upload_url=data["uploadUrl"], authorization_token=data["authorizationToken"])


@dataclass
class DeletedFileResponse:
    file_id: str
    file_name: str

    @classmethod
    def from_dict(cls, data: dict) -> DeletedFileResponse:
        return cls(file_id=data["fileId"], file_name=data["fileName"])


@dataclass
class DownloadAuthorization:
    bucket_id: str
    file_name_prefix: str
    authorization_token: str

    @classmethod
    def from_dict(cls, data: dict) -> DownloadAuthorization:
        return cls(
            bucket_id=data["bucketId"],
            file_name_prefix=data["fileNamePrefix"],
            authorization_token=data["authorizationToken"],
        )


@dataclass
class DownloadedFile:
    content: bytes
    file_id: str
    file_name: str
    content_length: int
    content_type: str
    content_sha1: str | None = None
    file_info: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_response(cls, response: Response) -> DownloadedFile:
        file_info: dict[str, str] = {}
        for k, v in response.headers.items():
            kl = k.lower()
            if kl.startswith("x-bz-info-"):
                file_info[k[len("X-Bz-Info-") :]] = unquote(v)

        return DownloadedFile(
            content=response.content,  # type: ignore[reportArgumentType]
            file_id=response.headers["X-Bz-File-Id"],
            file_name=unquote(response.headers["X-Bz-File-Name"]),
            content_length=int(response.headers["Content-Length"]),
            content_type=response.headers["Content-Type"],
            content_sha1=response.headers.get("X-Bz-Content-Sha1"),
            file_info=file_info,
            headers=dict(response.headers),
        )


@dataclass
class Part:
    file_id: str
    part_number: int
    content_length: int
    content_sha1: str
    content_md5: str | None = None
    upload_timestamp: int | None = None
    server_side_encryption: ServerSideEncryptionValue | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Part:
        server_side_encryption_data = data.get("serverSideEncryption")
        server_side_encryption = (
            ServerSideEncryptionValue.from_dict(server_side_encryption_data)
            if isinstance(server_side_encryption_data, dict)
            else None
        )
        return cls(
            file_id=data["fileId"],
            part_number=int(data["partNumber"]),
            content_length=int(data["contentLength"]),
            content_sha1=data.get("contentSha1", ""),
            content_md5=data.get("contentMd5"),
            upload_timestamp=data.get("uploadTimestamp"),
            server_side_encryption=server_side_encryption,
        )


@dataclass
class PartsListPage:
    parts: list[Part]
    next_part_number: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PartsListPage:
        return cls(
            parts=[Part.from_dict(p) for p in (data.get("parts") or [])],
            next_part_number=data.get("nextPartNumber"),
        )
