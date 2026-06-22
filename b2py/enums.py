from __future__ import annotations

import logging
from enum import StrEnum
from typing import Self, cast

logger = logging.getLogger(__name__)


class UnknownStrEnum(StrEnum):
    @classmethod
    def _missing_(cls, value: object) -> Self | None:
        unknown = cls.__members__.get("UNKNOWN")

        if unknown is None:
            return None

        logger.warning("Unknown %s: %r", cls.__name__, value)
        return cast("Self", unknown)

    @classmethod
    def from_str(cls, value: str) -> Self:
        return cls(value)


class Capability(UnknownStrEnum):
    BYPASS_GOVERNANCE = "bypassGovernance"
    DELETE_BUCKETS = "deleteBuckets"
    DELETE_FILES = "deleteFiles"
    DELETE_KEYS = "deleteKeys"
    LIST_ALL_BUCKET_NAMES = "listAllBucketNames"
    LIST_BUCKETS = "listBuckets"
    LIST_FILES = "listFiles"
    LIST_KEYS = "listKeys"
    READ_BUCKET_ENCRYPTION = "readBucketEncryption"
    READ_BUCKET_LIFECYCLE_RULES = "readBucketLifecycleRules"
    READ_BUCKET_LOGGING = "readBucketLogging"
    READ_BUCKET_NOTIFICATIONS = "readBucketNotifications"
    READ_BUCKET_REPLICATIONS = "readBucketReplications"
    READ_BUCKET_RETENTIONS = "readBucketRetentions"
    READ_BUCKETS = "readBuckets"
    READ_FILE_LEGAL_HOLDS = "readFileLegalHolds"
    READ_FILE_RETENTIONS = "readFileRetentions"
    READ_FILES = "readFiles"
    SHARE_FILES = "shareFiles"
    WRITE_BUCKET_ENCRYPTION = "writeBucketEncryption"
    WRITE_BUCKET_LIFECYCLE_RULES = "writeBucketLifecycleRules"
    WRITE_BUCKET_LOGGING = "writeBucketLogging"
    WRITE_BUCKET_NOTIFICATIONS = "writeBucketNotifications"
    WRITE_BUCKET_REPLICATIONS = "writeBucketReplications"
    WRITE_BUCKET_RETENTIONS = "writeBucketRetentions"
    WRITE_BUCKETS = "writeBuckets"
    WRITE_FILE_LEGAL_HOLDS = "writeFileLegalHolds"
    WRITE_FILE_RETENTIONS = "writeFileRetentions"
    WRITE_FILES = "writeFiles"
    WRITE_KEYS = "writeKeys"
    UNKNOWN = "unknown"


class BucketType(UnknownStrEnum):
    ALL_PUBLIC = "allPublic"
    ALL_PRIVATE = "allPrivate"
    RESTRICTED = "restricted"
    SNAPSHOT = "snapshot"
    SHARED = "shared"
    UNKNOWN = "unknown"


class CORSRuleOperation(UnknownStrEnum):
    DOWNLOAD_FILE_BY_NAME = "b2_download_file_by_name"
    DOWNLOAD_FILE_BY_ID = "b2_download_file_by_id"
    UPLOAD_FILE = "b2_upload_file"
    UPLOAD_PART = "b2_upload_part"
    UNKNOWN = "unknown"


class FileAction(UnknownStrEnum):
    START = "start"
    UPLOAD = "upload"
    COPY = "copy"
    HIDE = "hide"
    FOLDER = "folder"
    UNKNOWN = "unknown"


class FileReplicationStatus(UnknownStrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REPLICA = "replica"
    UNKNOWN = "unknown"


class FileRetentionMode(UnknownStrEnum):
    GOVERNANCE = "governance"
    COMPLIANCE = "compliance"
    UNKNOWN = "unknown"


class LegalHoldStatus(UnknownStrEnum):
    ON = "on"
    OFF = "off"
    UNKNOWN = "unknown"
