from enum import Enum


class CredentialRecordStatus(Enum):
    Pending = "credential_pending"
    Acknowledged = "credential_acked"