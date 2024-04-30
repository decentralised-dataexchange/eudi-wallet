from enum import Enum


class VerificationRecordStatus(Enum):
    RequestSent = "request_sent"
    RequestReceived = "request_received"
    PresentationAck = "presentation_acked"
