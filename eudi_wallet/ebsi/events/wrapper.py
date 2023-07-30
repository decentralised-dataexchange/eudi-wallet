from dataclasses import dataclass

from dataclasses_json import DataClassJsonMixin


@dataclass
class EventWrapper(DataClassJsonMixin):
    event_type: str
    payload: dict
