import dataclasses
import typing
from logging import Logger

from confluent_kafka import Producer
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.value_objects.domain.discovery import (
    OpenIDAuthServerConfig, OpenIDCredentialIssuerConfig)


@dataclasses.dataclass
class AppObjects:
    credential_issuer_configuration: typing.Optional[
        OpenIDCredentialIssuerConfig
    ] = None
    auth_server_configuration: typing.Optional[OpenIDAuthServerConfig] = None
    logger: typing.Optional[Logger] = None
    kafka_producer: typing.Optional[Producer] = None
    kafka_topic: typing.Optional[str] = None
    db_session: typing.Optional[Session] = None


def get_app_objects(app) -> AppObjects:
    return AppObjects(
        credential_issuer_configuration=app["credential_issuer_configuration"],
        auth_server_configuration=app["auth_server_configuration"],
        logger=app["logger"],
        kafka_producer=app["kafka_producer"],
        kafka_topic=app["kafka_topic"],
        db_session=app["db_session"],
    )


def get_endpoint_url_by_name(app, endpoint_name):
    named_resources = app.router.named_resources()
    if endpoint_name in named_resources:
        resource = named_resources[endpoint_name]
        endpoint_url = resource.get_info().get("path")
        return endpoint_url
    else:
        return None
