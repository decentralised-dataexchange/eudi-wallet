import asyncio
import json
import logging

import click
from confluent_kafka import Consumer, KafkaError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from eudi_wallet.ebsi.event_handlers.application.legal_entity import \
    handle_event_onboard_trusted_issuer
from eudi_wallet.ebsi.events.application.legal_entity import \
    OnboardTrustedIssuerEvent
from eudi_wallet.ebsi.events.event_types import EventTypes
from eudi_wallet.ebsi.events.wrapper import EventWrapper

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(filename)s - %(levelname)s - %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


@click.command()
@click.option(
    "--kafka-broker-address",
    envvar="KAFKA_BROKER_ADDRESS",
    default="localhost:9092",
    prompt="Enter your kafka broker address",
    help="Kafka broker address",
)
@click.option(
    "--kafka-topic",
    envvar="KAFKA_TOPIC",
    default="ebsi",
    prompt="Enter your kafka topic",
    help="Topic to consume kafka events from",
)
def consume(kafka_broker_address, kafka_topic):
    conf = {
        "bootstrap.servers": kafka_broker_address,
        "group.id": "consumer_group_id",
        "auto.offset.reset": "earliest",
        "max.poll.interval.ms": "600000",
        "session.timeout.ms": "500000",
    }

    consumer = Consumer(conf)
    consumer.subscribe([kafka_topic])

    engine = create_engine("sqlite:///wallet.db")
    db_session = sessionmaker(bind=engine)

    while True:
        msg = consumer.poll(1.0)

        if msg is None:
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            else:
                print(f"Error: {msg.error()}")
                break

        msg_dict = json.loads(msg.value().decode("utf-8"))
        event_wrapper = EventWrapper.from_dict(msg_dict)
        event_type = event_wrapper.event_type

        logger.debug(f"Received message of type: {event_type}")

        if event_type == EventTypes.OnboardTrustedIssuer.value:
            event = OnboardTrustedIssuerEvent.from_dict(event_wrapper.payload)
            task = asyncio.ensure_future(
                handle_event_onboard_trusted_issuer(event, logger, db_session)
            )
            asyncio.get_event_loop().run_until_complete(task)

    consumer.close()


if __name__ == "__main__":
    consume()
