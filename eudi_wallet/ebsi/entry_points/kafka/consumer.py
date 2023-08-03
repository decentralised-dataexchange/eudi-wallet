import asyncio
import json
import logging

import click
from aiokafka import AIOKafkaConsumer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from eudi_wallet.ebsi.event_handlers.application.legal_entity import (
    handle_event_onboard_trusted_issuer,
)
from eudi_wallet.ebsi.events.application.legal_entity import OnboardTrustedIssuerEvent
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


async def consume(kafka_broker_address, kafka_topic):
    consumer = AIOKafkaConsumer(
        kafka_topic,
        bootstrap_servers=kafka_broker_address,
        group_id="consumer_group_id",
        auto_offset_reset="earliest",
    )

    await consumer.start()

    engine = create_engine("sqlite:///wallet.db")
    db_session = sessionmaker(bind=engine)

    try:
        # Consume messages
        async for msg in consumer:
            msg_dict = json.loads(msg.value.decode("utf-8"))
            event_wrapper = EventWrapper.from_dict(msg_dict)
            event_type = event_wrapper.event_type

            logger.debug(f"Received message of type: {event_type}")

            if event_type == EventTypes.OnboardTrustedIssuer.value:
                event = OnboardTrustedIssuerEvent.from_dict(event_wrapper.payload)
                await handle_event_onboard_trusted_issuer(event, logger, db_session)
    finally:
        # Will leave consumer group; perform autocommit if enabled.
        await consumer.stop()


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
def main(kafka_broker_address, kafka_topic):
    loop = asyncio.get_event_loop()

    consume_task = loop.create_task(consume(kafka_broker_address, kafka_topic))

    try:
        loop.run_until_complete(consume_task)
    except KeyboardInterrupt:
        print("CTRL+C Pressed. Shutting down gracefully...")
        consume_task.cancel()
        loop.run_until_complete(consume_task)
    finally:
        loop.close()


if __name__ == "__main__":
    main()
