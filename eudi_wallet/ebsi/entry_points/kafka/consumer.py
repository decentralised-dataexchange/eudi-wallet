import asyncio
import json
import logging

import click
import debugpy
from aiokafka import AIOKafkaConsumer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from eudi_wallet.ebsi.event_handlers.application.organisation import (
    handle_event_onboard_root_trusted_accreditation_organisation,
    handle_event_onboard_trusted_accreditation_organisation,
    handle_event_onboard_trusted_issuer,
)
from eudi_wallet.ebsi.events.application.organisation import (
    OnboardRootTrustedAccreditationOrganisationEvent,
    OnboardTrustedAccreditationOrganisationEvent,
    OnboardTrustedIssuerEvent,
)
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
            elif event_type == EventTypes.OnboardTrustedAccreditationOrganisation.value:
                event = OnboardTrustedAccreditationOrganisationEvent.from_dict(
                    event_wrapper.payload
                )
                await handle_event_onboard_trusted_accreditation_organisation(
                    event, logger, db_session
                )
            elif (
                event_type
                == EventTypes.OnboardRootTrustedAccreditationOrganisation.value
            ):
                event = OnboardRootTrustedAccreditationOrganisationEvent.from_dict(
                    event_wrapper.payload
                )
                await handle_event_onboard_root_trusted_accreditation_organisation(
                    event, logger, db_session
                )
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
@click.option(
    "--debug", envvar="KAFKA_CONSUMER_DEBUG", is_flag=True, help="Enable debugging mode"
)
@click.option(
    "--debug-host",
    envvar="KAFKA_CONSUMER_DEBUG_HOST",
    default="0.0.0.0",
    help="Debug host to listen on",
)
@click.option(
    "--debug-port",
    envvar="KAFKA_CONSUMER_DEBUG_PORT",
    default=5678,
    type=int,
    help="Debug port to listen on",
)
def main(
    kafka_broker_address,
    kafka_topic,
    debug,
    debug_host,
    debug_port,
):
    if debug:
        logger.debug(f"Starting debugger on {debug_host}:{debug_port}")
        debugpy.listen((debug_host, debug_port))
        logger.debug("Waiting for debugger to attach...")
        debugpy.wait_for_client()
        logger.debug("Debugger attached!")

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
