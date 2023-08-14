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


class AppLogger:
    def __init__(self, name, level=logging.DEBUG):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        handler = logging.StreamHandler()
        handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - [%(filename)s:%(lineno)d] - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)


class Consumer:
    def __init__(
        self,
        kafka_broker_address: str,
        kafka_topic: str,
        logger: logging.Logger,
        database_user: str,
        database_password: str,
        database_host: str,
        database_port: str,
        database_db: str,
    ):
        self.kafka_broker_address = kafka_broker_address
        self.kafka_topic = kafka_topic
        self.logger = logger
        self.database_user = database_user
        self.database_password = database_password
        self.database_host = database_host
        self.database_port = database_port
        self.database_db = database_db

    async def handle_event(
        self, event_type: str, event_wrapper: EventWrapper, db_session
    ):
        if event_type == EventTypes.OnboardTrustedIssuer.value:
            event = OnboardTrustedIssuerEvent.from_dict(event_wrapper.payload)
            await handle_event_onboard_trusted_issuer(event, self.logger, db_session)
        elif event_type == EventTypes.OnboardTrustedAccreditationOrganisation.value:
            event = OnboardTrustedAccreditationOrganisationEvent.from_dict(
                event_wrapper.payload
            )
            await handle_event_onboard_trusted_accreditation_organisation(
                event, self.logger, db_session
            )
        elif event_type == EventTypes.OnboardRootTrustedAccreditationOrganisation.value:
            event = OnboardRootTrustedAccreditationOrganisationEvent.from_dict(
                event_wrapper.payload
            )
            await handle_event_onboard_root_trusted_accreditation_organisation(
                event, self.logger, db_session
            )

    async def consume(self):
        consumer = AIOKafkaConsumer(
            self.kafka_topic,
            bootstrap_servers=self.kafka_broker_address,
            group_id="consumer_group_id",
            auto_offset_reset="earliest",
        )

        await consumer.start()

        database_url = f"postgresql+psycopg2://{self.database_user}:{self.database_password}@{self.database_host}:{self.database_port}/{self.database_db}"
        engine = create_engine(database_url)
        db_session = sessionmaker(bind=engine)

        try:
            # Consume messages
            async for msg in consumer:
                msg_dict = json.loads(msg.value.decode("utf-8"))
                event_wrapper = EventWrapper.from_dict(msg_dict)
                event_type = event_wrapper.event_type

                self.logger.debug(f"Received message of type: {event_type}")
                await self.handle_event(event_type, event_wrapper, db_session)

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
@click.option("--database-user", envvar="DATABASE_USER")
@click.option("--database-password", envvar="DATABASE_PASSWORD")
@click.option("--database-host", envvar="DATABASE_HOST")
@click.option("--database-port", envvar="DATABASE_PORT")
@click.option("--database-db", envvar="DATABASE_DB")
@click.option(
    "--log-level",
    default="DEBUG",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set the log level",
)
def main(
    kafka_broker_address,
    kafka_topic,
    debug,
    debug_host,
    debug_port,
    database_user,
    database_password,
    database_host,
    database_port,
    database_db,
    log_level,
):
    level = getattr(logging, log_level.upper(), None)
    logger = AppLogger(__name__, level=level).logger

    if debug:
        logger.debug(f"Starting debugger on {debug_host}:{debug_port}")
        debugpy.listen((debug_host, debug_port))
        logger.debug("Waiting for debugger to attach...")
        debugpy.wait_for_client()
        logger.debug("Debugger attached!")

    loop = asyncio.get_event_loop()

    consumer = Consumer(
        kafka_broker_address,
        kafka_topic,
        logger,
        database_user,
        database_password,
        database_host,
        database_port,
        database_db,
    )

    consume_task = loop.create_task(consumer.consume())

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
