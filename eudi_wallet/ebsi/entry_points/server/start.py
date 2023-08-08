import asyncio
import logging

import click
import debugpy
from aiohttp import web
from aiohttp.web_request import Request
from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaConnectionError
from pyngrok import ngrok  # type: ignore
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from eudi_wallet.ebsi.entry_points.server.middlewares import (
    error_middleware,
    logging_middleware,
)
from eudi_wallet.ebsi.entry_points.server.routes import routes
from eudi_wallet.ebsi.entry_points.server.startup import app_startup
from eudi_wallet.ebsi.models.base import Base


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


class DBSetup:
    def __init__(self, db_uri):
        self.db_uri = db_uri

    def setup_db(self):
        engine = create_engine(self.db_uri)
        Session = sessionmaker(bind=engine)

        # It creates a table if it does not exist.
        Base.metadata.create_all(engine)

        return Session


class NgrokSetup:
    def __init__(self, auth_token):
        self.auth_token = auth_token

    def configure_ngrok(self, port: int, custom_domain: str):
        ngrok.set_auth_token(self.auth_token)
        ngrok_tunnel = ngrok.connect(port, subdomain=custom_domain)
        return ngrok_tunnel


async def handle_404(request: Request):
    return web.Response(text="404 - Page not found", status=404)


class ServerSetup:
    def __init__(self, db_session, producer, logger, kafka_topic, subdomain):
        self.db_session = db_session
        self.producer = producer
        self.logger = logger
        self.kafka_topic = kafka_topic
        self.subdomain = subdomain
        self.domain = f"https://{self.subdomain}.ngrok.io"

    async def start_server(self, port: int):
        app = web.Application(middlewares=[error_middleware, logging_middleware])

        app["kafka_producer"] = self.producer
        app["kafka_topic"] = self.kafka_topic
        app["logger"] = self.logger
        app["db_session"] = self.db_session
        app["domain"] = self.domain

        # Add startup functions
        app.on_startup.append(app_startup)

        # Add routes
        app.add_routes(routes)
        app.add_routes([web.route("*", "/{tail:.*}", handle_404, name="handle_404")])

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()

        return runner, site


class ServerTeardown:
    async def stop_server(self, runner, site):
        await site.stop()
        await runner.cleanup()


@click.command()
@click.option("--port", envvar="PORT", default=8080)
@click.option("--ngrok-auth-token", envvar="NGROK_AUTH_TOKEN", default=None)
@click.option("--ngrok-subdomain", envvar="NGROK_SUBDOMAIN", default="ebsi-wallet")
@click.option("--kafka-broker-address", envvar="KAFKA_BROKER_ADDRESS", default=None)
@click.option("--kafka-topic", envvar="KAFKA_TOPIC", default=None)
@click.option(
    "--log-level",
    default="DEBUG",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set the log level",
)
@click.option("--debug", envvar="DEBUG", is_flag=True, help="Enable debugging mode")
@click.option(
    "--debug-host",
    envvar="DEBUG_HOST",
    default="0.0.0.0",
    help="Debug host to listen on",
)
@click.option(
    "--debug-port",
    envvar="DEBUG_PORT",
    default=5678,
    type=int,
    help="Debug port to listen on",
)
def main(
    port,
    ngrok_auth_token,
    ngrok_subdomain,
    kafka_broker_address,
    kafka_topic,
    log_level,
    debug,
    debug_host,
    debug_port,
):
    level = getattr(logging, log_level.upper(), None)
    logger = AppLogger(__name__, level=level).logger

    if debug:
        logger.debug(f"Starting debugger on {debug_host}:{debug_port}")
        debugpy.listen((debug_host, debug_port))
        logger.debug("Waiting for debugger to attach...")
        debugpy.wait_for_client()
        logger.debug("Debugger attached!")

    db_session = DBSetup("sqlite:///wallet.db").setup_db()

    loop = asyncio.get_event_loop()

    producer = None
    try:
        if kafka_broker_address:
            producer = AIOKafkaProducer(
                bootstrap_servers=kafka_broker_address, loop=loop
            )
            loop.run_until_complete(producer.start())
    except KafkaConnectionError as e:
        logger.error(f"Unable to connect to Kafka broker: {e}")

    server = ServerSetup(db_session, producer, logger, kafka_topic, ngrok_subdomain)

    runner, site = loop.run_until_complete(server.start_server(port))

    # Only set up ngrok if auth token is provided
    ngrok_tunnel = None
    if ngrok_auth_token:
        ngrok_tunnel = NgrokSetup(ngrok_auth_token)
        try:
            tunnel = ngrok_tunnel.configure_ngrok(port, ngrok_subdomain)
            logger.info(f"ngrok tunnel URL: {tunnel.public_url}")

        except Exception as e:
            logger.error(f"Error while setting up ngrok: {e}")
    else:
        logger.info("Starting without ngrok...")

    try:
        loop.run_forever()

    except KeyboardInterrupt:
        print("CTRL+C Pressed. Shutting down gracefully...")
        pass

    finally:
        loop.run_until_complete(server.stop(runner, site))
        loop.run_until_complete(producer.stop())
        loop.close()

        if ngrok_tunnel and "tunnel" in locals():
            ngrok.disconnect(tunnel.public_url)
            ngrok.kill()


if __name__ == "__main__":
    main()
