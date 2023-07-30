import asyncio
import logging

import click
from aiohttp import web
from aiohttp.web_request import Request
from confluent_kafka import Producer
from pyngrok import ngrok  # type: ignore
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from eudi_wallet.ebsi.entities.base import Base
from eudi_wallet.ebsi.entry_points.server.constants import ISSUER_SUBDOMAIN
from eudi_wallet.ebsi.entry_points.server.routes import routes
from eudi_wallet.ebsi.entry_points.server.startup import app_startup

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(filename)s - %(levelname)s - %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


async def handle_404(request: Request):
    return web.Response(text="404 - Page not found", status=404)


def setup_db():
    engine = create_engine("sqlite:///wallet.db")
    Session = sessionmaker(bind=engine)

    # It creates a table if it does not exist.
    Base.metadata.create_all(engine)

    return Session


async def start_server(port: int, kafka_broker_address: str, kafka_topic: str):
    app = web.Application()

    conf = {"bootstrap.servers": kafka_broker_address}
    producer = Producer(conf)

    db_session = setup_db()

    app["kafka_producer"] = producer
    app["kafka_topic"] = kafka_topic
    app["logger"] = logger
    app["db_session"] = db_session

    # Add startup functions
    app.on_startup.append(app_startup)

    # Add routes
    app.add_routes(routes)
    app.add_routes([web.route("*", "/{tail:.*}", handle_404, name="handle_404")])

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, "localhost", port)
    await site.start()

    return runner, site


async def stop_server(runner, site):
    await site.stop()
    await runner.cleanup()


def configure_ngrok(port: int, auth_token: str, custom_domain: str):
    ngrok.set_auth_token(auth_token)
    ngrok_tunnel = ngrok.connect(port, subdomain=custom_domain)
    return ngrok_tunnel


@click.command()
@click.option("--port", default=8080, help="Port number to start the server on.")
@click.option(
    "--auth-token",
    envvar="NGROK_AUTH_TOKEN",
    prompt="Enter your ngrok authentication token",
    help="ngrok authentication token.",
)
@click.option(
    "--kafka-broker-address",
    envvar="KAFKA_BROKER_ADDRESS",
    prompt="Enter your kafka broker address",
    help="Kafka broker address",
)
@click.option(
    "--kafka-topic",
    envvar="KAFKA_TOPIC",
    prompt="Enter your kafka topic",
    help="Topic to consume kafka events from",
)
def main(port: int, auth_token: str, kafka_broker_address: str, kafka_topic: str):
    loop = asyncio.get_event_loop()
    runner, site = loop.run_until_complete(
        start_server(port, kafka_broker_address, kafka_topic)
    )

    try:
        ngrok_tunnel = configure_ngrok(port, auth_token, ISSUER_SUBDOMAIN)
        print(f"ngrok tunnel URL: {ngrok_tunnel.public_url}")

        loop.run_forever()

    except KeyboardInterrupt:
        pass

    finally:
        loop.run_until_complete(stop_server(runner, site))
        loop.close()
        # If tried to stop the server before ngrok tunnel is created, UnboundLocalError is raised
        if ngrok_tunnel:
            ngrok.disconnect(ngrok_tunnel.public_url)
            ngrok.kill()


if __name__ == "__main__":
    main()
