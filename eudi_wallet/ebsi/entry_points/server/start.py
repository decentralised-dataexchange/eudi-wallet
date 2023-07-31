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
from eudi_wallet.ebsi.entry_points.server.constants import WALLET_SUBDOMAIN
from eudi_wallet.ebsi.entry_points.server.middlewares import (
    error_middleware, logging_middleware)
from eudi_wallet.ebsi.entry_points.server.routes import routes
from eudi_wallet.ebsi.entry_points.server.startup import app_startup


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
    def __init__(self, db_session, producer, logger, kafka_topic):
        self.db_session = db_session
        self.producer = producer
        self.logger = logger
        self.kafka_topic = kafka_topic

    async def start_server(self, port: int):
        app = web.Application(middlewares=[error_middleware, logging_middleware])

        app["kafka_producer"] = self.producer
        app["kafka_topic"] = self.kafka_topic
        app["logger"] = self.logger
        app["db_session"] = self.db_session

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


class ServerTeardown:
    async def stop_server(self, runner, site):
        await site.stop()
        await runner.cleanup()


@click.command()
@click.option("--port", default=8080)
@click.option("--auth-token", envvar="NGROK_AUTH_TOKEN", prompt=True)
@click.option("--kafka-broker-address", envvar="KAFKA_BROKER_ADDRESS", prompt=True)
@click.option("--kafka-topic", envvar="KAFKA_TOPIC", prompt=True)
def main(port, auth_token, kafka_broker_address, kafka_topic):
    logger = AppLogger(__name__).logger
    db_session = DBSetup("sqlite:///wallet.db").setup_db()
    conf = {"bootstrap.servers": kafka_broker_address}
    producer = Producer(conf)

    server = ServerSetup(db_session, producer, logger, kafka_topic)
    ngrok_tunnel = NgrokSetup(auth_token)

    loop = asyncio.get_event_loop()
    runner, site = loop.run_until_complete(server.start_server(port))

    try:
        tunnel = ngrok_tunnel.configure_ngrok(port, WALLET_SUBDOMAIN)
        print(f"ngrok tunnel URL: {tunnel.public_url}")
        loop.run_forever()

    except KeyboardInterrupt:
        pass

    finally:
        loop.run_until_complete(server.stop(runner, site))
        loop.close()

        if "tunnel" in locals():
            ngrok.disconnect(tunnel.public_url)
            ngrok.kill()


if __name__ == "__main__":
    main()
