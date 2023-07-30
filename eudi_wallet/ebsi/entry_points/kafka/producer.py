from logging import Logger

from confluent_kafka import Producer


def produce(message: str, topic: str, producer: Producer, logger: Logger):
    def delivery_report(err, msg):
        if err is not None:
            logger.debug(f"Message delivery failed: {err}")
        else:
            logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}]")

    producer.produce(topic, message, callback=delivery_report)
    producer.flush()


if __name__ == "__main__":
    produce()
