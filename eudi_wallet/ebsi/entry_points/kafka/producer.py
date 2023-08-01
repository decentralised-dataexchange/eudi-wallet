from logging import Logger

from aiokafka import AIOKafkaProducer


async def produce(message: str, topic: str, producer: AIOKafkaProducer, logger: Logger):
    try:
        await producer.send_and_wait(topic, message.encode("utf-8"))
        logger.debug(f"Message delivered to {topic}")
    except Exception as err:
        logger.debug(f"Message delivery failed: {err}")
