import asyncio

from kafka.admin import KafkaAdminClient, NewTopic


async def create_topic_if_not_exists(
    broker, topic_name, num_partitions=1, replication_factor=1
):
    admin_client = KafkaAdminClient(bootstrap_servers=broker)

    # Fetch topic metadata
    topic_metadata = admin_client.list_topics()
    if topic_name in set(topic_metadata):
        print(f"Topic '{topic_name}' already exists.")
        return
    else:
        print(f"Topic '{topic_name}' does not exist. Creating...")

    # Topic configuration
    topic_config = {
        "cleanup.policy": "delete",
        "delete.retention.ms": "5000",
        "file.delete.delay.ms": "60000",
    }

    # Define NewTopic object
    new_topic = [
        NewTopic(
            name=topic_name,
            num_partitions=num_partitions,
            replication_factor=replication_factor,
            topic_configs=topic_config,
        )
    ]

    # Create topic
    try:
        admin_client.create_topics(new_topics=new_topic)
        print(f"Topic {topic_name} created")
    except Exception as e:
        print(f"Failed to create topic {topic_name}: {e}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(create_topic_if_not_exists("localhost:9092", "ebsi"))
    loop.close()
