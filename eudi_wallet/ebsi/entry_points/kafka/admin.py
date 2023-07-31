from confluent_kafka.admin import AdminClient, NewTopic


def create_topic_if_not_exists(
    broker, topic_name, num_partitions=1, replication_factor=1
):
    admin_client = AdminClient({"bootstrap.servers": broker})

    # Fetch topic metadata
    topic_metadata = admin_client.list_topics(timeout=5)
    if topic_name in topic_metadata.topics:
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
            topic_name,
            num_partitions=num_partitions,
            replication_factor=replication_factor,
            config=topic_config,
        )
    ]

    # Create topic
    fs = admin_client.create_topics(new_topic)

    # Wait for each operation to finish.
    for topic, f in fs.items():
        try:
            f.result()  # The result itself is None
            print(f"Topic {topic} created")
        except Exception as e:
            print(f"Failed to create topic {topic}: {e}")


if __name__ == "__main__":
    create_topic_if_not_exists("localhost:9092", "ebsi")
