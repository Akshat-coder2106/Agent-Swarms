"""Apache Kafka event streaming for Sentinel."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from .models import (
    AgentRole,
    AuditEvent,
    MCPMessage,
    sha256_text,
)


class KafkaTopic(StrEnum):
    """Kafka topic names."""

    ARCHITECT_TASKS = "sentinel.architect.tasks"
    SCOUT_TASKS = "sentinel.scout.tasks"
    ENGINEER_TASKS = "sentinel.engineer.tasks"
    CRITIC_TASKS = "sentinel.critic.tasks"
    ARCHITECT_OUT = "sentinel.architect.out"
    SCOUT_OUT = "sentinel.scout.out"
    ENGINEER_OUT = "sentinel.engineer.out"
    CRITIC_OUT = "sentinel.critic.out"
    REPO_CHANGES = "sentinel.repo.changes"
    AUDIT_EVENTS = "sentinel.audit.events"


@dataclass
class KafkaConfig:
    """Configuration for Kafka integration."""

    bootstrap_servers: str = "localhost:9092"
    group_id: str = "sentinel-consumer-group"
    auto_offset_reset: str = "earliest"
    enable_auto_commit: bool = True
    session_timeout_ms: int = 30000
    request_timeout_ms: int = 30000
    max_poll_records: int = 100
    max_poll_interval_ms: int = 300000


class KafkaEventProducer:
    """Kafka producer for publishing events."""

    def __init__(self, config: KafkaConfig) -> None:
        self._config = config
        self._producer = Producer(
            {
                "bootstrap.servers": config.bootstrap_servers,
                "client.id": "sentinel-producer",
                "acks": "all",
                "retries": 3,
                "compression.type": "snappy",
            }
        )

    def publish_mcp_message(
        self,
        message: MCPMessage,
        topic: KafkaTopic,
    ) -> None:
        """Publish an MCP message to Kafka."""
        self._produce(topic, message.model_dump(mode="json"))

    def publish_audit_event(
        self,
        event: AuditEvent,
        topic: KafkaTopic = KafkaTopic.AUDIT_EVENTS,
    ) -> None:
        """Publish an audit event to Kafka."""
        self._produce(topic, event.model_dump(mode="json"))

    def publish_repo_change(
        self,
        session_id: str,
        commit_sha: str,
        changed_files: list[str],
        diff_hunks: list[dict[str, Any]],
    ) -> None:
        """Publish a repository change event."""
        payload = {
            "session_id": session_id,
            "commit_sha": commit_sha,
            "changed_files": changed_files,
            "diff_hunks": diff_hunks,
            "timestamp": sha256_text(f"{session_id}:{commit_sha}"),
        }
        self._produce(KafkaTopic.REPO_CHANGES, payload)

    def _produce(self, topic: KafkaTopic, payload: dict[str, Any]) -> None:
        """Produce a message to Kafka."""
        try:
            self._producer.produce(
                topic.value,
                key=payload.get("session_id", "default"),
                value=json.dumps(payload),
                callback=self._delivery_report,
            )
            self._producer.poll(0)
        except BufferError:
            self._producer.flush()

    def _delivery_report(self, err, msg) -> None:
        """Callback for message delivery reports."""
        if err is not None:
            print(f"Message delivery failed: {err}")
        else:
            print(f"Message delivered to {msg.topic()} [{msg.partition()}]")

    def flush(self) -> None:
        """Flush all pending messages."""
        self._producer.flush()

    def close(self) -> None:
        """Close the producer."""
        self._producer.flush()
        self._producer.close()


class KafkaEventConsumer:
    """Kafka consumer for consuming events."""

    def __init__(self, config: KafkaConfig) -> None:
        self._config = config
        self._consumer = None

    def subscribe(
        self,
        topics: list[KafkaTopic],
        callback,
    ) -> None:
        """Subscribe to topics and start consuming."""
        self._consumer = Consumer(
            {
                "bootstrap.servers": self._config.bootstrap_servers,
                "group.id": self._config.group_id,
                "auto.offset.reset": self._config.auto_offset_reset,
                "enable.auto.commit": self._config.enable_auto_commit,
                "session.timeout.ms": self._config.session_timeout_ms,
                "request.timeout.ms": self._config.request_timeout_ms,
                "max.poll.records": self._config.max_poll_records,
                "max.poll.interval.ms": self._config.max_poll_interval_ms,
            }
        )

        self._consumer.subscribe([topic.value for topic in topics])

        try:
            while True:
                msg = self._consumer.poll(1.0)

                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        raise KafkaException(msg.error())

                try:
                    payload = json.loads(msg.value().decode("utf-8"))
                    callback(payload)
                except json.JSONDecodeError:
                    print(f"Failed to decode message from {msg.topic()}")

        except KeyboardInterrupt:
            pass
        finally:
            self._consumer.close()

    def consume_messages(
        self,
        topics: list[KafkaTopic],
        max_messages: int = 100,
    ) -> list[dict[str, Any]]:
        """Consume a batch of messages from topics."""
        self._consumer = Consumer(
            {
                "bootstrap.servers": self._config.bootstrap_servers,
                "group.id": self._config.group_id,
                "auto.offset.reset": self._config.auto_offset_reset,
                "enable.auto.commit": False,
            }
        )

        self._consumer.subscribe([topic.value for topic in topics])

        messages = []
        try:
            for _ in range(max_messages):
                msg = self._consumer.poll(1.0)

                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        raise KafkaException(msg.error())

                try:
                    payload = json.loads(msg.value().decode("utf-8"))
                    messages.append(payload)
                except json.JSONDecodeError:
                    continue

        finally:
            self._consumer.close()

        return messages

    def close(self) -> None:
        """Close the consumer."""
        if self._consumer:
            self._consumer.close()


class KafkaTopicManager:
    """Manager for Kafka topic administration."""

    def __init__(self, config: KafkaConfig) -> None:
        self._config = config
        self._admin_client = AdminClient({"bootstrap.servers": config.bootstrap_servers})

    def create_topics(
        self,
        topics: list[KafkaTopic],
        num_partitions: int = 3,
        replication_factor: int = 1,
    ) -> None:
        """Create Kafka topics if they don't exist."""
        new_topics = [
            NewTopic(
                topic.value,
                num_partitions=num_partitions,
                replication_factor=replication_factor,
            )
            for topic in topics
        ]

        futures = self._admin_client.create_topics(new_topics)

        for topic, future in futures.items():
            try:
                future.result()
                print(f"Topic {topic} created")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"Topic {topic} already exists")
                else:
                    print(f"Failed to create topic {topic}: {e}")

    def delete_topics(self, topics: list[KafkaTopic]) -> None:
        """Delete Kafka topics."""
        futures = self._admin_client.delete_topics([topic.value for topic in topics])

        for topic, future in futures.items():
            try:
                future.result()
                print(f"Topic {topic} deleted")
            except Exception as e:
                print(f"Failed to delete topic {topic}: {e}")

    def list_topics(self) -> list[str]:
        """List all existing topics."""
        cluster_metadata = self._admin_client.list_topics(timeout=10)
        return list(cluster_metadata.topics.keys())

    def close(self) -> None:
        """Close the admin client."""
        pass


class GitHookKafkaPublisher:
    """Publisher for git hook events to Kafka."""

    def __init__(self, producer: KafkaEventProducer) -> None:
        self._producer = producer

    def publish_commit(
        self,
        session_id: str,
        commit_sha: str,
        changed_files: list[str],
        diff_hunks: list[dict[str, Any]],
    ) -> None:
        """Publish a commit event from git hook."""
        self._producer.publish_repo_change(
            session_id=session_id,
            commit_sha=commit_sha,
            changed_files=changed_files,
            diff_hunks=diff_hunks,
        )


class AgentTaskRouter:
    """Router for agent tasks via Kafka."""

    def __init__(
        self,
        producer: KafkaEventProducer,
        consumer: KafkaEventConsumer,
    ) -> None:
        self._producer = producer
        self._consumer = consumer

    def route_task(
        self,
        message: MCPMessage,
    ) -> None:
        """Route an MCP message to the appropriate agent topic."""
        recipient = message.recipient

        topic_mapping = {
            AgentRole.ARCHITECT: KafkaTopic.ARCHITECT_TASKS,
            AgentRole.SCOUT: KafkaTopic.SCOUT_TASKS,
            AgentRole.ENGINEER: KafkaTopic.ENGINEER_TASKS,
            AgentRole.CRITIC: KafkaTopic.CRITIC_TASKS,
        }

        topic = topic_mapping.get(recipient)
        if topic:
            self._producer.publish_mcp_message(message, topic)

    def consume_agent_tasks(
        self,
        agent_role: AgentRole,
        callback,
    ) -> None:
        """Consume tasks for a specific agent."""
        topic_mapping = {
            AgentRole.ARCHITECT: KafkaTopic.ARCHITECT_TASKS,
            AgentRole.SCOUT: KafkaTopic.SCOUT_TASKS,
            AgentRole.ENGINEER: KafkaTopic.ENGINEER_TASKS,
            AgentRole.CRITIC: KafkaTopic.CRITIC_TASKS,
        }

        topic = topic_mapping.get(agent_role)
        if topic:
            self._consumer.subscribe([topic], callback)
