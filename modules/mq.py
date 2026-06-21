#!/usr/bin/env python3
"""modules.mq — message-queue / broker methodology (built-in fallback)."""
from __future__ import annotations

from .base import SpecModule


class MQModule(SpecModule):
    name = "mq"
    title = "Message Queue / Broker"
    NAMES = ("amqp", "mqtt", "kafka", "stomp", "nats", "zeromq")
    TLS_PORTS = (8883,)
    UNAUTH = ("amqp", "mqtt", "kafka", "stomp", "nats", "zeromq")
    SUMMARY = "{disp} broker ({prod}) reachable."
    KEYWORDS = ("amqp", "rabbitmq", "mqtt", "kafka", "broker", "nats")
    EXTRA_TECH = ("T1213",)
    LABELS = {"amqp": "AMQP/RabbitMQ", "mqtt": "MQTT", "kafka": "Kafka",
              "stomp": "STOMP", "nats": "NATS", "zeromq": "ZeroMQ"}
    SURFACE = (
        ("unauth", "{disp} brokers often allow anonymous/guest access — subscribe and enumerate topics/queues to gauge data exposure."),
        ("has_cve", "Broker version has known CVEs (see findings)."),
    )
    CHECKS = (
        ("Broker fingerprint", "T1592.002", "nmap -p{port} -sV --script banner {ip}", "Identify the broker and version."),
        ("MQTT subscribe-all", "T1213", "mosquitto_sub -h {ip} -p {port} -t '#' -v", "Subscribe to all MQTT topics to inventory exposed messages (authorized)."),
        ("AMQP/mgmt access", "T1078", "curl -s http://{ip}:15672/api/overview -u guest:guest", "Test the RabbitMQ management API with default guest credentials."),
        ("Kafka topics", "T1213", "kafka-topics.sh --bootstrap-server {ip}:{port} --list", "Enumerate Kafka topics on an unauthenticated broker."),
    )
