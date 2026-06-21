# Message Queue / Broker Module

Message-broker methodology (AMQP/RabbitMQ, MQTT, Kafka, STOMP, NATS). Brokers
frequently allow anonymous/guest access; enumerate topics/queues to gauge data
exposure. `{disp}` resolves from `labels`.

```yaml
module: mq
title: Message Queue / Broker
scope: port
matches: [amqp, mqtt, kafka, stomp, nats, zeromq]
tls_ports: [8883]
summary: "{disp} broker ({prod}) reachable."
finding_keywords: [amqp, rabbitmq, mqtt, kafka, broker, nats]
labels:
  amqp: AMQP/RabbitMQ
  mqtt: MQTT
  kafka: Kafka
  stomp: STOMP
  nats: NATS
  zeromq: ZeroMQ
unauth_services: [amqp, mqtt, kafka, stomp, nats, zeromq]
techniques_extra: [T1213]
attack_surface:
  - { when: "unauth", note: "{disp} brokers often allow anonymous/guest access — subscribe and enumerate topics/queues to gauge data exposure." }
  - { when: "has_cve", note: "Broker version has known CVEs (see findings)." }
checks:
  - { name: Broker fingerprint, attack: T1592.002, command: "nmap -p{port} -sV --script banner {ip}", purpose: "Identify the broker and version." }
  - { name: MQTT subscribe-all, attack: T1213, command: "mosquitto_sub -h {ip} -p {port} -t '#' -v", purpose: "Subscribe to all MQTT topics to inventory exposed messages (authorized)." }
  - { name: AMQP/mgmt access, attack: T1078, command: "curl -s http://{ip}:15672/api/overview -u guest:guest", purpose: "Test the RabbitMQ management API with default guest credentials." }
  - { name: Kafka topics, attack: T1213, command: "kafka-topics.sh --bootstrap-server {ip}:{port} --list", purpose: "Enumerate Kafka topics on an unauthenticated broker." }
  - { name: Credential test, attack: T1110, command: "# authorized credential testing against the broker auth (mind lockout)", purpose: "Test for weak/default broker credentials." }
```
