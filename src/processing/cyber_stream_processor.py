"""Enterprise Real-Time Cyber Threat & Phishing Stream Processor.

Kafka consumer pipeline running Shannon Entropy, BK-Tree Levenshtein matching,
DNS RPZ autonomous sinkholing, and dual-path storage synchronization.
"""

import json
import logging
import os
import sys
import time
from typing import Dict, Any, List
from kafka import KafkaConsumer
from kafka.errors import KafkaError
import psycopg2
import redis

# Add project root to sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.analytics.threat_matrix import ThreatMatrixEngine
from src.enforcement.dns_sinkhole_api import DNSSinkholeService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CyberStreamProcessor")

KAFKA_BOOTSTRAP = "localhost:9095"
KAFKA_TOPIC = "cyber.certstream.raw"
PG_CONFIG = {
    "host": "localhost",
    "port": 5434,
    "user": "cyber_admin",
    "password": "cyber_secret",
    "dbname": "cyber_threat_db"
}


class CyberStreamProcessor:
    """High-throughput pure Big Data stream analytics processor."""

    def __init__(self, bootstrap_servers: str = KAFKA_BOOTSTRAP, pg_config: Dict = PG_CONFIG):
        self.bootstrap = bootstrap_servers
        self.pg_config = pg_config
        self.pg_conn = None
        self.redis_client = None
        self.threat_engine = None
        self.sinkhole_service = None
        self._init_components()

    def _init_components(self):
        """Connect to Postgres, Redis, and instantiate analytics engines."""
        # 1. Connect PostgreSQL
        for attempt in range(10):
            try:
                self.pg_conn = psycopg2.connect(**self.pg_config)
                self.pg_conn.autocommit = False
                logger.info(f"Connected to PostgreSQL at {self.pg_config['host']}:{self.pg_config['port']}")
                break
            except Exception as e:
                logger.warning(f"Waiting for Postgres (attempt {attempt+1}/10): {e}. Retrying in 2s...")
                time.sleep(2)
        if not self.pg_conn:
            raise RuntimeError("Could not connect to PostgreSQL.")

        # 2. Connect Redis on port 6380
        self.redis_client = redis.Redis(host="localhost", port=6380, db=0, decode_responses=True)
        try:
            self.redis_client.ping()
            logger.info("Connected to Redis Bloom/Cache Store at localhost:6380")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            raise

        # 3. Threat Engine & Sinkhole Enforcement
        self.threat_engine = ThreatMatrixEngine()
        self.sinkhole_service = DNSSinkholeService(pg_conn=self.pg_conn, redis_client=self.redis_client)
        logger.info("✅ Pure Big Data Stream Analytics Engine successfully initialized!")

    def run(self):
        """Continuously consume from Kafka and process threat telemetry."""
        consumer = None
        group_id = f"cyber-processor-{int(time.time())}"

        for attempt in range(10):
            try:
                consumer = KafkaConsumer(
                    KAFKA_TOPIC,
                    bootstrap_servers=self.bootstrap,
                    group_id=group_id,
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    consumer_timeout_ms=1000
                )
                logger.info(f"Kafka consumer subscribed to '{KAFKA_TOPIC}' with group '{group_id}'")
                break
            except (KafkaError, Exception) as e:
                logger.warning(f"Waiting for Kafka at {self.bootstrap} (attempt {attempt+1}/10)...")
                time.sleep(2)

        if not consumer:
            raise RuntimeError("Failed to connect Kafka consumer.")

        total_processed = 0
        threat_count = 0
        batch_stream_records = []
        last_flush_time = time.time()

        logger.info("🚀 Cyber Threat Sentinel Processor is actively monitoring live global certificates...")
        try:
            while True:
                records = consumer.poll(timeout_ms=1000)
                if not records:
                    if batch_stream_records and (time.time() - last_flush_time > 2.0):
                        self._flush_stream_records(batch_stream_records)
                        batch_stream_records.clear()
                        last_flush_time = time.time()
                    continue

                for tp, messages in records.items():
                    for message in messages:
                        cert = message.value
                        domain = cert.get("domain", "")
                        issuer_ca = cert.get("issuer_ca", "Unknown")

                        if not domain:
                            continue

                        # 1. Deduplication via Redis Bloom/Set (< 0.1ms)
                        if self.redis_client.sismember("bloom:seen_domains", domain):
                            continue
                        self.redis_client.sadd("bloom:seen_domains", domain)

                        # 2. Pure Big Data Algorithmic Evaluation (< 0.2ms)
                        verdict = self.threat_engine.evaluate(domain, issuer_ca)
                        total_processed += 1

                        # 3. Autonomous Enforcement Action
                        if verdict["action_taken"] == "AUTO_SINKHOLE":
                            threat_count += 1
                            reason_text = (
                                f"{verdict['threat_type']} targeting brand '{verdict['target_brand']}' "
                                f"with severity score {verdict['threat_score']}/5.0 (Entropy: {verdict['shannon_entropy']} bits)"
                            )
                            self.sinkhole_service.enforce_sinkhole(
                                domain=domain,
                                target_brand=verdict["target_brand"],
                                threat_type=verdict["threat_type"],
                                threat_score=verdict["threat_score"],
                                reason=reason_text
                            )
                            self._save_threat(verdict)

                        elif verdict["action_taken"] == "FLAGGED_SOC":
                            threat_count += 1
                            self._save_threat(verdict)

                        # 4. Collect stream records for batch insertion
                        batch_stream_records.append((
                            domain, json.dumps(cert.get("all_domains", [])[:3]), issuer_ca,
                            cert.get("fingerprint", ""), verdict["tld"],
                            verdict["shannon_entropy"], verdict["action_taken"]
                        ))

                        # Flush batch stream every 25 records or 2 seconds
                        if len(batch_stream_records) >= 25 or (time.time() - last_flush_time > 2.0):
                            self._flush_stream_records(batch_stream_records)
                            batch_stream_records.clear()
                            last_flush_time = time.time()

                        if total_processed % 50 == 0:
                            logger.info(
                                f"⚡ [CPS MONITOR] Ingested: {total_processed} certs | Phishing Blocked: {threat_count} | "
                                f"Latest: {domain} ({verdict['threat_type']} - Latency: {verdict['processing_latency_ms']}ms)"
                            )

        except KeyboardInterrupt:
            logger.info("Stream processor stopped by user.")
        finally:
            if consumer:
                consumer.close()
            if self.pg_conn:
                self.pg_conn.close()

    def _save_threat(self, v: Dict):
        """Save high-risk phishing threat to PostgreSQL."""
        try:
            with self.pg_conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO phishing_threats 
                    (timestamp, domain, target_brand, threat_type, threat_score, confidence, 
                     shannon_entropy, levenshtein_distance, issuer_ca, action_taken, processing_latency_ms)
                    VALUES (CURRENT_TIMESTAMP, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        v["domain"], v["target_brand"], v["threat_type"], v["threat_score"],
                        v["confidence"], v["shannon_entropy"], v["levenshtein_dist"],
                        v["issuer_ca"], v["action_taken"], v["processing_latency_ms"]
                    )
                )
                self.pg_conn.commit()
        except Exception as e:
            logger.error(f"Failed to save threat alert: {e}")
            self.pg_conn.rollback()

    def _flush_stream_records(self, records: List):
        """Batch insert raw certificates into PostgreSQL."""
        if not records:
            return
        try:
            with self.pg_conn.cursor() as cur:
                from psycopg2.extras import execute_values
                execute_values(
                    cur,
                    """
                    INSERT INTO certificates_stream 
                    (domain, all_domains, issuer_ca, fingerprint, tld, shannon_entropy, threat_verdict)
                    VALUES %s;
                    """,
                    records
                )
                self.pg_conn.commit()
        except Exception as e:
            logger.error(f"Failed to batch insert stream records: {e}")
            self.pg_conn.rollback()


if __name__ == "__main__":
    processor = CyberStreamProcessor()
    processor.run()
