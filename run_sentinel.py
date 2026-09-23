"""Unified Orchestrator: Zero-Hour Cyber Threat & Phishing Sentinel.

Launches the live global CertStream WebSocket ingestion gateway, pure Big Data
analytics stream processor (BK-Tree + Shannon Entropy), autonomous DNS sinkholing,
and periodic Apache Parquet lakehouse archiver in a single, high-throughput process.
"""

import asyncio
import logging
import os
import signal
import sys
import threading
import time

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure project root is in python path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.ingestion.certstream_producer import create_kafka_producer, stream_live_certstream
from src.processing.cyber_stream_processor import CyberStreamProcessor
from src.lakehouse.parquet_archiver import archive_cyber_data

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("SentinelMasterOrchestrator")


def run_producer_thread(stop_event):
    """Background worker streaming real-time global SSL/TLS certificates into Kafka."""
    logger.info("Initializing CertStream WebSocket Producer to Kafka (Port 9095)...")
    try:
        producer = create_kafka_producer()
        stream_live_certstream(producer)
    except Exception as e:
        logger.error(f"Producer thread encountered an error: {e}")


def run_processor_thread(stop_event):
    """Background worker consuming from Kafka, executing BK-Tree & Shannon Entropy algorithms."""
    logger.info("Initializing Cyber Threat Stream Processor (BK-Tree + Entropy Engine)...")
    try:
        processor = CyberStreamProcessor()
        processor.run()
    except Exception as e:
        logger.error(f"Stream processor thread encountered an error: {e}")


def run_archiver_loop(stop_event):
    """Periodic cold-storage archiver running every 60 seconds into Snappy Parquet."""
    logger.info("Cold Lakehouse Archiver active (period: 60s)...")
    while not stop_event.is_set():
        time.sleep(60)
        try:
            stats = archive_cyber_data()
            if stats["threats_archived"] > 0 or stats["certs_archived"] > 0:
                logger.info(f"🏛️ [LAKEHOUSE] Periodic archive cycle complete: {stats}")
        except Exception as e:
            logger.error(f"Archiver loop error: {e}")


def main():
    print("""
============================================================================
🌐  ZERO-HOUR CYBER THREAT & PHISHING SENTINEL (LIVE CERTSTREAM SOC)  🌐
============================================================================
Pure Big Data Engineering (Kappa Architecture) — 100% Real-Time Live Data:
  • Live Ingestion: wss://certstream.calidog.io (50-100+ certs/sec globally)
  • Stream Backbone: Apache Kafka (localhost:9095 / cyber.certstream.raw)
  • Deduplication: Redis 7 In-Memory Set / Bloom (localhost:6380)
  • Algorithmic Analytics:
      - Shannon Information Entropy (H(X) >= 4.15 bits for DGA Botnets)
      - BK-Tree Metric Tree & Levenshtein Distance (O(log N), < 0.1ms)
  • Hot Storage & Enforcement: PostgreSQL 14 (localhost:5434 / cyber_threat_db)
  • Autonomous Mitigation: DNS RPZ Sinkhole (0.0.0.0 redirection)
  • Cold Storage: Snappy Apache Parquet Lakehouse (data/lakehouse/)
  • SOC Radar Visualizer: Grafana (localhost:3000 / cyber_threat_sentinel_v1)
============================================================================
    """)

    stop_event = threading.Event()

    # 1. Start Cyber Stream Processor (Consumer)
    proc_thread = threading.Thread(target=run_processor_thread, args=(stop_event,), daemon=True)
    proc_thread.start()

    time.sleep(3)  # Allow consumer to establish partition assignment

    # 2. Start Live CertStream Producer
    prod_thread = threading.Thread(target=run_producer_thread, args=(stop_event,), daemon=True)
    prod_thread.start()

    # 3. Start Lakehouse Archiver
    arch_thread = threading.Thread(target=run_archiver_loop, args=(stop_event,), daemon=True)
    arch_thread.start()

    logger.info("⚡ All Cyber Sentinel subsystems are running. Press Ctrl+C to terminate.")

    def signal_handler(sig, frame):
        logger.info("Shutdown signal received. Stopping Sentinel gracefully...")
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting...")
        stop_event.set()


if __name__ == "__main__":
    main()
