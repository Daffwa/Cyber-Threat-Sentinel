"""Cold Data Lakehouse Archiver (Snappy Apache Parquet).

Archives cyber threats and raw certificate telemetry into partitioned
Apache Parquet files (year=YYYY/month=MM/day=DD/) for threat intelligence audits.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any
import pandas as pd
import psycopg2
import pyarrow as pa
import pyarrow.parquet as pq

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CyberParquetArchiver")

BASE_LAKEHOUSE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "lakehouse")
PG_CONFIG = {
    "host": "localhost",
    "port": 5434,
    "user": "cyber_admin",
    "password": "cyber_secret",
    "dbname": "cyber_threat_db"
}


def archive_cyber_data(base_dir: str = BASE_LAKEHOUSE_DIR, pg_config: Dict = PG_CONFIG) -> Dict[str, int]:
    """Export recent certificates and phishing alerts to partitioned Snappy Parquet files."""
    now = datetime.now(timezone.utc)
    year_str = now.strftime("%Y")
    month_str = now.strftime("%m")
    day_str = now.strftime("%d")
    timestamp_suffix = now.strftime("%Y%m%d_%H%M%S")

    conn = psycopg2.connect(**pg_config)
    stats = {"certs_archived": 0, "threats_archived": 0, "blocks_archived": 0}

    try:
        # 1. Archive Phishing Threats
        threat_df = pd.read_sql("SELECT * FROM phishing_threats ORDER BY timestamp DESC LIMIT 5000;", conn)
        if not threat_df.empty:
            threat_dir = os.path.join(base_dir, "threats", f"year={year_str}", f"month={month_str}", f"day={day_str}")
            os.makedirs(threat_dir, exist_ok=True)
            threat_file = os.path.join(threat_dir, f"phishing_threats_{timestamp_suffix}.parquet")
            pq.write_table(pa.Table.from_pandas(threat_df), threat_file, compression="snappy")
            stats["threats_archived"] = len(threat_df)
            logger.info(f"🚨 Archived {len(threat_df)} threats to: {threat_file}")

        # 2. Archive Sinkhole Blocks
        block_df = pd.read_sql("SELECT * FROM sinkhole_blocks ORDER BY timestamp DESC LIMIT 5000;", conn)
        if not block_df.empty:
            block_dir = os.path.join(base_dir, "sinkhole_blocks", f"year={year_str}", f"month={month_str}", f"day={day_str}")
            os.makedirs(block_dir, exist_ok=True)
            block_file = os.path.join(block_dir, f"sinkhole_{timestamp_suffix}.parquet")
            pq.write_table(pa.Table.from_pandas(block_df), block_file, compression="snappy")
            stats["blocks_archived"] = len(block_df)
            logger.info(f"🚫 Archived {len(block_df)} sinkhole blocks to: {block_file}")

        # 3. Archive Certificates Stream
        cert_df = pd.read_sql("SELECT * FROM certificates_stream ORDER BY timestamp DESC LIMIT 10000;", conn)
        if not cert_df.empty:
            cert_dir = os.path.join(base_dir, "certificates", f"year={year_str}", f"month={month_str}", f"day={day_str}")
            os.makedirs(cert_dir, exist_ok=True)
            cert_file = os.path.join(cert_dir, f"certs_{timestamp_suffix}.parquet")
            pq.write_table(pa.Table.from_pandas(cert_df), cert_file, compression="snappy")
            stats["certs_archived"] = len(cert_df)
            logger.info(f"🌐 Archived {len(cert_df)} raw certs to: {cert_file}")

    except Exception as e:
        logger.error(f"Error during cyber parquet archival: {e}")
    finally:
        conn.close()

    return stats


if __name__ == "__main__":
    archive_cyber_data()
