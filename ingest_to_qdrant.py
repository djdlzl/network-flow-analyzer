"""AWS 네트워크 CSV → Qdrant 업서트 스크립트

Prerequisite:
1. Qdrant 서버 실행 (로컬 `docker run -p 6333:6333 -p 6334:6334 -d qdrant/qdrant` 등)
2. `aws_network_outputs` 폴더에 계정별 `network_data_<account>.csv` 존재

Usage:
    python ingest_to_qdrant.py  # 기본 경로/컬렉션으로 모두 적재

환경변수:
    CSV_DIR            : CSV 폴더 경로 (default: ../tmp/network_outputs)
    QDRANT_URL         : http://localhost:6333
    QDRANT_COLLECTION  : aws_network
"""

from __future__ import annotations

import glob
import hashlib
import ipaddress
import os
import csv
from typing import Dict, Any, List

from qdrant_client import QdrantClient, models as qdrant

CSV_DIR = os.environ.get("CSV_DIR") or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tmp", "network_outputs"))
QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333")
COLLECTION = os.environ.get("QDRANT_COLLECTION", "aws_network")
VECTOR_SIZE = 1  # 의미 없는 Platzhalter 벡터 (벡터 검색 안씀)

client = QdrantClient(url=QDRANT_URL)

def ensure_collection():
    if COLLECTION in [c.name for c in client.get_collections().collections]:
        return
    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=qdrant.VectorParams(size=VECTOR_SIZE, distance=qdrant.Distance.DOT),
        optimizers_config=qdrant.OptimizersConfigDiff(memmap_threshold=20000),
    )
    print(f"[INIT] Created collection {COLLECTION}")


def cidr_to_range(cidr: str):
    """Return (start_int, end_int) for both v4/v6."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None, None
    # IPv6 too big for 64-bit, but Qdrant numeric stores float64, so convert to int via int()
    return int(net.network_address), int(net.broadcast_address)


def iter_csv_rows():
    for path in glob.glob(os.path.join(CSV_DIR, "*.csv")):
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                yield r


def upsert():
    points: List[qdrant.PointStruct] = []
    for row in iter_csv_rows():
        cidr = row.get("IpCidr") or ""
        start, end = cidr_to_range(cidr)
        row["cidr_start"], row["cidr_end"] = start, end
        # point id deterministic hash
        uid_base = f"{row.get('ResourceType')}_{row.get('ResourceId')}_{cidr}"
        pid = int(hashlib.md5(uid_base.encode()).hexdigest()[:16], 16)  # 64-bit int
        points.append(qdrant.PointStruct(id=pid, vector=[0.0], payload=row))
        # batch flush every 1000
        if len(points) >= 1000:
            client.upsert(COLLECTION, points=points)
            print(f"Upserted {len(points)} points…")
            points.clear()
    if points:
        client.upsert(COLLECTION, points=points)
        print(f"Upserted {len(points)} points (final)")


if __name__ == "__main__":
    ensure_collection()
    upsert()
    print("✅ Ingestion complete")

