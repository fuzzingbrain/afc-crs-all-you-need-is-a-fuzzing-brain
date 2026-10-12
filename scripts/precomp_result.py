#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One TSV line describing a finished run, read from MongoDB.

    precomp_result.py <run_id>   ->   status<TAB>povs<TAB>sps<TAB>cost<TAB>note

status is the run's own status ("completed" when the POV target was reached,
"error" on timeout/budget, "cancelled" on Ctrl+C) or "missing" when the run
never reached the database (crashed before it could register).
"""
import sys

from bson import ObjectId
from pymongo import MongoClient


def main() -> int:
    tid = sys.argv[1]
    db = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)["fuzzingbrain"]
    run = db.runs.find_one({"_id": ObjectId(tid)})
    if not run:
        print("missing\t0\t0\t0\tno run record")
        return 0
    oid = ObjectId(tid)
    povs = db.povs.count_documents({"run_id": oid, "is_successful": True})
    sps = db.suspicious_points.count_documents({"run_id": oid})
    cost = float(run.get("llm_cost") or 0)
    note = (run.get("error_msg") or "").replace("\t", " ").replace("\n", " ")[:80]
    print(f"{run.get('status')}\t{povs}\t{sps}\t{cost:.2f}\t{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
