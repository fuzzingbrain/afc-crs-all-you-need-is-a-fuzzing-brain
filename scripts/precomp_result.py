#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One TSV line describing a finished task, read from MongoDB.

    precomp_result.py <task_id>   ->   status<TAB>povs<TAB>sps<TAB>cost<TAB>note

status is the task's own status ("completed" when the POV target was reached,
"error" on timeout/budget, "cancelled" on Ctrl+C) or "missing" when the task
never reached the database (crashed before it could register).
"""
import sys

from bson import ObjectId
from pymongo import MongoClient


def main() -> int:
    tid = sys.argv[1]
    db = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)["fuzzingbrain"]
    task = db.tasks.find_one({"_id": ObjectId(tid)})
    if not task:
        print("missing\t0\t0\t0\tno task record")
        return 0
    oid = ObjectId(tid)
    povs = db.povs.count_documents({"task_id": oid, "is_successful": True})
    sps = db.suspicious_points.count_documents({"task_id": oid})
    cost = float(task.get("llm_cost") or 0)
    note = (task.get("error_msg") or "").replace("\t", " ").replace("\n", " ")[:80]
    print(f"{task.get('status')}\t{povs}\t{sps}\t{cost:.2f}\t{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
