"""
This script will run CRS on a project with a given number of tasks (a batch).

Default batch size is 60.
"""
import argparse
import os
import sys
import json
import logging
import time
import random
import string
import subprocess
import shutil
import requests
import tempfile
import shutil
import re
import threading
import concurrent.futures
from datetime import datetime
from pathlib import Path
import uuid


from dotenv import load_dotenv
from loguru import logger

from recorder import send_current_project_tasks, send_current_task_result, send_stats

# setup
load_dotenv()

# setup logging
logger.add("./logs/crs.log", rotation="100 MB", retention="180 days")

DASHBOARD_API = os.getenv("DASHBOARD_API", "http://localhost:8081")
CRS_GROUP_ID = os.getenv("CRS_GROUP_ID") or str(uuid.uuid4())

logger.info(f"CRS_GROUP_ID: {CRS_GROUP_ID}")

PER_TASK_DURATION_SEC = int(os.getenv("PER_TASK_DURATION_SEC", "3000"))
BATCH_START_TIME_ISO = os.getenv("BATCH_START_TIME")
LOG_DIR = os.getenv("CRS_LOG_DIR", os.getcwd())

def _post_json(path: str, payload: dict, timeout: int = 5):
    url = f"{DASHBOARD_API}{path}"
    try:
        # add retry
        for i in range(3):
            try:
                r = requests.post(url, json=payload, timeout=timeout)
                r.raise_for_status()
                return True, r.text
            except Exception as e:
                logger.warning(f"[dashboard] POST {url} failed: {e}")
                time.sleep(1)
        return False, str(e)
        r.raise_for_status()
        return True, r.text
    except Exception as e:
        logger.warning(f"[dashboard] POST {url} failed: {e}")
        return False, str(e)

def send_meta(group_id: str, start_time_iso: str, per_task_sec: int,
              current_project: str | None = None, current_task_id: int | None = None):
    payload = {
        "groupId": group_id,
        "startTime": start_time_iso,
        "perTaskDurationSec": per_task_sec,
    }
    if current_project is not None:
        payload["currentProject"] = current_project
    if current_task_id is not None:
        payload["currentTaskId"] = current_task_id
    return _post_json("/api/ingest/meta", payload)


def send_project_tasks(group_id: str, project: str, tasks: list[dict]):
    payload = {
        "groupId": group_id,
        "project": project,
        "tasks": tasks,
    }
    return _post_json("/api/ingest/project-tasks", payload)


def send_status(group_id: str, project: str, task_id: int, status: str, task_obj: dict | None = None):
    payload = {
        "groupId": group_id,
        "project": project,
        "taskId": task_id, 
        "status": status,   # pending|running|completed|failed|pov_found|patch_found
    }
    if task_obj is not None:
        payload["task"] = task_obj
    return _post_json("/api/ingest/status", payload)


class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    POV_FOUND = "pov_found"
    PATCH_FOUND = "patch_found"
    FAILED = "failed"
    

class Dataset:
    # has a list of current projects

    # has map of list of map (json object)

    # has a list of current tasks map {task_name: [{{task_id}: status}}, ...], ...}.
    """
    spring-boot: [{}, {}],
    rust-analyzer: [{}, {}],
    ...
    """ 
    def __init__(self, project_folder, batch_size):
        self.projects = []
        self.project_to_tasks = dict()
        self.project_to_task_numbers = dict()
        self.project_to_status = dict()  # project -> list[str]: pending|running|completed|failed
        self.current_tasks = dict()  # project -> set[int] of indices currently running
        for project in os.listdir(project_folder):
            with open(os.path.join(project_folder, project, f"{project}_{batch_size}_tasks.json"), "r") as f:
                self.project_to_tasks[project] = json.load(f)
                self.project_to_task_numbers[project] = len(self.project_to_tasks[project])
                self.project_to_status[project] = [TaskStatus.PENDING] * self.project_to_task_numbers[project]
            self.projects.append(project)
        for project in self.projects:
            self.current_tasks[project] = set()

    def get_projects(self):
        return list(self.projects)

    def get_task_count(self, project):
        return self.project_to_task_numbers.get(project, 0)

    def get_task(self, project, index):
        return self.project_to_tasks[project][index]

    def get_status(self, project, index):
        return self.project_to_status[project][index]

    def acquire_next_pending(self, project):
        """Acquire next pending task index and mark it as running. Returns (index, task) or (None, None)."""
        statuses = self.project_to_status.get(project)
        if statuses is None:
            return None, None
        for idx, status in enumerate(statuses):
            if status == TaskStatus.PENDING:
                statuses[idx] = TaskStatus.RUNNING
                self.current_tasks[project].add(idx)
                return idx, self.project_to_tasks[project][idx]
        return None, None
    
    def mark_running(self, project, index):
        self._mark(project, index, TaskStatus.RUNNING)

    def mark_completed(self, project, index):
        self._mark(project, index, TaskStatus.COMPLETED)

    def mark_failed(self, project, index):
        self._mark(project, index, TaskStatus.FAILED)

    def mark_pov_found(self, project, index):
        self._mark(project, index, TaskStatus.POV_FOUND)

    def mark_patch_found(self, project, index):
        self._mark(project, index, TaskStatus.PATCH_FOUND)

    def release_running(self, project, index):
        """Release a running task back to pending (e.g., worker crash)."""
        if project in self.current_tasks and index in self.current_tasks[project]:
            self.current_tasks[project].discard(index)
            self.project_to_status[project][index] = TaskStatus.PENDING

    def _mark(self, project, index, new_status):
        if project not in self.project_to_status:
            return
        if 0 <= index < len(self.project_to_status[project]):
            self.project_to_status[project][index] = new_status
            if project in self.current_tasks:
                self.current_tasks[project].discard(index)

    def stats(self, project=None):
        """Return aggregate stats. If project is None, returns totals across all projects."""
        def count_status(status_list):
            summary = {
                TaskStatus.PENDING: 0,
                TaskStatus.RUNNING: 0,
                TaskStatus.COMPLETED: 0,
                TaskStatus.FAILED: 0,
                TaskStatus.POV_FOUND: 0,
                TaskStatus.PATCH_FOUND: 0,
            }
            for s in status_list:
                if s in summary:
                    summary[s] += 1
            return summary

        if project:
            return count_status(self.project_to_status.get(project, []))
        total = {
            TaskStatus.PENDING: 0,
            TaskStatus.RUNNING: 0,
            TaskStatus.COMPLETED: 0,
            TaskStatus.FAILED: 0,
            TaskStatus.POV_FOUND: 0,
            TaskStatus.PATCH_FOUND: 0,
        }
        for prj in self.projects:
            prj_sum = count_status(self.project_to_status.get(prj, []))
            for k in total:
                total[k] += prj_sum[k]
        return total

    def save_progress(self, output_path):
        """Persist status to a JSON file for later resume/inspection."""
        snapshot = {
            "projects": self.projects,
            "task_numbers": self.project_to_task_numbers,
            "status": self.project_to_status,
        }
        with open(output_path, "w") as f:
            json.dump(snapshot, f, indent=2)
    




# global variables: ENTER YOUR PROJECT BATCH JSON FILE FOLDER HERE
project_folder = "/home/ze/new_crs/afc-crs-all-you-need-is-a-fuzzing-brain/task_builder/projects"
batch_size = 60

dataset = Dataset(project_folder, batch_size)
logger.info(f"Loaded {len(dataset.projects)} projects with {batch_size} tasks each")
logger.info(f"Project to task numbers: {dataset.project_to_task_numbers}")
logger.info(f"Current tasks: {dataset.current_tasks}")
# show stats
logger.info(f"Stats: {dataset.stats()}")

_batch_start_iso = BATCH_START_TIME_ISO or datetime.utcnow().isoformat() + "Z"
ok, _ = send_meta(
    CRS_GROUP_ID,
    start_time_iso=_batch_start_iso,
    per_task_sec=PER_TASK_DURATION_SEC,
    current_project=None,
    current_task_id=None,
)
if not ok:
    logger.warning("[dashboard] send_meta failed")


for _proj in dataset.projects:
    try:
        _tasks = dataset.project_to_tasks[_proj]
        ok, _ = send_project_tasks(CRS_GROUP_ID, _proj, _tasks)
        if not ok:
            logger.warning(f"[dashboard] send_project_tasks({_proj}) failed")
    except Exception as e:
        logger.warning(f"[dashboard] send_project_tasks({_proj}) exception: {e}")


# Run CRS
"""
Example task:
{
    "id": 1,
    "challenge_repo_url": "https://github.com/spring-projects/spring-boot.git",
    "challenge_repo_base_ref": "fd4f2b8af5337c3c7c6275be7e8ce538fc395ea1",
    "challenge_repo_head_ref": "6207e41473d52ffa2075c9b7af1c267c2ea013e5",
    "fuzz_tooling_url": "git@github.com:OwenSanzas/fuzzing-brain-oss-fuzz.git",
    "fuzz_tooling_ref": "34a63267342dbaebe65b41e2172f43273dceb0ff",
    "fuzz_tooling_project_name": "spring-boot",
    "duration": 720
  },

"""

for project in dataset.projects:
    logger.info(f"Running CRS on project {project}")

    current_tasks = dataset.project_to_tasks[project]

    logger.info(f"Current tasks: {len(current_tasks)}")

    for task in current_tasks:
        # if project == "fwupd" or project == "igraph":
        #     dataset.mark_completed(project, task["id"])
        #     continue

        task_id = task["id"]
        challenge_repo_url = task["challenge_repo_url"]
        challenge_repo_base_ref = task["challenge_repo_base_ref"]
        challenge_repo_head_ref = task["challenge_repo_head_ref"]
        fuzz_tooling_url = task["fuzz_tooling_url"]
        fuzz_tooling_ref = task["fuzz_tooling_ref"]
        fuzz_tooling_project_name = task["fuzz_tooling_project_name"]

        send_meta(
            CRS_GROUP_ID,
            start_time_iso=_batch_start_iso,
            per_task_sec=PER_TASK_DURATION_SEC,
            current_project=project,
            current_task_id=task_id,
        )

        log_file_name = f"crs_log_{project}_{task_id}.log"
        LOG_DIR = '/home/ze/new_crs/afc-crs-all-you-need-is-a-fuzzing-brain/crs/logs'
        log_path = os.path.abspath(os.path.join(LOG_DIR, log_file_name))

        task_payload = {
            "id": task_id,
            "challenge_repo_url": challenge_repo_url,
            "challenge_repo_base_ref": challenge_repo_base_ref,
            "challenge_repo_head_ref": challenge_repo_head_ref,
            "fuzz_tooling_url": fuzz_tooling_url,
            "fuzz_tooling_ref": fuzz_tooling_ref,
            "fuzz_tooling_project_name": fuzz_tooling_project_name,
            "duration": PER_TASK_DURATION_SEC,
            "workspace": os.path.join(f"/home/ze/crs_dataset/dataset_{project}", f"{project}_{task_id}"),
            "log_path": log_path,
        }
        send_status(CRS_GROUP_ID, project, task_id, "running", task_payload)

        
        # change task to running
        dataset.mark_running(project, task_id)

        # show stats
        logger.info(f"Stats: {dataset.stats()}")

        # hardcode duration to 900 seconds -> including building the project
        duration = 3000
        
        logger.info(f"Running CRS on task {task_id} of project {project}")

        # build the task files

        """
        build_task.py

        Build a task for the CRS system.
        
        Parameters:
        -r, --base-github-repo-link: base github repo link
        -b, --base-github-repo-version: base github repo version
        -c, --reference-github-repo-version: reference github repo version
        -o, --oss-fuzz-link: oss-fuzz link, default: https://github.com/google/oss-fuzz
        -f, --oss-fuzz-version: oss-fuzz version
        --output-dir: output directory for the task (default: ./output)
        --zip-name: custom name for the output ZIP file (without .zip extension)
        """

        dataset_path = f"/home/ze/crs_dataset/dataset_{project}"
        zip_name = f"{project}_{task_id}"

        # run python script to build the task files
        subprocess.run([
        "python", 
        "build_task.py", 
        "-r", challenge_repo_url, 
        "-b", challenge_repo_base_ref, 
        "-c", challenge_repo_head_ref, 
        "-o", fuzz_tooling_url, 
        "-f", fuzz_tooling_ref,
        "--output-dir", dataset_path, 
        "--zip-name", zip_name
        ])

        full_zip_path = os.path.join(dataset_path, f"{zip_name}.zip")

        if not os.path.exists(dataset_path):
            logger.error(f"Dataset path {dataset_path} does not exist")
            dataset.mark_failed(project, task_id)
            continue
        if not os.path.exists(full_zip_path):
            logger.error(f"Zip file {full_zip_path} does not exist")
            dataset.mark_failed(project, task_id)
            continue

        logger.info(f"Built task files for task {task_id} of project {project}")

        # check if the workspace directory exists
        workspace_path = os.path.join(dataset_path, f"{zip_name}")
        if not os.path.exists(workspace_path):
            logger.error(f"Workspace path {workspace_path} does not exist")
            dataset.mark_failed(project, task_id)
            continue
        
        logger.info(f"Workspace path {workspace_path} exists")

        # run script to run the CRS
        # sudo ./run_crs.sh workspace_path log_file_name

        #limit time to 3000 seconds
        res = subprocess.run([
            "sudo", "-n",
            "timeout", "-s", "TERM", "-k", "10s", "3000s",
            "./run_crs.sh", workspace_path, f"crs_log_{project}_{task_id}"
        ])

        # TEST_ONLY: sleep 10 seconds
        # res = subprocess.run([
        #     "sleep", "10"
        # ])

        if res.returncode == 0:
            send_status(CRS_GROUP_ID, project, task_id, "completed", {"log_path": log_path})
            logger.info(f"Task {project}:{task_id} completed successfully")
            dataset.mark_completed(project, task_id)
        elif res.returncode == 124:
            send_status(CRS_GROUP_ID, project, task_id, "completed", {"log_path": log_path})
            logger.error(f"Task {project}:{task_id} timed out (rc=124)")
            dataset.mark_completed(project, task_id)
        elif res.returncode == 137:
            send_status(CRS_GROUP_ID, project, task_id, "completed", {"log_path": log_path})
            logger.error(f"Task {project}:{task_id} killed (rc=137)")
            dataset.mark_completed(project, task_id)
        else:
            send_status(CRS_GROUP_ID, project, task_id, "failed", {"log_path": log_path})
            logger.error(f"Task {project}:{task_id} failed, rc={res.returncode}")
            dataset.mark_failed(project, task_id)

        # show stats
        logger.info(f"Stats: {dataset.stats()}")

    
    # send_current_project_tasks(project, current_tasks)








