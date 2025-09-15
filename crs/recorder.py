"""
Send http request to the server to render the task and save the result.
"""

import requests


URL = "http://localhost:8080"

def send_current_project_tasks(project, tasks):
    """
    Send the current project tasks to the server to render and save the result.
    """
    current_tasks = {
        "project": project,
        "tasks": tasks
    }

    """ if error, no crash, just print the error """
    try:
        requests.post(f"{URL}/current_project_tasks", json=current_tasks)
    except Exception as e:
        print(f"Error sending current project tasks to the server: {e}")

    print(f"Sent current project tasks to the server: {current_tasks}")

def send_current_task_result(project, task_id, result):
    """
    Send the current task result to the server to save the result.
    """
    pass

def send_stats(stats):
    """
    Send the stats to the server to save the stats.
    """
    pass



