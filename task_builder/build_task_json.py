#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Adjacent Commits Generator
Fetches all commits from a repository and generates JSON configurations for adjacent commit pairs
"""

import requests
import json
import time
import argparse
import os
from typing import List, Dict, Optional

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip

class GitHubCommitPairGenerator:
    def __init__(self, token: Optional[str] = None):
        """
        Initialize the generator
        :param token: GitHub Personal Access Token
        """
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            })
    
    def get_repo_default_branch(self, repo_owner: str, repo_name: str) -> str:
        """
        Get the default branch of the repository
        :param repo_owner: Repository owner
        :param repo_name: Repository name
        :return: Default branch name
        """
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            repo_info = response.json()
            return repo_info.get('default_branch', 'main')
        except requests.exceptions.RequestException as e:
            print(f"Warning: Could not get repo info: {e}")
            return 'main'
    
    def get_all_commits(self, repo_owner: str, repo_name: str, 
                       branch: str = None, max_commits: int = None) -> List[str]:
        """
        Get all commit SHAs from the repository
        :param repo_owner: Repository owner
        :param repo_name: Repository name
        :param branch: Branch name (None for auto-detect)
        :param max_commits: Maximum number of commits to fetch
        :return: List of commit SHAs (in reverse chronological order)
        """
        # Auto-detect default branch if not specified
        if branch is None:
            branch = self.get_repo_default_branch(repo_owner, repo_name)
            print(f"Auto-detected default branch: {branch}")
        
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits"
        commits = []
        page = 1
        per_page = 100
        
        print(f"Fetching commits from {repo_owner}/{repo_name}...")
        
        while True:
            if max_commits and len(commits) >= max_commits:
                commits = commits[:max_commits]
                break
                
            params = {
                'sha': branch,
                'per_page': per_page,
                'page': page
            }
            
            try:
                response = self.session.get(url, params=params)
                response.raise_for_status()
                
                # Check API rate limits
                remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                if remaining < 10:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_time = reset_time - int(time.time()) + 60
                    print(f"API rate limit almost exceeded, waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                
                page_commits = response.json()
                if not page_commits:
                    break
                
                for commit in page_commits:
                    commits.append(commit['sha'])
                
                print(f"Fetched {len(commits)} commits so far")
                page += 1
                
                time.sleep(0.1)  # Avoid too frequent requests
                
            except requests.exceptions.RequestException as e:
                print(f"Request error: {e}")
                break
        
        print(f"Total commits fetched: {len(commits)}")
        return commits
    
    def generate_commit_pairs(self, commits: List[str], repo_url: str,
                             fuzz_tooling_url: str = "git@github.com:OwenSanzas/fuzzing-brain-oss-fuzz.git",
                             fuzz_tooling_ref: str = "0ec14aafb616fed7ed2dd1aebbabe69b23b3e708",
                             fuzz_tooling_project_name: str = "igraph",
                             duration: int = 720) -> List[Dict]:
        """
        Generate configurations for adjacent commit pairs
        :param commits: List of commit SHAs (in reverse chronological order)
        :param repo_url: Repository URL
        :param fuzz_tooling_url: Fuzz tooling URL
        :param fuzz_tooling_ref: Fuzz tooling reference
        :param fuzz_tooling_project_name: Project name
        :param duration: Duration value
        :return: List of configurations
        """
        pairs = []
        
        # Commits are in reverse chronological order, so adjacent commits form base_ref -> head_ref
        for i in range(len(commits) - 1):
            head_ref = commits[i]      # Newer commit
            base_ref = commits[i + 1]  # Older commit
            
            # Generate unique ID for this task (starting from 1)
            task_id = i + 1
            
            pair = {
                "id": task_id,
                "challenge_repo_url": repo_url,
                "challenge_repo_base_ref": base_ref,
                "challenge_repo_head_ref": head_ref,
                "fuzz_tooling_url": fuzz_tooling_url,
                "fuzz_tooling_ref": fuzz_tooling_ref,
                "fuzz_tooling_project_name": fuzz_tooling_project_name,
                "duration": duration
            }
            pairs.append(pair)
        
        return pairs

def main():
    parser = argparse.ArgumentParser(description='Generate JSON configurations for adjacent GitHub commits')
    parser.add_argument('--repo', required=True, help='Repository URL (supports https://, git@, or owner/repo format)')
    parser.add_argument('--token', help='GitHub Personal Access Token (default: read from GITHUB_TOKEN env var)')
    parser.add_argument('--branch', default=None, help='Branch name (default: auto-detect repository default branch)')
    parser.add_argument('--max-commits', type=int, default=61, help='Maximum number of commits to fetch (default: 61 for 60 pairs)')
    parser.add_argument('--output', default=None, help='Output file name (default: auto-generated as project_name_number_tasks.json)')
    parser.add_argument('--fuzz-url', default='git@github.com:OwenSanzas/fuzzing-brain-oss-fuzz.git', 
                       help='Fuzz tooling URL')
    parser.add_argument('--fuzz-ref', default='0ec14aafb616fed7ed2dd1aebbabe69b23b3e708',
                       help='Fuzz tooling reference')
    parser.add_argument('--project-name', required=True, help='Project name (required)')
    parser.add_argument('--duration', type=int, default=720, help='Duration value')
    
    args = parser.parse_args()
    
    # Get GitHub token from environment or command line
    token = args.token or os.getenv('GITHUB_TOKEN')
    if not token:
        print("Warning: No GitHub token provided. API requests will be limited.")
        print("Solutions:")
        print("  1. Create .env file: echo 'GITHUB_TOKEN=your_token' > .env")
        print("  2. Export variable: export GITHUB_TOKEN=your_token")
        print("  3. Use --token argument")
        print("  4. Install python-dotenv: pip install python-dotenv")
    else:
        print(f"✓ Using GitHub token (ends with: ...{token[-4:]})")
    
    # Parse repository information from various URL formats
    def parse_repo_url(repo_input: str):
        """Parse different GitHub URL formats"""
        # Remove trailing .git if present
        repo_input = repo_input.removesuffix('.git')  # Python 3.9+
        
        if repo_input.startswith('https://github.com/'):
            # https://github.com/owner/repo
            repo_path = repo_input.replace('https://github.com/', '')
            parts = repo_path.split('/')
            if len(parts) >= 2:
                owner, name = parts[0], parts[1]
            else:
                raise ValueError("Invalid repository format")
            repo_url = f"https://github.com/{owner}/{name}.git"
        elif repo_input.startswith('git@github.com:'):
            # git@github.com:owner/repo
            repo_path = repo_input.replace('git@github.com:', '')
            parts = repo_path.split('/')
            if len(parts) >= 2:
                owner, name = parts[0], parts[1]
            else:
                raise ValueError("Invalid repository format")
            repo_url = f"https://github.com/{owner}/{name}.git"
        elif '/' in repo_input and not repo_input.startswith('http'):
            # owner/repo format
            parts = repo_input.split('/')
            if len(parts) >= 2:
                owner, name = parts[0], parts[1]
            else:
                raise ValueError("Invalid repository format")
            repo_url = f"https://github.com/{owner}/{name}.git"
        else:
            raise ValueError("Invalid repository format")
        
        print(f"Parsed repository: owner='{owner}', name='{name}', url='{repo_url}'")
        return owner, name, repo_url
    
    try:
        owner, name, repo_url = parse_repo_url(args.repo)
    except ValueError:
        print("Error: Repository format should be:")
        print("  - https://github.com/owner/repo")
        print("  - git@github.com:owner/repo") 
        print("  - owner/repo")
        return
    
    # Initialize the generator
    scraper = GitHubCommitPairGenerator(token)
    
    # Get all commits
    commits = scraper.get_all_commits(owner, name, args.branch, args.max_commits)
    
    if len(commits) < 2:
        print("Error: At least 2 commits are required to generate configuration pairs")
        return
    
    # Generate configuration pairs
    pairs = scraper.generate_commit_pairs(
        commits, repo_url, args.fuzz_url, args.fuzz_ref, 
        args.project_name, args.duration
    )
    
    # Auto-generate output filename if not specified
    if args.output is None:
        output_filename = f"{args.project_name}_{len(pairs)}_tasks.json"
    else:
        output_filename = args.output
    
    # Save to file
    with open(output_filename, 'w', encoding='utf-8') as f:
        json.dump(pairs, f, indent=2, ensure_ascii=False)
    
    print(f"Generated {len(pairs)} commit configuration pairs (tasks)")
    print(f"Saved to: {output_filename}")
    
    # Show first few examples
    print(f"\nFirst 3 task examples out of {len(pairs)} total:")
    for i, pair in enumerate(pairs[:3]):
        print(f"\nTask {pair['id']}:")
        print(f"  base_ref:  {pair['challenge_repo_base_ref'][:12]}...")
        print(f"  head_ref:  {pair['challenge_repo_head_ref'][:12]}...")
    
    if len(pairs) >= 60:
        print(f"\n✓ Generated {len(pairs)} tasks (target: 60 tasks achieved!)")
    else:
        print(f"\n⚠ Only generated {len(pairs)} tasks (target was 60 tasks)")
        print(f"  Repository may have fewer than 61 commits")

if __name__ == "__main__":
    # If running directly, you can set default parameters here
    # Example usage:
    print("GitHub Adjacent Commits Generator")
    print("=" * 50)
    print("Usage examples:")
    print("# Method 1: Use .env file")
    print("echo 'GITHUB_TOKEN=your_token_here' > .env")
    print("python script.py --repo https://github.com/fwupd/fwupd.git --project-name fwupd")
    print("")
    print("# Method 2: Different project")
    print("python script.py --repo git@github.com:igraph/igraph.git --project-name igraph")
    print("")
    print("# Method 3: Custom fuzz version")
    print("python script.py --repo fwupd/fwupd --project-name fwupd --fuzz-ref 881cc790c923808a70b1895c16b98b47ce8b0711")
    print("# Output: fwupd_60_tasks.json (auto-generated filename)")
    print("")
    print("# Default: fetches 61 commits to generate 60 task pairs")
    print("# Output file: project_name_number_tasks.json")
    print("# Note: Install python-dotenv for .env file support: pip install python-dotenv")
    print()
    
    # If no arguments provided, show help
    import sys
    if len(sys.argv) == 1:
        print("Please provide arguments, use --help for detailed instructions")
    else:
        main()