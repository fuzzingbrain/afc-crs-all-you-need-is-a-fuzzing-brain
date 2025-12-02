#!/usr/bin/env python3
"""
Configuration management for Full Scan suspicious point analysis
"""
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class DatabaseConfig:
    """PostgreSQL database configuration"""
    host: str = "localhost"
    port: int = 5432
    database: str = "crs"
    user: str = "postgres"
    password: str = "password"

    @classmethod
    def from_env(cls) -> 'DatabaseConfig':
        """Load from environment variables"""
        return cls(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            database=os.getenv("POSTGRES_DB", "crs"),
            user=os.getenv("POSTGRES_USER", "postgres"),
            password=os.getenv("POSTGRES_PASSWORD", "password"),
        )

    def get_connection_string(self) -> str:
        """Get PostgreSQL connection string"""
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class AnalysisServiceConfig:
    """Analysis Service API configuration"""
    base_url: str = "http://localhost:7082"
    api_key_id: str = ""
    api_token: str = ""
    timeout: int = 300  # 5 minutes

    @classmethod
    def from_env(cls) -> 'AnalysisServiceConfig':
        """Load from environment variables"""
        return cls(
            base_url=os.getenv("ANALYSIS_SERVICE_URL", "http://localhost:7082"),
            api_key_id=os.getenv("COMPETITION_API_KEY_ID", ""),
            api_token=os.getenv("COMPETITION_API_KEY_TOKEN", ""),
            timeout=int(os.getenv("ANALYSIS_SERVICE_TIMEOUT", "300")),
        )


@dataclass
class LLMConfig:
    """LLM configuration for suspicious point analysis"""
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    max_tokens: int = 4096
    temperature: float = 0.0
    window_size: int = 3  # Call chain context window

    @classmethod
    def from_env(cls) -> 'LLMConfig':
        """Load from environment variables"""
        return cls(
            model=os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
            api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.0")),
            window_size=int(os.getenv("CALL_CHAIN_WINDOW_SIZE", "3")),
        )


@dataclass
class FuzzerConfig:
    """Fuzzer execution configuration"""
    timeout: int = 60  # seconds per fuzzer run
    memory_limit: str = "2048"  # MB
    max_pov_attempts: int = 3  # Max attempts per suspicious point

    @classmethod
    def from_env(cls) -> 'FuzzerConfig':
        """Load from environment variables"""
        return cls(
            timeout=int(os.getenv("FUZZER_TIMEOUT", "60")),
            memory_limit=os.getenv("FUZZER_MEMORY_LIMIT", "2048"),
            max_pov_attempts=int(os.getenv("MAX_POV_ATTEMPTS", "3")),
        )


@dataclass
class FullScanConfig:
    """Complete Full Scan configuration"""
    # Sub-configs
    database: DatabaseConfig
    analysis_service: AnalysisServiceConfig
    llm: LLMConfig
    fuzzer: FuzzerConfig

    # Task information
    task_id: str
    project_name: str
    focus: str
    language: str
    sanitizer: str
    fuzzer_path: str
    project_dir: str

    # Execution settings
    max_iterations: int = 100  # Max suspicious points to analyze
    deadline_timestamp: Optional[int] = None

    @classmethod
    def from_env(cls, task_id: str, project_name: str, focus: str,
                 language: str, sanitizer: str, fuzzer_path: str,
                 project_dir: str) -> 'FullScanConfig':
        """
        Create configuration from environment variables

        Args:
            task_id: Task UUID
            project_name: Project name (e.g., "libxml2")
            focus: Focus directory (e.g., "afc-libxml2")
            language: Programming language (c/java)
            sanitizer: Sanitizer type (address/memory/undefined)
            fuzzer_path: Path to fuzzer executable
            project_dir: Project source directory
        """
        return cls(
            database=DatabaseConfig.from_env(),
            analysis_service=AnalysisServiceConfig.from_env(),
            llm=LLMConfig.from_env(),
            fuzzer=FuzzerConfig.from_env(),
            task_id=task_id,
            project_name=project_name,
            focus=focus,
            language=language,
            sanitizer=sanitizer,
            fuzzer_path=fuzzer_path,
            project_dir=project_dir,
            max_iterations=int(os.getenv("MAX_SUSPICIOUS_POINTS", "100")),
            deadline_timestamp=int(os.getenv("TASK_DEADLINE")) if os.getenv("TASK_DEADLINE") else None,
        )

    def __str__(self) -> str:
        """Pretty print configuration"""
        return f"""
Full Scan Configuration:
========================
Task ID: {self.task_id}
Project: {self.project_name}
Focus: {self.focus}
Language: {self.language}
Sanitizer: {self.sanitizer}
Fuzzer: {self.fuzzer_path}
Project Dir: {self.project_dir}

Database: {self.database.host}:{self.database.port}/{self.database.database}
Analysis Service: {self.analysis_service.base_url}
LLM Model: {self.llm.model}
Max Iterations: {self.max_iterations}
"""


# Singleton instance
_config: Optional[FullScanConfig] = None


def get_config() -> FullScanConfig:
    """Get global configuration instance"""
    global _config
    if _config is None:
        raise RuntimeError("Configuration not initialized. Call init_config() first.")
    return _config


def init_config(task_id: str, project_name: str, focus: str,
                language: str, sanitizer: str, fuzzer_path: str,
                project_dir: str) -> FullScanConfig:
    """
    Initialize global configuration

    Args:
        task_id: Task UUID
        project_name: Project name
        focus: Focus directory
        language: Programming language
        sanitizer: Sanitizer type
        fuzzer_path: Path to fuzzer executable
        project_dir: Project source directory

    Returns:
        Initialized configuration
    """
    global _config
    _config = FullScanConfig.from_env(
        task_id=task_id,
        project_name=project_name,
        focus=focus,
        language=language,
        sanitizer=sanitizer,
        fuzzer_path=fuzzer_path,
        project_dir=project_dir
    )
    return _config
