"""
Strategy Logger
Unified logging for all strategies using loguru
"""
import os
import time
import datetime
from typing import TYPE_CHECKING
from loguru import logger as global_logger

if TYPE_CHECKING:
    from common.config import StrategyConfig


class StrategyLogger:
    """Centralized logging for strategies using loguru with isolated logger instance"""

    def __init__(self, config: 'StrategyConfig'):
        self.config = config
        # Create an isolated logger instance (avoids conflicts with parallel strategies)
        self.logger = global_logger.bind(strategy=config.strategy_name)
        self.log_file = self._setup_logging()

    def _setup_logging(self) -> str:
        """Setup logging and return log file path"""
        # Create log filename based on strategy config
        patch_status = "patch_only" if self.config.do_patch_only else "basic_pov_delta_strategy"
        scan_type = "full_scan" if self.config.full_scan else "delta_scan"

        timestamp = int(time.time())
        log_filename = f"{self.config.strategy_name}_{self.config.fuzzer_name}_{patch_status}_{scan_type}_{timestamp}.log"
        log_file = os.path.join(self.config.log_dir, log_filename)

        # Ensure log directory exists
        os.makedirs(self.config.log_dir, exist_ok=True)

        # Add file handler for THIS strategy only
        # Using filter to ensure only this strategy's logs go to its file
        handler_id = self.logger.add(
            log_file,
            format="{message}",  # Simple format, just the message
            level="DEBUG",
            enqueue=True,  # Thread-safe
            backtrace=True,  # Better error traces
            diagnose=True,
            filter=lambda record: record["extra"].get("strategy") == self.config.strategy_name
        )

        # Store handler ID for potential cleanup
        self.file_handler_id = handler_id

        # Write initial configuration header
        self.logger.info("=" * 80)
        self.logger.info(f"Strategy: {self.config.strategy_name}")
        self.logger.info(f"Fuzzer: {self.config.fuzzer_name}")
        self.logger.info(f"Timestamp: {timestamp} ({datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')})")
        self.logger.info(f"DO_PATCH_ONLY: {self.config.do_patch_only}")
        self.logger.info(f"FULL_SCAN: {self.config.full_scan}")
        self.logger.info(f"FUZZING_TIMEOUT_MINUTES: {self.config.fuzzing_timeout_minutes}")
        self.logger.info(f"MAX_ITERATIONS: {self.config.max_iterations}")
        self.logger.info(f"LOG_DIR: {self.config.log_dir}")
        self.logger.info(f"POV_SUCCESS_DIR: {self.config.pov_success_dir}")
        self.logger.info(f"MODELS: {', '.join(self.config.models)}")
        self.logger.info("=" * 80)

        return log_file

    def log(self, message: str):
        """Log an info message"""
        self.logger.info(message)

    def log_cost(self, model_name: str, cost: float):
        """Log model cost"""
        self.logger.info(f"Model: {model_name}, Cost: ${cost:.4f}")

    def log_time(self, start_time: float, end_time: float, function_name: str, description: str = ""):
        """Log execution time"""
        elapsed = end_time - start_time
        msg = f"[TIMING] {function_name}: {elapsed:.2f}s"
        if description:
            msg += f" - {description}"
        self.logger.info(msg)

    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)

    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)

    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)

    def success(self, message: str):
        """Log success message"""
        self.logger.success(message)

    def get_log_file(self) -> str:
        """Get the log file path"""
        return self.log_file

    def log_user_input(self, content: str, round_number: int = None):
        """
        Log user input message in a formatted way

        Args:
            content: User input content
            round_number: Optional round number for tracking conversation
        """
        self.logger.info("=" * 80)
        if round_number is not None:
            self.logger.info(f"[USER INPUT - Round {round_number}]")
        else:
            self.logger.info("[USER INPUT]")
        self.logger.info(content)
        self.logger.info("=" * 80)

    def log_llm_response(self, content: str, model_name: str = None):
        """
        Log LLM response message in a formatted way

        Args:
            content: LLM response content
            model_name: Optional model name
        """
        self.logger.info("=" * 80)
        if model_name:
            self.logger.info(f"[LLM RESPONSE - Model: {model_name}]")
        else:
            self.logger.info("[LLM RESPONSE]")
        self.logger.info(content)
        self.logger.info("=" * 80)
