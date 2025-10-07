"""
Base Strategy
Abstract base class for all strategies
"""
from abc import ABC, abstractmethod
from opentelemetry import trace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from common.config import StrategyConfig
    from common.logging.logger import StrategyLogger
    from common.llm.client import LLMClient


class BaseStrategy(ABC):
    """Base class for all CRS strategies"""

    def __init__(self, config: 'StrategyConfig'):
        self.config = config

        # Import here to avoid circular imports
        from common.logging.logger import StrategyLogger
        from common.llm.client import LLMClient

        self.logger = StrategyLogger(config)
        self.llm_client = LLMClient(config, self.logger)
        self.tracer = trace.get_tracer(__name__)

    @abstractmethod
    def get_strategy_name(self) -> str:
        """Return strategy name for logging"""
        pass

    @abstractmethod
    def execute_core_logic(self) -> bool:
        """Execute the core strategy logic"""
        pass

    def run(self) -> bool:
        """
        Main execution flow - template method

        Returns:
            bool: True if strategy succeeded, False otherwise
        """
        span_name = f"strategy.{self.config.strategy_name}"
        with self.tracer.start_as_current_span(span_name) as span:
            self._set_span_attributes(span)

            self.logger.log(f"Starting strategy: {self.get_strategy_name()}")
            self.logger.log(f"Fuzzer: {self.config.fuzzer_path}")
            self.logger.log(f"Project: {self.config.project_dir}")

            # Print debug info
            self.config.debug_print()

            try:
                success = self.execute_core_logic()
                span.set_attribute("crs.success", success)

                if success:
                    self.logger.log(f"Strategy {self.get_strategy_name()} succeeded!")
                else:
                    self.logger.log(f"Strategy {self.get_strategy_name()} failed.")

                return success

            except Exception as e:
                span.record_exception(e)
                self.logger.error(f"Strategy execution failed: {str(e)}")
                import traceback
                self.logger.error(traceback.format_exc())
                return False

    def _set_span_attributes(self, span):
        """Set common telemetry attributes"""
        span.set_attribute("crs.action.category", "strategy_execution")
        span.set_attribute("crs.action.name", self.get_strategy_name())
        span.set_attribute("service.name", self.get_strategy_name())
        span.set_attribute("fuzzer.path", self.config.fuzzer_path)
        span.set_attribute("project.name", self.config.project_name)
        span.set_attribute("language", self.config.language)
