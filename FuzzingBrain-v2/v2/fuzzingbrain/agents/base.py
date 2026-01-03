"""
Base Agent

MCP-based AI agent with tool execution loop.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client, FastMCP
from loguru import logger

from ..llms import LLMClient, LLMResponse, ModelInfo
from ..tools.mcp_factory import create_isolated_mcp_server
from ..core.logging import get_agent_banner_and_header


class BaseAgent(ABC):
    """
    Base class for MCP-based AI agents.

    Implements the core agent loop:
    1. Connect to MCP server (tools_mcp)
    2. Get available tools
    3. Call LLM with tools
    4. Execute tool calls via MCP
    5. Repeat until LLM stops calling tools
    """

    # Default temperature for this agent type (can be overridden by subclasses)
    default_temperature: float = 0.7

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 20,
        verbose: bool = True,
        temperature: Optional[float] = None,
        # Logging context
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
    ):
        """
        Initialize agent.

        Args:
            llm_client: LLM client instance (creates new one if None)
            model: Model to use for LLM calls
            max_iterations: Maximum tool call iterations to prevent infinite loops
            verbose: Whether to log detailed progress
            temperature: LLM temperature (uses class default_temperature if None)
            task_id: Task ID for logging context
            worker_id: Worker ID for logging context
            log_dir: Directory for log files
        """
        self.llm_client = llm_client or LLMClient()
        self.model = model
        self.max_iterations = max_iterations
        self.verbose = verbose
        self.temperature = temperature if temperature is not None else self.default_temperature

        # Logging context
        self.task_id = task_id
        self.worker_id = worker_id
        self.log_dir = log_dir

        # Conversation history
        self.messages: List[Dict[str, str]] = []

        # Tool definitions (populated when connecting to MCP)
        self._tools: List[Dict[str, Any]] = []

        # Statistics
        self.total_iterations = 0
        self.total_tool_calls = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        # Agent-specific logger
        self._agent_logger = None
        self._log_file: Optional[Path] = None
        self._chat_log_file: Optional[Path] = None

    @property
    def agent_name(self) -> str:
        """Get agent name for logging."""
        return self.__class__.__name__

    @property
    def include_pov_tools(self) -> bool:
        """Whether to include POV tools in MCP server.

        Override to True in POVAgent. Other agents don't need POV tools.
        """
        return False

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """System prompt for the agent."""
        pass

    @abstractmethod
    def get_initial_message(self, **kwargs) -> str:
        """Generate the initial user message based on task context."""
        pass

    def _get_agent_metadata(self) -> dict:
        """
        Get metadata for agent banner. Subclasses should override to add specific info.

        Returns:
            Dict with keys like: Agent, Scan Mode, Phase, Fuzzer, Sanitizer,
            Worker ID, Direction, Target Function, SP ID, Vulnerability Type, Goal
        """
        return {
            "Agent": self.agent_name,
            "Worker ID": self.worker_id,
            "Task ID": self.task_id,
        }

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        """
        Get urgency message when iterations are running low.

        Subclasses can override this to provide agent-specific urgency prompts.

        Args:
            iteration: Current iteration number
            remaining: Remaining iterations

        Returns:
            Urgency message to inject, or None if not needed
        """
        return None

    def _setup_logging(self) -> None:
        """Set up agent-specific logging."""
        if not self.log_dir:
            return

        log_dir = Path(self.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        # Create log file name: {agent_name}_{worker_id}_{timestamp}.log
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        agent_short_name = self.agent_name.replace("Agent", "").lower()
        if self.worker_id:
            log_name = f"{agent_short_name}_{self.worker_id}_{timestamp}.log"
        else:
            log_name = f"{agent_short_name}_{timestamp}.log"

        self._log_file = log_dir / log_name

        # Create unique instance ID for this agent (for log filtering)
        self._agent_instance_id = f"{self.agent_name}_{self.worker_id}_{id(self)}"

        # Write banner to log file first
        metadata = self._get_agent_metadata()
        banner = get_agent_banner_and_header(metadata)
        with open(self._log_file, "w", encoding="utf-8") as f:
            f.write(banner)
            f.write("\n")

        # Get fuzzer and sanitizer from subclass if available
        fuzzer = getattr(self, 'fuzzer', '') or ''
        sanitizer = getattr(self, 'sanitizer', '') or ''

        # Add file handler with agent-specific filter
        self._agent_logger = logger.bind(
            agent=self.agent_name,
            agent_instance_id=self._agent_instance_id,
            task_id=self.task_id,
            worker_id=self.worker_id,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )

        # Build format string with context info
        # Format: timestamp | level | agent | task_id | worker_id | fuzzer | sanitizer | message
        format_parts = [
            "{time:YYYY-MM-DD HH:mm:ss.SSS}",
            "{level: <8}",
            "{extra[agent]}",
        ]
        if self.task_id:
            format_parts.append("task:{extra[task_id]}")
        if self.worker_id:
            format_parts.append("worker:{extra[worker_id]}")
        if fuzzer:
            format_parts.append("fuzzer:{extra[fuzzer]}")
        if sanitizer:
            format_parts.append("san:{extra[sanitizer]}")
        format_parts.append("{message}")
        log_format = " | ".join(format_parts)

        # Add file sink for this agent - use instance ID for filtering (append mode)
        instance_id = self._agent_instance_id  # Capture for closure
        logger.add(
            self._log_file,
            level="DEBUG",
            format=log_format,
            filter=lambda record: record["extra"].get("agent_instance_id") == instance_id,
            encoding="utf-8",
            mode="a",  # Append after banner
        )

        # Create chat log file for detailed conversation tracking
        self._chat_log_file = self._log_file.with_suffix(".chat.md")
        self._init_chat_log()

        self._log("Logging initialized", level="INFO")
        self._log(f"Log file: {self._log_file}", level="INFO")

    def _log(self, message: str, level: str = "DEBUG") -> None:
        """Log a message with agent context."""
        if self._agent_logger:
            log_func = getattr(self._agent_logger, level.lower(), self._agent_logger.debug)
            log_func(message)
        elif self.verbose:
            # Fallback to standard logger
            prefix = f"[{self.agent_name}]"
            if self.worker_id:
                prefix = f"[{self.agent_name}:{self.worker_id}]"
            log_func = getattr(logger, level.lower(), logger.debug)
            log_func(f"{prefix} {message}")

    def _get_summary_table(self) -> str:
        """
        Generate a summary table for the agent's work.

        Subclasses should override this to provide specific summaries.

        Returns:
            Formatted summary string with box drawing characters
        """
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0

        lines = []
        lines.append("")
        lines.append("┌" + "─" * 60 + "┐")
        lines.append("│" + " AGENT SUMMARY ".center(60) + "│")
        lines.append("├" + "─" * 60 + "┤")
        lines.append("│" + f"  Agent: {self.agent_name}".ljust(60) + "│")
        lines.append("│" + f"  Duration: {duration:.2f}s".ljust(60) + "│")
        lines.append("│" + f"  Iterations: {self.total_iterations}".ljust(60) + "│")
        lines.append("│" + f"  Tool Calls: {self.total_tool_calls}".ljust(60) + "│")
        lines.append("└" + "─" * 60 + "┘")
        lines.append("")

        return "\n".join(lines)

    def _write_summary_table(self) -> None:
        """Write the summary table to the log file."""
        if not self._log_file:
            return

        summary = self._get_summary_table()

        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write("\n")
                f.write(summary)
                f.write("\n")
        except Exception as e:
            self._log(f"Failed to write summary table: {e}", level="ERROR")

    def _init_chat_log(self) -> None:
        """Initialize the detailed chat log file with markdown header."""
        if not hasattr(self, '_chat_log_file') or not self._chat_log_file:
            return
        try:
            # Get fuzzer and sanitizer from subclass if available
            fuzzer = getattr(self, 'fuzzer', '') or ''
            sanitizer = getattr(self, 'sanitizer', '') or ''

            with open(self._chat_log_file, "w", encoding="utf-8") as f:
                f.write(f"# Agent Chat Log\n\n")
                f.write(f"- **Agent**: {self.agent_name}\n")
                f.write(f"- **Task ID**: {self.task_id}\n")
                f.write(f"- **Worker ID**: {self.worker_id}\n")
                if fuzzer:
                    f.write(f"- **Fuzzer**: {fuzzer}\n")
                if sanitizer:
                    f.write(f"- **Sanitizer**: {sanitizer}\n")
                f.write(f"- **Start Time**: {datetime.now().isoformat()}\n")
                f.write(f"- **Model**: {self.model.id if hasattr(self.model, 'id') else (self.model or 'default')}\n")
                f.write(f"\n{'='*80}\n\n")
        except Exception as e:
            self._log(f"Failed to init chat log: {e}", level="ERROR")

    def _log_chat_message(
        self,
        role: str,
        content: str,
        iteration: int = 0,
        tool_calls: Optional[List[Dict]] = None,
        tool_call_id: Optional[str] = None,
    ) -> None:
        """
        Log a chat message with clear visual separation.

        Args:
            role: Message role (system, user, assistant, tool)
            content: Message content
            iteration: Current iteration number
            tool_calls: List of tool calls (for assistant messages)
            tool_call_id: Tool call ID (for tool response messages)
        """
        if not hasattr(self, '_chat_log_file') or not self._chat_log_file:
            return

        try:
            with open(self._chat_log_file, "a", encoding="utf-8") as f:
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

                # Role-specific formatting with clear visual separators
                if role == "system":
                    f.write(f"## 📋 SYSTEM PROMPT\n")
                    f.write(f"*[{timestamp}]*\n\n")
                    f.write(f"```\n{content}\n```\n\n")
                    f.write(f"{'─'*80}\n\n")

                elif role == "user":
                    f.write(f"## 👤 USER (Iteration {iteration})\n")
                    f.write(f"*[{timestamp}]*\n\n")
                    f.write(f"{content}\n\n")
                    f.write(f"{'─'*80}\n\n")

                elif role == "assistant":
                    f.write(f"## 🤖 ASSISTANT (Iteration {iteration})\n")
                    f.write(f"*[{timestamp}]*\n\n")
                    if content:
                        f.write(f"{content}\n\n")
                    if tool_calls:
                        f.write(f"### Tool Calls:\n")
                        for tc in tool_calls:
                            func_name = tc.get("function", {}).get("name", "unknown")
                            func_args = tc.get("function", {}).get("arguments", "{}")
                            tc_id = tc.get("id", "")
                            f.write(f"- **{func_name}** (id: `{tc_id}`)\n")
                            f.write(f"  ```json\n  {func_args}\n  ```\n")
                        f.write("\n")
                    f.write(f"{'─'*80}\n\n")

                elif role == "tool":
                    f.write(f"## 🔧 TOOL RESULT\n")
                    f.write(f"*[{timestamp}]* Tool Call ID: `{tool_call_id}`\n\n")
                    # Truncate very long tool results for readability
                    if len(content) > 5000:
                        f.write(f"```\n{content[:5000]}\n... (truncated, {len(content)} total chars)\n```\n\n")
                    else:
                        f.write(f"```\n{content}\n```\n\n")
                    f.write(f"{'─'*80}\n\n")

        except Exception as e:
            self._log(f"Failed to log chat message: {e}", level="ERROR")

    def _finalize_chat_log(self, final_response: str) -> None:
        """Finalize the chat log with summary statistics."""
        if not hasattr(self, '_chat_log_file') or not self._chat_log_file:
            return

        try:
            duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0

            with open(self._chat_log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"# SUMMARY\n\n")
                f.write(f"- **End Time**: {self.end_time.isoformat() if self.end_time else 'N/A'}\n")
                f.write(f"- **Duration**: {duration:.2f} seconds\n")
                f.write(f"- **Total Iterations**: {self.total_iterations}\n")
                f.write(f"- **Total Tool Calls**: {self.total_tool_calls}\n")
                f.write(f"- **Total Messages**: {len(self.messages)}\n\n")
                f.write(f"## Final Response:\n\n{final_response}\n")
        except Exception as e:
            self._log(f"Failed to finalize chat log: {e}", level="ERROR")

    def _log_conversation(self) -> None:
        """Log the full conversation history to file."""
        if not self._log_file:
            return

        # Get fuzzer and sanitizer from subclass if available
        fuzzer = getattr(self, 'fuzzer', '') or ''
        sanitizer = getattr(self, 'sanitizer', '') or ''

        conv_file = self._log_file.with_suffix(".conversation.json")
        try:
            with open(conv_file, "w", encoding="utf-8") as f:
                json.dump({
                    "agent": self.agent_name,
                    "task_id": self.task_id,
                    "worker_id": self.worker_id,
                    "fuzzer": fuzzer,
                    "sanitizer": sanitizer,
                    "start_time": self.start_time.isoformat() if self.start_time else None,
                    "end_time": self.end_time.isoformat() if self.end_time else None,
                    "total_iterations": self.total_iterations,
                    "total_tool_calls": self.total_tool_calls,
                    "messages": self.messages,
                }, f, indent=2, ensure_ascii=False)
            self._log(f"Conversation saved to: {conv_file}", level="INFO")
        except Exception as e:
            self._log(f"Failed to save conversation: {e}", level="ERROR")

    def _convert_mcp_tools_to_openai(self, mcp_tools: List[Any]) -> List[Dict[str, Any]]:
        """
        Convert MCP tool definitions to OpenAI function calling format.

        Args:
            mcp_tools: List of MCP Tool objects

        Returns:
            List of OpenAI-format tool definitions
        """
        openai_tools = []

        for tool in mcp_tools:
            # MCP Tool has: name, description, inputSchema
            tool_def = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": tool.inputSchema if hasattr(tool, 'inputSchema') else {
                        "type": "object",
                        "properties": {},
                    },
                },
            }
            openai_tools.append(tool_def)

        return openai_tools

    async def _get_tools(self, client: Client) -> List[Dict[str, Any]]:
        """
        Get tools from MCP server and convert to OpenAI format.

        Args:
            client: Connected MCP Client

        Returns:
            List of OpenAI-format tool definitions
        """
        mcp_tools = await client.list_tools()
        return self._convert_mcp_tools_to_openai(mcp_tools)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """
        Execute a tool via MCP.

        Args:
            client: Connected MCP Client
            tool_name: Name of tool to call
            tool_args: Arguments for the tool

        Returns:
            Tool result as string
        """
        import time
        t0 = time.time()
        self._log(f"Executing tool: {tool_name}", level="DEBUG")
        self._log(f"  Args: {json.dumps(tool_args, ensure_ascii=False)[:500]}", level="DEBUG")

        try:
            result = await client.call_tool(tool_name, tool_args)
            t1 = time.time()
            if t1 - t0 > 0.5:  # Log if > 500ms
                self._log(f"[TIMING] MCP call_tool({tool_name}): {t1-t0:.3f}s", level="INFO")

            # Extract text content from result
            if hasattr(result, 'content') and result.content:
                # MCP returns content as list of content blocks
                texts = []
                for block in result.content:
                    if hasattr(block, 'text'):
                        texts.append(block.text)
                    elif isinstance(block, str):
                        texts.append(block)
                result_str = '\n'.join(texts) if texts else str(result)
            else:
                result_str = str(result)

            self._log(f"  Result: {result_str[:500]}...", level="DEBUG")
            return result_str

        except Exception as e:
            error_msg = f"Tool execution error: {e}"
            self._log(error_msg, level="ERROR")
            return json.dumps({"success": False, "error": str(e)})

    async def _run_agent_loop(
        self,
        client: Client,
        initial_message: str,
    ) -> str:
        """
        Run the agent loop.

        Args:
            client: Connected MCP Client
            initial_message: Initial user message

        Returns:
            Final agent response
        """
        # Initialize conversation
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_message},
        ]

        # Log initial messages to chat log
        self._log_chat_message("system", self.system_prompt)
        self._log_chat_message("user", initial_message, iteration=0)

        # Get tools
        self._tools = await self._get_tools(client)
        self._log(f"Loaded {len(self._tools)} MCP tools", level="INFO")

        # Log tool names
        tool_names = [t["function"]["name"] for t in self._tools]
        self._log(f"Available tools: {', '.join(tool_names)}", level="DEBUG")

        # Log model info
        model_name = self.model.id if hasattr(self.model, 'id') else (self.model or self.llm_client.config.default_model.id)
        self._log(f"Using model: {model_name}", level="INFO")

        iteration = 0
        final_response = ""
        response = None

        while iteration < self.max_iterations:
            iteration += 1
            self.total_iterations += 1
            remaining = self.max_iterations - iteration

            self._log(f"=== Iteration {iteration}/{self.max_iterations} ===", level="INFO")

            # Check for urgency message (when running low on iterations)
            urgency_message = self._get_urgency_message(iteration, remaining)
            if urgency_message:
                self._log(f"Injecting urgency message (remaining={remaining})", level="INFO")
                self.messages.append({
                    "role": "user",
                    "content": urgency_message,
                })
                self._log_chat_message("user", urgency_message, iteration=iteration)

            # Call LLM with tools (async to avoid blocking event loop)
            self.llm_client.reset_tried_models()
            try:
                response = await self.llm_client.acall_with_tools(
                    messages=self.messages,
                    tools=self._tools,
                    model=self.model,
                    temperature=self.temperature,
                )
            except Exception as e:
                import traceback
                self._log(f"LLM call failed: {e}", level="ERROR")
                self._log(f"Traceback:\n{traceback.format_exc()}", level="ERROR")
                break

            # Log LLM response
            if response.content:
                self._log(f"LLM response: {response.content[:300]}...", level="DEBUG")

            # Check for tool calls
            if response.tool_calls:
                self._log(f"LLM requested {len(response.tool_calls)} tool call(s)", level="INFO")

                # Add assistant message with tool calls
                self.messages.append({
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": response.tool_calls,
                })

                # Log assistant message with tool calls
                self._log_chat_message(
                    "assistant",
                    response.content or "",
                    iteration=iteration,
                    tool_calls=response.tool_calls,
                )

                # Execute each tool call
                for tool_call in response.tool_calls:
                    tool_name = tool_call["function"]["name"]
                    tool_args_str = tool_call["function"]["arguments"]
                    tool_id = tool_call["id"]

                    # Parse arguments
                    try:
                        tool_args = json.loads(tool_args_str) if tool_args_str else {}
                    except json.JSONDecodeError:
                        tool_args = {}
                        self._log(f"Failed to parse tool args: {tool_args_str}", level="WARNING")

                    self._log(f"Calling tool: {tool_name}", level="INFO")

                    # Execute tool via MCP
                    tool_result = await self._execute_tool(client, tool_name, tool_args)
                    self.total_tool_calls += 1

                    # Add tool result to messages
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": tool_result,
                    })

                    # Log tool result
                    self._log_chat_message(
                        "tool",
                        tool_result,
                        iteration=iteration,
                        tool_call_id=tool_id,
                    )

            else:
                # No tool calls - agent is done
                final_response = response.content
                self._log(f"Agent completed after {iteration} iterations", level="INFO")
                self._log(f"Final response: {final_response[:500]}...", level="DEBUG")

                # Log final assistant response
                self._log_chat_message(
                    "assistant",
                    final_response or "",
                    iteration=iteration,
                )
                break

        if iteration >= self.max_iterations:
            self._log(f"Max iterations ({self.max_iterations}) reached", level="WARNING")
            final_response = response.content if response else ""

        return final_response

    async def run_async(self, **kwargs) -> str:
        """
        Run the agent asynchronously.

        Args:
            **kwargs: Task-specific arguments passed to get_initial_message()

        Returns:
            Final agent response
        """
        # Setup logging
        self._setup_logging()

        self.start_time = datetime.now()
        self._log(f"Starting agent run", level="INFO")
        self._log(f"Task ID: {self.task_id}", level="INFO")
        self._log(f"Worker ID: {self.worker_id}", level="INFO")

        initial_message = self.get_initial_message(**kwargs)
        self._log(f"Initial message: {initial_message[:500]}...", level="DEBUG")

        try:
            # Create an isolated MCP server for this agent
            # This prevents response mixing when multiple agents run concurrently
            # Pass worker_id so POV tools can find the right context
            agent_id = f"{self.agent_name}_{self.worker_id}_{id(self)}"
            mcp_server = create_isolated_mcp_server(
                agent_id=agent_id,
                worker_id=self.worker_id,  # Bind worker_id for POV context lookup
                include_pov_tools=self.include_pov_tools,  # Only POVAgent needs POV tools
            )
            self._log(f"Created isolated MCP server: {agent_id} (pov_tools={self.include_pov_tools})", level="DEBUG")

            # Connect to the isolated MCP server and run agent loop
            async with Client(mcp_server) as client:
                result = await self._run_agent_loop(client, initial_message)
        except Exception as e:
            self._log(f"Agent run failed: {e}", level="ERROR")
            import traceback
            self._log(f"Traceback:\n{traceback.format_exc()}", level="ERROR")
            result = f"Agent failed: {e}"

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        self._log(f"Agent run completed in {duration:.2f}s", level="INFO")
        self._log(f"Total iterations: {self.total_iterations}", level="INFO")
        self._log(f"Total tool calls: {self.total_tool_calls}", level="INFO")

        # Write summary table to log
        self._write_summary_table()

        # Save conversation log (JSON format)
        self._log_conversation()

        # Finalize chat log (markdown format with summary)
        self._finalize_chat_log(result)

        return result

    def run(self, **kwargs) -> str:
        """
        Run the agent synchronously.

        Args:
            **kwargs: Task-specific arguments passed to get_initial_message()

        Returns:
            Final agent response
        """
        return asyncio.run(self.run_async(**kwargs))

    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        stats = {
            "agent": self.agent_name,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "total_iterations": self.total_iterations,
            "total_tool_calls": self.total_tool_calls,
            "message_count": len(self.messages),
        }

        if self.start_time and self.end_time:
            stats["duration_seconds"] = (self.end_time - self.start_time).total_seconds()

        if self._log_file:
            stats["log_file"] = str(self._log_file)

        if self._chat_log_file:
            stats["chat_log_file"] = str(self._chat_log_file)

        return stats
