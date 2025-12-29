"""
Base Agent

MCP-based AI agent with tool execution loop.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client
from loguru import logger

from ..llms import LLMClient, LLMResponse, ModelInfo
from ..tools import tools_mcp


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

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 20,
        verbose: bool = True,
    ):
        """
        Initialize agent.

        Args:
            llm_client: LLM client instance (creates new one if None)
            model: Model to use for LLM calls
            max_iterations: Maximum tool call iterations to prevent infinite loops
            verbose: Whether to log detailed progress
        """
        self.llm_client = llm_client or LLMClient()
        self.model = model
        self.max_iterations = max_iterations
        self.verbose = verbose

        # Conversation history
        self.messages: List[Dict[str, str]] = []

        # Tool definitions (populated when connecting to MCP)
        self._tools: List[Dict[str, Any]] = []

        # Statistics
        self.total_iterations = 0
        self.total_tool_calls = 0

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """System prompt for the agent."""
        pass

    @abstractmethod
    def get_initial_message(self, **kwargs) -> str:
        """Generate the initial user message based on task context."""
        pass

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
        try:
            result = await client.call_tool(tool_name, tool_args)

            # Extract text content from result
            if hasattr(result, 'content') and result.content:
                # MCP returns content as list of content blocks
                texts = []
                for block in result.content:
                    if hasattr(block, 'text'):
                        texts.append(block.text)
                    elif isinstance(block, str):
                        texts.append(block)
                return '\n'.join(texts) if texts else str(result)

            return str(result)

        except Exception as e:
            error_msg = f"Tool execution error: {e}"
            logger.warning(f"[{self.__class__.__name__}] {error_msg}")
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

        # Get tools
        self._tools = await self._get_tools(client)

        if self.verbose:
            logger.info(f"[{self.__class__.__name__}] Loaded {len(self._tools)} tools")

        iteration = 0
        final_response = ""

        while iteration < self.max_iterations:
            iteration += 1
            self.total_iterations += 1

            if self.verbose:
                logger.debug(f"[{self.__class__.__name__}] Iteration {iteration}")

            # Call LLM with tools
            self.llm_client.reset_tried_models()
            response = self.llm_client.call_with_tools(
                messages=self.messages,
                tools=self._tools,
                model=self.model,
            )

            # Check for tool calls
            if response.tool_calls:
                # Add assistant message with tool calls
                self.messages.append({
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": response.tool_calls,
                })

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

                    if self.verbose:
                        logger.info(f"[{self.__class__.__name__}] Calling tool: {tool_name}")

                    # Execute tool via MCP
                    tool_result = await self._execute_tool(client, tool_name, tool_args)
                    self.total_tool_calls += 1

                    # Add tool result to messages
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": tool_result,
                    })

            else:
                # No tool calls - agent is done
                final_response = response.content
                if self.verbose:
                    logger.info(f"[{self.__class__.__name__}] Completed after {iteration} iterations")
                break

        if iteration >= self.max_iterations:
            logger.warning(f"[{self.__class__.__name__}] Max iterations reached")
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
        initial_message = self.get_initial_message(**kwargs)

        # Connect to MCP server and run agent loop
        async with Client(tools_mcp) as client:
            return await self._run_agent_loop(client, initial_message)

    def run(self, **kwargs) -> str:
        """
        Run the agent synchronously.

        Args:
            **kwargs: Task-specific arguments passed to get_initial_message()

        Returns:
            Final agent response
        """
        return asyncio.run(self.run_async(**kwargs))

    def get_stats(self) -> Dict[str, int]:
        """Get agent statistics."""
        return {
            "total_iterations": self.total_iterations,
            "total_tool_calls": self.total_tool_calls,
            "message_count": len(self.messages),
        }
