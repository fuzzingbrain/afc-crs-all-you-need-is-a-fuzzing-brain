#!/bin/bash
# MCP Server Mode - Start MCP server
cd "$(dirname "$0")/../.."

echo "Starting MCP server..."
echo "This server uses MCP protocol (not HTTP)."
echo "Use Claude Desktop or other MCP clients to connect."
echo ""
echo "Press Ctrl+C to stop."
echo ""

./FuzzingBrain.sh --mcp
