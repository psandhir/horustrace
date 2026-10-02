from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP

server = MCPServerStreamableHTTP("http://mcp.example.test")
agent = Agent("openai:gpt-4o", mcp_servers=[server])
