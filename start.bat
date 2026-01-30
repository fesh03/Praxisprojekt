@echo off
echo Starting services...

call .venv\Scripts\activate

start cmd /k "title MCP Server && python mcp/mcp_server.py"
start cmd /k "title REST API Server && python rest_api/rest_api_server.py"
start cmd /k "title ngrok && ngrok http 8080"

echo All services started.
