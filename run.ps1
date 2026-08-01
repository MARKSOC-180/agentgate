# AgentGate — one gesture on Windows
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python -m pip install -e . -q
python -m agentgate.cli start @Args
