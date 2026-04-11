# Changelog

All notable changes to this project will be documented in this file.

## 2026-04-08
### Support for TAMU AI Chat APIs
To make it more convenient for Texas A&M University (TAMU) students to use FuzzingBrain, we have added support for TAMU AI Chat APIs.

TAMU students can now seamlessly integrate their TAMU-provided AI services with FuzzingBrain. To get started, you can obtain your API key by following the official TAMU AI documentation:
https://docs.tamus.ai/docs/prod/api-tool/create-and-test-api-key/

Once you have your API key, you can configure it within FuzzingBrain and begin using TAMU AI-powered features.

#### Usage

```bash
# Use --tamuai flag to route all LLM calls through TAMU AI
./FuzzingBrain.sh --tamuai git@github.com:user/repo.git

# Or via environment variable
USE_TAMU_AI=true TAMU_AI_API_KEY=sk-xxx ./FuzzingBrain.sh git@github.com:user/repo.git

# Or via Go binary directly
go run ./cmd/local/main.go --tamuai /path/to/task
```

#### Configuration

Set your API key in `crs/.env`:
```
USE_TAMU_AI=false
TAMU_AI_API_KEY=sk-your-tamu-ai-api-key
```

#### Available TAMU Models

When `--tamuai` is enabled, models are automatically mapped to TAMU's protected equivalents:

| Original Model | TAMU Protected Model |
|---|---|
| claude-sonnet-4-5-* | protected.Claude Sonnet 4.5 |
| claude-sonnet-4-* | protected.Claude Sonnet 4 |
| claude-opus-4-* | protected.Claude Opus 4.1 |
| gpt-4.1 | protected.gpt-4.1 (default) |
| gpt-4o | protected.gpt-4o |
| o3 / o4-mini | protected.o3 / protected.o4-mini |
| gemini-2.5-pro | protected.gemini-2.5-pro |
| gemini-2.5-flash | protected.gemini-2.5-flash |

#### Implementation Details

- **Direct HTTP calls**: TAMU API is called directly via `requests` (not through litellm), because TAMU's endpoint returns SSE streaming format that litellm cannot parse.
- **Unified entry point**: `crs/strategy/jeff/tamu_ai.py` handles model mapping, fallback chains, and API communication for all 23 strategy files.
- **No disruption to existing flow**: When `--tamuai` is not set, all LLM calls follow the original Anthropic/OpenAI/Gemini SDK paths unchanged.

#### Files Changed

| File | Change |
|---|---|
| `FuzzingBrain.sh` | Added `--tamuai` option, TAMU key prompting, `sudo -E` for env preservation |
| `crs/run_crs.sh` | Passes `--tamuai` to Go binary, preserves TAMU env vars across `.env` sourcing |
| `crs/cmd/local/main.go` | Added `--tamuai` flag, default model `protected.gpt-4.1` |
| `crs/internal/config/config.go` | Added `TAMUAIAPIKey`, `UseTAMU` to AIConfig, TAMU-aware validation |
| `crs/.env.example` | Added `USE_TAMU_AI=false` and `TAMU_AI_API_KEY` |
| `crs/strategy/jeff/tamu_ai.py` | New file: TAMU API client, model mapping, fallback logic |
| `crs/strategy/jeff/*.py` (23 files) | TAMU early-return in `call_litellm()` and `call_llm()` |
| `crs/strategy/common/llm/client.py` | TAMU routing in unified LLM client |
