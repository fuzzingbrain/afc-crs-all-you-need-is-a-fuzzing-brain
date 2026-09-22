from unittest.mock import MagicMock, patch

import pytest

from minisweagent.exceptions import FormatError
from minisweagent.models.litellm_model import LitellmModel, LitellmModelConfig
from minisweagent.models.utils.actions_toolcall import BASH_TOOL


class TestLitellmModelConfig:
    def test_default_format_error_template(self):
        assert LitellmModelConfig(model_name="test").format_error_template == "{{ error }}"


def _mock_litellm_response(tool_calls):
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.tool_calls = tool_calls
    mock_response.choices[0].message.model_dump.return_value = {"role": "assistant", "content": None}
    mock_response.model_dump.return_value = {}
    return mock_response


class TestLitellmModel:
    @patch("minisweagent.models.litellm_model.litellm.completion")
    @patch("minisweagent.models.litellm_model.litellm.cost_calculator.completion_cost")
    def test_query_includes_bash_tool(self, mock_cost, mock_completion):
        tool_call = MagicMock()
        tool_call.function.name = "bash"
        tool_call.function.arguments = '{"command": "echo test"}'
        tool_call.id = "call_1"
        mock_completion.return_value = _mock_litellm_response([tool_call])
        mock_cost.return_value = 0.001

        model = LitellmModel(model_name="gpt-4")
        model.query([{"role": "user", "content": "test"}])

        mock_completion.assert_called_once()
        assert mock_completion.call_args.kwargs["tools"] == [BASH_TOOL]

    @patch("minisweagent.models.litellm_model.litellm.completion")
    @patch("minisweagent.models.litellm_model.litellm.cost_calculator.completion_cost")
    def test_parse_actions_valid_tool_call(self, mock_cost, mock_completion):
        tool_call = MagicMock()
        tool_call.function.name = "bash"
        tool_call.function.arguments = '{"command": "ls -la"}'
        tool_call.id = "call_abc"
        mock_completion.return_value = _mock_litellm_response([tool_call])
        mock_cost.return_value = 0.001

        model = LitellmModel(model_name="gpt-4")
        result = model.query([{"role": "user", "content": "list files"}])
        assert result["extra"]["actions"] == [{"tool": "bash", "args": {"command": "ls -la"}, "command": "ls -la", "tool_call_id": "call_abc"}]

    @patch("minisweagent.models.litellm_model.litellm.completion")
    @patch("minisweagent.models.litellm_model.litellm.cost_calculator.completion_cost")
    def test_parse_actions_no_tool_calls_raises(self, mock_cost, mock_completion):
        mock_completion.return_value = _mock_litellm_response(None)
        mock_cost.return_value = 0.001

        model = LitellmModel(model_name="gpt-4")
        with pytest.raises(FormatError):
            model.query([{"role": "user", "content": "test"}])

    @patch("minisweagent.models.litellm_model.litellm.completion")
    @patch("minisweagent.models.litellm_model.litellm.cost_calculator.completion_cost")
    def test_finish_reason_threaded_into_format_error_template(self, mock_cost, mock_completion):
        """The response finish_reason is exposed to format_error_template via template_kwargs, so a
        config can report a max_tokens truncation instead of the misleading "no tool call" error."""
        response = _mock_litellm_response(None)
        response.choices[0].finish_reason = "length"
        mock_completion.return_value = response
        mock_cost.return_value = 0.001

        model = LitellmModel(
            model_name="gpt-4",
            format_error_template="{% if finish_reason == 'length' %}cut off{% else %}{{ error }}{% endif %}",
        )
        with pytest.raises(FormatError) as exc:
            model.query([{"role": "user", "content": "test"}])
        assert exc.value.messages[0]["content"] == "cut off"

    def test_format_observation_messages(self):
        model = LitellmModel(model_name="gpt-4", observation_template="{{ output.output }}")
        message = {"extra": {"actions": [{"command": "echo test", "tool_call_id": "call_1"}]}}
        outputs = [{"output": "test output", "returncode": 0}]
        result = model.format_observation_messages(message, outputs)
        assert len(result) == 1
        assert result[0]["role"] == "tool"
        assert result[0]["tool_call_id"] == "call_1"
        assert result[0]["content"] == "test output"

    def test_format_observation_messages_no_actions(self):
        model = LitellmModel(model_name="gpt-4")
        result = model.format_observation_messages({"extra": {}}, [])
        assert result == []


# ------------------------------------------------- the verbatim exchange
def test_the_request_and_response_are_recorded_verbatim(tmp_path, monkeypatch):
    """A run kept the dialogue but not the REQUEST.

    report.html renders the reasoning, the tool calls and the results, which is
    the conversation -- but not the assembled message array as it went over the
    wire, with the tool schemas and sampling parameters. That is reconstructable
    because the agent builds it deterministically, and "reconstructable" is not
    "auditable": a reviewer asking what exactly was sent on turn 40 should get
    the bytes.
    """
    import json
    from minisweagent.models.litellm_model import LitellmModel
    log = tmp_path / "exchange.jsonl"
    monkeypatch.setenv("FBAGENT_EXCHANGE_LOG", str(log))
    m = LitellmModel.__new__(LitellmModel)
    m.config = type("C", (), {"model_name": "test-model", "model_kwargs": {"api_key": "SECRET"}})()
    m._tools = lambda: [{"function": {"name": "exec"}}]
    class R:
        def model_dump(self, mode=None): return {"choices": [{"message": {"content": "hi"}}]}
    m._record_exchange([{"role": "user", "content": "find the bug"}], R(), {"temperature": 0})
    rec = json.loads(log.read_text().strip())
    assert rec["request"]["messages"] == [{"role": "user", "content": "find the bug"}]
    assert rec["request"]["tools"] == [{"function": {"name": "exec"}}]
    assert rec["request"]["kwargs"] == {"temperature": 0}
    assert rec["response"]["choices"][0]["message"]["content"] == "hi"
    assert "SECRET" not in log.read_text(), "credentials must never be written"


def test_nothing_is_written_when_the_log_is_not_configured(tmp_path, monkeypatch):
    from minisweagent.models.litellm_model import LitellmModel
    monkeypatch.delenv("FBAGENT_EXCHANGE_LOG", raising=False)
    m = LitellmModel.__new__(LitellmModel)
    m.config = type("C", (), {"model_name": "x", "model_kwargs": {}})()
    m._tools = lambda: []
    m._record_exchange([{"role": "user", "content": "x"}], object(), {})  # must not raise


def test_a_logging_failure_never_breaks_a_run(tmp_path, monkeypatch):
    from minisweagent.models.litellm_model import LitellmModel
    monkeypatch.setenv("FBAGENT_EXCHANGE_LOG", str(tmp_path / "nope" / "deep" / "x.jsonl"))
    m = LitellmModel.__new__(LitellmModel)
    m.config = type("C", (), {"model_name": "x", "model_kwargs": {}})()
    m._tools = lambda: []
    m._record_exchange([{"role": "user", "content": "x"}], object(), {})  # must not raise
