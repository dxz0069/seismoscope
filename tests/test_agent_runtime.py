"""Focused tests for the AutoCVE-inspired agent runtime."""

import asyncio
import json

import pytest

from core.agent_runtime import (
    AgentRuntimeState,
    AgentTask,
    AgentTaskLoop,
    ContextWindow,
    FinalizeTaskContract,
    InvalidTransitionError,
    PermissionedToolExecutor,
    ReActConfig,
    ReActHandler,
    RetryPolicy,
    TaskGraphController,
    TaskStateMachine,
)
from core.agent_runtime.loop import TaskTurn
from core.agents.base import AgentResult
from core.llm_service import LLMMessage, LLMResponse, MockLLMService
from core.session.models import RunSession
from core.session.store import SessionStore


def test_state_machine_rejects_illegal_transition_and_round_trips():
    machine = TaskStateMachine()
    machine.transition(AgentRuntimeState.PLANNED, reason="plan")
    machine.transition(AgentRuntimeState.DISPATCHED, reason="dispatch")
    machine.transition(AgentRuntimeState.RUNNING, reason="start")

    with pytest.raises(InvalidTransitionError):
        machine.transition(AgentRuntimeState.COMPLETED)

    restored = TaskStateMachine.from_dict(machine.to_dict())
    assert restored.state == AgentRuntimeState.RUNNING
    assert [item.to_state.value for item in restored.history] == [
        "planned",
        "dispatched",
        "running",
    ]


def test_task_loop_executes_tool_and_validates_completion():
    calls = []

    async def run_case():
        task = AgentTask(
            agent_name="test-agent",
            phase="audit",
            completion_contract=FinalizeTaskContract().to_dict(),
            max_attempts=1,
        )

        async def handler(current_task, context):
            calls.append(current_task.turn_count)
            if not context.get("tool_results"):
                return {
                    "status": "needs_tool",
                    "tool_call": {"name": "read_file", "arguments": {"path": "app.py"}},
                }
            return {
                "done": True,
                "terminal_action": "FinalizeTask",
                "output": {"summary": "Audit completed", "next_action": "return"},
            }

        async def tool_executor(name, arguments, context):
            assert name == "read_file"
            assert arguments["path"] == "app.py"
            return {"content": "safe"}

        loop = AgentTaskLoop(
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0),
            max_turns=4,
        )
        return await loop.run(task, handler, tool_executor=tool_executor)

    result = asyncio.run(run_case())
    assert result.status == "completed"
    assert result.task.status == AgentRuntimeState.COMPLETED
    assert calls == [1, 2]
    assert "waiting_tool" in [item["to_state"] for item in result.task.state_history]


def test_task_loop_retries_exception_and_nudges_invalid_completion():
    attempts = {"count": 0}

    async def run_case():
        task = AgentTask(
            completion_contract=FinalizeTaskContract().to_dict(),
            max_attempts=2,
        )

        async def handler(current_task, context):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise RuntimeError("transient model error")
            if "completion_feedback" not in context:
                return {
                    "done": True,
                    "terminal_action": "FinalizeTask",
                    "output": {"summary": "incomplete"},
                }
            return {
                "done": True,
                "terminal_action": "FinalizeTask",
                "output": {"summary": "complete", "next_action": "return"},
            }

        loop = AgentTaskLoop(
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0),
            max_turns=5,
        )
        return await loop.run(task, handler)

    result = asyncio.run(run_case())
    assert result.status == "completed"
    assert attempts["count"] == 3
    assert result.task.attempt == 1
    assert result.task.metadata["completion_nudges"] == 1


def test_task_loop_does_not_retry_provider_contract_errors():
    attempts = {"count": 0}

    async def run_case():
        task = AgentTask(max_attempts=3)

        async def handler(current_task, context):
            attempts["count"] += 1
            raise RuntimeError("Error code: 400 - invalid_request_error")

        return await AgentTaskLoop(
            retry_policy=RetryPolicy(max_attempts=3, base_delay_seconds=0),
        ).run(task, handler)

    result = asyncio.run(run_case())

    assert result.status == "failed"
    assert attempts["count"] == 1


def test_session_store_loads_latest_snapshot(tmp_path):
    store = SessionStore(str(tmp_path))
    session = RunSession(project_path=".")
    session.start()
    session.checkpoint("agent_task", {"task": {"task_id": "task-1", "status": "paused"}})
    store.save(session)
    session.emit("resumed", "agent_task", "resume")
    store.save(session)

    loaded = store.load(session.session_id)
    assert loaded.session_id == session.session_id
    assert loaded.events[-1].event_type == "resumed"
    assert store.latest_checkpoint(session.session_id).phase == "agent_task"


def test_session_store_replaces_snapshot_instead_of_appending_full_history(tmp_path):
    store = SessionStore(str(tmp_path))
    session = RunSession(project_path=".")
    session.start()
    session.checkpoint("plan", {"version": 1})
    store.save(session)
    session.emit("phase_started", "audit", "started")
    session.checkpoint("audit", {"version": 2})
    path = store.save(session)

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 1
    loaded = store.load(session.session_id)
    assert loaded.events[-1].phase == "audit"
    assert loaded.checkpoints[-1].state["version"] == 2


def test_task_and_checkpoint_snapshots_are_json_safe_and_redacted():
    secret = "sk-checkpoint-secret-123456789"
    task = AgentTask(
        input_payload={"source_excerpt": f"api_key = '{secret}'"},
        metadata={"handler_state": {"messages": [f"token = '{secret}'"]}},
    )
    session = RunSession(project_path=".")
    session.checkpoint("agent_task", {"task": task, "state": AgentRuntimeState.RUNNING})

    serialized = json.dumps(session.to_dict())

    assert secret not in serialized
    assert "[REDACTED" in serialized


def test_resume_manager_continues_paused_task(tmp_path):
    async def run_case():
        store = SessionStore(str(tmp_path))
        task = AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1)
        machine = task.state_machine()
        machine.transition(AgentRuntimeState.PAUSED, reason="manual pause")
        task.sync_state(machine)
        session = RunSession(project_path=".")
        session.start()
        session.checkpoint("agent_task", {"task": task.to_dict()})
        store.save(session)

        from core.agent_runtime.resume import ResumeManager

        async def handler(current_task, context):
            return {
                "done": True,
                "terminal_action": "FinalizeTask",
                "output": {"summary": "resumed", "next_action": "return"},
            }

        result = await ResumeManager(store).resume_session(session.session_id, handler)
        loaded = store.load(session.session_id)
        return result, loaded

    result, loaded = asyncio.run(run_case())
    assert result.status == "completed"
    assert loaded.checkpoints[-1].state["task"]["status"] == "completed"


def test_resume_manager_executes_tool_pending_at_pause(tmp_path):
    async def run_case():
        from core.agent_runtime.resume import ResumeManager

        store = SessionStore(str(tmp_path))
        session = RunSession(project_path=".")
        session.start()
        first_provider = MockLLMService(responses=[LLMResponse(
            content="inspect",
            tool_calls=[{
                "id": "pending-call",
                "function": {"name": "read_file", "arguments": '{"path":"app.py"}'},
            }],
        )])
        first_handler = ReActHandler(first_provider)
        task = AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1)
        loop = AgentTaskLoop(max_turns=5)

        def checkpoint_sink(current_task, payload):
            session.checkpoint("agent_task", payload)
            store.save(session)

        loop.checkpoint_sink = checkpoint_sink
        original_handler = first_handler.__call__

        async def pausing_handler(current_task, context):
            result = await original_handler(current_task, context)
            if result.get("tool_call"):
                loop.request_pause()
            return result

        paused = await loop.run(task, pausing_handler)
        assert paused.status == "paused"
        assert paused.task.metadata["paused_from"] == "waiting_tool"

        resumed_provider = MockLLMService(responses=[LLMResponse(
            content="",
            tool_calls=[{
                "id": "final-call",
                "function": {
                    "name": "FinalizeTask",
                    "arguments": '{"summary":"resumed safely","next_action":"return"}',
                },
            }],
        )])
        resumed_handler = ReActHandler(resumed_provider)
        tool_calls = []

        async def tool_executor(name, arguments, context):
            tool_calls.append((name, arguments))
            return {"content": "safe"}

        completed = await ResumeManager(store).resume_session(
            session.session_id,
            resumed_handler,
            loop=AgentTaskLoop(max_turns=5),
            tool_executor=tool_executor,
        )
        return completed, tool_calls, resumed_handler

    completed, tool_calls, handler = asyncio.run(run_case())

    assert completed.status == "completed"
    assert tool_calls == [("read_file", {"path": "app.py"})]
    assert [message.role for message in handler.messages[-2:]] == ["tool", "assistant"]


def test_react_handler_routes_tool_calls_and_terminal_tool():
    async def run_case():
        llm = MockLLMService(
            responses=[
                LLMResponse(
                    content="Inspecting the file",
                    tool_calls=[
                        {
                            "id": "call-1",
                            "function": {
                                "name": "read_file",
                                "arguments": '{"path": "app.py"}',
                            },
                        }
                    ],
                    usage={"total_tokens": 3},
                ),
                LLMResponse(
                    content="",
                    tool_calls=[
                        {
                            "id": "call-2",
                            "function": {
                                "name": "FinalizeTask",
                                "arguments": '{"summary": "safe", "next_action": "return"}',
                            },
                        }
                    ],
                    usage={"total_tokens": 4},
                ),
            ]
        )
        handler = ReActHandler(llm)
        task = AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1)
        loop = AgentTaskLoop(retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0))
        return await loop.run(
            task,
            handler,
            tool_executor=lambda name, arguments, context: {"name": name, "path": arguments["path"]},
        ), handler

    result, handler = asyncio.run(run_case())
    assert result.status == "completed"
    assert any(message.role == "tool" for message in handler.messages)


def test_react_handler_preserves_and_serializes_a_tool_call_batch():
    async def run_case():
        llm = MockLLMService(
            responses=[
                LLMResponse(
                    content="Inspect both files",
                    tool_calls=[
                        {
                            "id": "read-1",
                            "function": {"name": "read_file", "arguments": '{"path":"first.py"}'},
                        },
                        {
                            "id": "read-2",
                            "function": {"name": "read_file", "arguments": '{"path":"second.py"}'},
                        },
                    ],
                ),
                LLMResponse(
                    content="",
                    tool_calls=[
                        {
                            "id": "final-batch",
                            "function": {
                                "name": "FinalizeTask",
                                "arguments": '{"summary":"complete","next_action":"return"}',
                            },
                        }
                    ],
                ),
            ]
        )
        handler = ReActHandler(llm)
        executed = []

        async def tool_executor(name, arguments, context):
            del context
            executed.append((name, arguments["path"]))
            return {"path": arguments["path"]}

        result = await AgentTaskLoop(max_turns=4).run(
            AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1),
            handler,
            tool_executor=tool_executor,
        )
        return result, handler, executed

    result, handler, executed = asyncio.run(run_case())

    assert result.status == "completed"
    assert executed == [("read_file", "first.py"), ("read_file", "second.py")]
    assistant_with_batch = next(message for message in handler.messages if message.tool_calls)
    assert [item["id"] for item in assistant_with_batch.tool_calls] == ["read-1", "read-2"]
    assert [message.tool_call_id for message in handler.messages if message.role == "tool"] == ["read-1", "read-2"]


def test_react_handler_uses_json_fallback_after_terminal_tool_is_not_returned():
    class RecordingProvider(MockLLMService):
        def __init__(self):
            super().__init__(responses=[
                LLMResponse(content="", tool_calls=[{
                    "id": "read-1",
                    "function": {"name": "read_file", "arguments": '{"path":"app.py"}'},
                }]),
                LLMResponse(content="I cannot call the terminal tool."),
                LLMResponse(content=json.dumps({
                    "terminal_action": "FinalizeTask",
                    "output": {"summary": "complete", "next_action": "return"},
                })),
            ])
            self.requests = []

        async def chat(self, messages, *, tools=None, **kwargs):
            self.requests.append({"tools": tools, "options": kwargs})
            return await super().chat(messages, tools=tools, **kwargs)

    async def run_case():
        provider = RecordingProvider()
        handler = ReActHandler(
            provider,
            tool_schemas=[{
                "type": "function",
                "function": {"name": "read_file", "parameters": {"type": "object"}},
            }, {
                "type": "function",
                "function": {"name": "FinalizeTask", "parameters": {"type": "object"}},
            }],
            config=ReActConfig(force_terminal_after_tool_results=1, max_context_messages=20),
        )
        result = await AgentTaskLoop(max_turns=4).run(
            AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1),
            handler,
            tool_executor=lambda name, arguments, context: {"path": arguments["path"]},
        )
        return result, provider

    result, provider = asyncio.run(run_case())

    assert result.status == "completed"
    assert provider.requests[-1]["tools"] is None
    assert "parallel_tool_calls" not in provider.requests[-1]["options"]
    assert "tool_choice" not in provider.requests[-1]["options"]


def test_deepseek_uses_json_terminal_on_the_first_forced_turn():
    class DeepSeekProvider(MockLLMService):
        provider = "deepseek"

        def __init__(self):
            super().__init__(responses=[
                LLMResponse(content="", tool_calls=[{
                    "id": "read-1",
                    "function": {"name": "read_file", "arguments": '{"path":"app.py"}'},
                }]),
                LLMResponse(content=json.dumps({
                    "terminal_action": "FinalizeTask",
                    "output": {"summary": "complete", "next_action": "return"},
                })),
            ])
            self.provider = "deepseek"
            self.requests = []

        async def chat(self, messages, *, tools=None, **kwargs):
            self.requests.append({"messages": list(messages), "tools": tools, "options": kwargs})
            return await super().chat(messages, tools=tools, **kwargs)

    async def run_case():
        provider = DeepSeekProvider()
        handler = ReActHandler(
            provider,
            tool_schemas=[{
                "type": "function",
                "function": {"name": "read_file", "parameters": {"type": "object"}},
            }, {
                "type": "function",
                "function": {"name": "FinalizeTask", "parameters": {"type": "object"}},
            }],
            config=ReActConfig(force_terminal_after_tool_results=1, max_context_messages=20),
        )
        result = await AgentTaskLoop(max_turns=3).run(
            AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1),
            handler,
            tool_executor=lambda name, arguments, context: {"path": arguments["path"]},
        )
        return result, provider

    result, provider = asyncio.run(run_case())

    assert result.status == "completed"
    assert len(provider.requests) == 2
    assert provider.requests[-1]["tools"] is None
    terminal_prompt = provider.requests[-1]["messages"][-1].content
    assert "output must contain actual finding values" in terminal_prompt
    assert "Do not include schema keywords" in terminal_prompt


def test_tool_failure_is_returned_as_a_paired_observation():
    async def run_case():
        llm = MockLLMService(responses=[
            LLMResponse(
                content="read evidence",
                tool_calls=[{
                    "id": "failed-call",
                    "function": {"name": "read_file", "arguments": '{"path":"app.py"}'},
                }],
            ),
            LLMResponse(
                content="",
                tool_calls=[{
                    "id": "final-call",
                    "function": {
                        "name": "FinalizeTask",
                        "arguments": '{"summary":"tool unavailable","next_action":"return"}',
                    },
                }],
            ),
        ])
        handler = ReActHandler(llm)
        task = AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1)

        async def failing_tool(name, arguments, context):
            raise RuntimeError("read failed")

        result = await AgentTaskLoop(max_turns=4).run(
            task,
            handler,
            tool_executor=failing_tool,
        )
        return result, handler

    result, handler = asyncio.run(run_case())
    tool_message = next(message for message in handler.messages if message.role == "tool")

    assert result.status == "completed"
    assert tool_message.tool_call_id == "failed-call"
    assert "read failed" in tool_message.content


def test_task_turn_preserves_terminal_action_in_wrapped_result():
    raw = {
        "result": AgentResult.success_result({"finding_count": 1}),
        "done": True,
        "terminal_action": "FinalizeTask",
        "output": {"summary": "complete", "next_action": "return"},
    }

    turn = TaskTurn.from_any(raw)

    assert turn.done is True
    assert turn.terminal_action == "FinalizeTask"
    assert turn.output["summary"] == "complete"


def test_task_graph_honors_dependencies_and_runs_children():
    async def run_case():
        graph = TaskGraphController(max_concurrency=2)
        first = AgentTask(agent_name="first")
        second = AgentTask(agent_name="second")

        async def handler(current_task, context):
            return {"done": True, "output": {"task": current_task.agent_name}}

        graph.add_task(first, handler)
        graph.add_task(second, handler, depends_on=[first.task_id])
        return await graph.run()

    result = asyncio.run(run_case())
    assert result.status == "completed"
    assert [item.task.agent_name for item in result.completed] == ["first", "second"]


def test_stop_hook_blocks_completion_without_finalize_action():
    async def run_case():
        task = AgentTask(completion_contract=FinalizeTaskContract().to_dict(), max_attempts=1)

        async def handler(current_task, context):
            return {"done": True, "output": {"summary": "claimed complete", "next_action": "return"}}

        loop = AgentTaskLoop(max_completion_nudges=1, retry_policy=RetryPolicy(max_attempts=1))
        return await loop.run(task, handler)

    result = asyncio.run(run_case())
    assert result.status == "waiting_handoff"
    assert result.task.metadata["terminal_action_nudges"] == 2


def test_context_window_compacts_and_react_state_round_trips():
    window = ContextWindow(max_messages=4, max_chars=80)
    messages = [LLMMessage(role="system", content="system")] + [
        LLMMessage(role="user", content=f"message-{index}-long") for index in range(8)
    ]
    compacted = window.compact(messages)
    assert len(compacted) <= 4
    assert window.compacted_count == 1

    handler = ReActHandler(MockLLMService())
    handler.messages = compacted
    state = handler.to_state()
    restored = ReActHandler(MockLLMService())
    restored.restore_state(state)
    assert [item.content for item in restored.messages] == [item.content for item in compacted]


def test_context_compaction_keeps_tool_call_and_result_atomic():
    window = ContextWindow(max_messages=4, max_chars=500)
    messages = [
        LLMMessage(role="system", content="system"),
        LLMMessage(role="user", content="old context"),
        LLMMessage(role="user", content="more old context"),
        LLMMessage(
            role="assistant",
            content="",
            tool_calls=[{
                "id": "paired-call",
                "function": {"name": "read_file", "arguments": "{}"},
            }],
        ),
        LLMMessage(
            role="tool",
            content='{"ok":true}',
            name="read_file",
            tool_call_id="paired-call",
        ),
    ]

    compacted = window.compact(messages)

    assert [message.role for message in compacted[-2:]] == ["assistant", "tool"]
    assert compacted[-1].tool_call_id == "paired-call"
    assert window.compaction_events[-1]["protocol_safe"] is True


def test_permissioned_tool_executor_blocks_and_audits_denied_calls():
    async def run_case():
        calls = []
        records = []

        async def raw_executor(name, arguments):
            calls.append(name)
            return {"ok": True}

        from core.runtime.permission_policy import PermissionPolicy

        executor = PermissionedToolExecutor(
            raw_executor,
            policy=PermissionPolicy(denied_tools=["delete_file"]),
            audit_sink=records.append,
        )
        blocked = await executor.execute(name="delete_file", arguments={"path": "x"})
        allowed = await executor.execute(name="read_file", arguments={"path": "x"})
        return blocked, allowed, calls, records

    blocked, allowed, calls, records = asyncio.run(run_case())
    assert blocked["blocked"] is True
    assert allowed["ok"] is True
    assert calls == ["read_file"]
    assert [record.allowed for record in records] == [False, True]
