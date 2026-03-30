import asyncio
from unittest.mock import AsyncMock

import pytest

from core.dispatch import DispatchContext, DispatchCounter, DispatchTool


def test_can_dispatch_within_limits():
    ctx = DispatchContext()

    assert ctx.can_dispatch("forensics") is True


def test_cannot_dispatch_reporter():
    ctx = DispatchContext()

    assert ctx.can_dispatch("reporter") is False


def test_cannot_dispatch_commander():
    ctx = DispatchContext()

    assert ctx.can_dispatch("commander") is False


def test_cannot_dispatch_at_max_depth():
    ctx = DispatchContext(depth=2, max_depth=2)

    assert ctx.can_dispatch("forensics") is False


def test_cannot_dispatch_when_budget_exhausted():
    counter = DispatchCounter(value=5)
    ctx = DispatchContext(max_sub_tasks=5, _counter=counter)

    assert ctx.can_dispatch("forensics") is False


def test_cannot_dispatch_same_agent_in_chain():
    ctx = DispatchContext(dispatched_agents=frozenset({"recon"}))

    assert ctx.can_dispatch("recon") is False


def test_child_increments_depth():
    ctx = DispatchContext(depth=0)
    child = ctx.child("forensics")

    assert child.depth == 1


def test_child_adds_agent_to_dispatched_set():
    ctx = DispatchContext()
    child = ctx.child("forensics")

    assert "forensics" in child.dispatched_agents


def test_child_shares_counter():
    ctx = DispatchContext()
    child = ctx.child("forensics")

    assert child._counter is ctx._counter


@pytest.mark.asyncio
async def test_counter_increment():
    counter = DispatchCounter()

    assert await counter.increment() == 1
    assert await counter.increment() == 2


@pytest.mark.asyncio
async def test_dispatch_tool_calls_dispatch_fn():
    mock_fn = AsyncMock(return_value="forensics findings")
    ctx = DispatchContext()
    tool = DispatchTool(
        dispatch_fn=mock_fn,
        dispatch_context=ctx,
        caller_name="recon",
        sub_task_timeout=30.0,
    )

    result = await tool.run(agent="forensics", objective="analyse hash", context={"hash": "abc"})

    assert result == "forensics findings"
    mock_fn.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_tool_blocks_self_dispatch():
    mock_fn = AsyncMock(return_value="findings")
    ctx = DispatchContext()
    tool = DispatchTool(
        dispatch_fn=mock_fn,
        dispatch_context=ctx,
        caller_name="recon",
        sub_task_timeout=30.0,
    )

    result = await tool.run(agent="recon", objective="more recon", context={})

    assert "Cannot dispatch to self" in result
    mock_fn.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_tool_respects_limit():
    mock_fn = AsyncMock(return_value="findings")
    ctx = DispatchContext(depth=2, max_depth=2)
    tool = DispatchTool(
        dispatch_fn=mock_fn,
        dispatch_context=ctx,
        caller_name="recon",
        sub_task_timeout=30.0,
    )

    result = await tool.run(agent="forensics", objective="analyse", context={})

    assert "Dispatch limit reached" in result
    mock_fn.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_tool_handles_timeout():
    async def slow_fn(*args, **kwargs):
        await asyncio.sleep(100)
        return "never"

    ctx = DispatchContext()
    tool = DispatchTool(
        dispatch_fn=slow_fn,
        dispatch_context=ctx,
        caller_name="recon",
        sub_task_timeout=0.01,
    )

    result = await tool.run(agent="forensics", objective="analyse", context={})

    assert "timed out" in result


@pytest.mark.asyncio
async def test_dispatch_tool_handles_exception():
    async def failing_fn(*args, **kwargs):
        raise RuntimeError("agent exploded")

    ctx = DispatchContext()
    tool = DispatchTool(
        dispatch_fn=failing_fn,
        dispatch_context=ctx,
        caller_name="recon",
        sub_task_timeout=30.0,
    )

    result = await tool.run(agent="forensics", objective="analyse", context={})

    assert "failed" in result
    assert "agent exploded" in result


@pytest.mark.asyncio
async def test_dispatch_tool_rejects_non_string_agent():
    mock_fn = AsyncMock(return_value="findings")
    ctx = DispatchContext()
    tool = DispatchTool(
        dispatch_fn=mock_fn,
        dispatch_context=ctx,
        caller_name="recon",
        sub_task_timeout=30.0,
    )

    result = await tool.run(agent={"type": "forensics"}, objective="analyse", context={})

    assert "agent must be a non-empty string" in result
    mock_fn.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_tool_normalizes_non_mapping_context():
    mock_fn = AsyncMock(return_value="findings")
    ctx = DispatchContext()
    tool = DispatchTool(
        dispatch_fn=mock_fn,
        dispatch_context=ctx,
        caller_name="recon",
        sub_task_timeout=30.0,
    )

    await tool.run(agent="forensics", objective="analyse", context=["ioc-1"])

    mock_fn.assert_awaited_once_with(
        "forensics",
        "analyse",
        {"raw": ["ioc-1"]},
        ctx,
    )
