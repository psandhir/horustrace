"""Source-shaped AgentOps regression cases: internal context != external effect."""

from pathlib import Path

from horustrace.scanner import scan


def test_openai_run_context_mutation_does_not_invent_persistent_write(
    tmp_path: Path,
) -> None:
    (tmp_path / "customer_service_agent.py").write_text(
        """
from agents import Agent, RunContextWrapper, function_tool, handoff

class AirlineAgentContext:
    confirmation_number: str | None = None
    seat_number: str | None = None

@function_tool
async def update_seat(
    context: RunContextWrapper[AirlineAgentContext],
    confirmation_number: str,
    new_seat: str,
) -> str:
    context.context.confirmation_number = confirmation_number
    context.context.seat_number = new_seat
    return f"Updated seat to {new_seat}"

seat_booking_agent = Agent[AirlineAgentContext](
    name="Seat Booking Agent", tools=[update_seat],
)
triage_agent = Agent[AirlineAgentContext](
    name="Triage Agent", handoffs=[handoff(agent=seat_booking_agent)],
)
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    seat_agent = next(a for a in graph.agents if a.name == "Seat Booking Agent")
    seat_tool = next(t for t in seat_agent.tools if t.name == "update_seat")

    assert seat_tool.metadata["effect_scope"] == "run_context"
    assert seat_tool.metadata["persistent_effect_proven"] is False
    assert "data.write" not in seat_tool.capabilities
    assert "external.write" not in seat_tool.capabilities
    assert not any(
        f.agent == "Seat Booking Agent" and f.rule_id in {"AGT022", "CAP005"}
        for f in findings
    )

    triage = next(a for a in graph.agents if a.name == "Triage Agent")
    assert "external.write" not in triage.capabilities


def test_sql_mutation_is_not_mistaken_for_in_memory_context_change(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, RunContextWrapper, function_tool

@function_tool
async def update_seat(context: RunContextWrapper, db, new_seat):
    context.context.seat_number = new_seat
    db.execute("UPDATE bookings SET seat = ?", (new_seat,))
    db.commit()
    return "ok"

agent = Agent(name="booking", tools=[update_seat])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "booking")
    tool = next(t for t in agent.tools if t.name == "update_seat")
    assert "data.write" in tool.capabilities
