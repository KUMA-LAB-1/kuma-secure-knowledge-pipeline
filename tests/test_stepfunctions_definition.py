"""Local structural contract for the Step Functions orchestration artifact.

This is deliberately not a substitute for AWS ValidateStateMachineDefinition.
"""

import json
from pathlib import Path

import pytest

DEFINITION_PATH = (
    Path(__file__).resolve().parents[1] / "infra" / "stepfunctions" / "kuma_pipeline.asl.json"
)
TASKS = ("LoadEvidence", "BuildRequest", "Enrich", "PersistResult", "AuditFailure")


@pytest.fixture(scope="module")
def definition():
    return json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))


def test_explicit_start_and_success_route(definition):
    states = definition["States"]
    assert definition["StartAt"] == "LoadEvidence"
    assert (
        states["LoadEvidence"]["Next"],
        states["BuildRequest"]["Next"],
        states["Enrich"]["Next"],
        states["PersistResult"]["Next"],
    ) == ("BuildRequest", "Enrich", "PersistResult", "Succeeded")
    assert states["Succeeded"]["Type"] == "Succeed"
    assert states["Failed"]["Type"] == "Fail"


def test_all_tasks_are_lambda_integrations_with_bounded_time(definition):
    states = definition["States"]
    assert definition["TimeoutSeconds"] == 300
    for name in TASKS:
        task = states[name]
        assert task["Type"] == "Task"
        assert task["Resource"] == "arn:aws:states:::lambda:invoke"
        assert 1 <= task["TimeoutSeconds"] <= 180
        assert task["Parameters"]["FunctionName"] == f"${{{name}LambdaArn}}"


def test_every_operational_error_routes_to_fail_closed_audit(definition):
    states = definition["States"]
    for name in TASKS[:-1]:
        assert states[name]["Catch"] == [
            {"ErrorEquals": ["States.ALL"], "ResultPath": None, "Next": "AuditFailure"}
        ]
    assert states["AuditFailure"]["Next"] == "Failed"
    assert states["AuditFailure"]["Catch"][0]["Next"] == "Failed"
    assert states["AuditFailure"]["Catch"][0]["ResultPath"] is None
    assert states["AuditFailure"]["ResultPath"] is None


def test_inference_and_persistence_are_not_automatically_retried(definition):
    states = definition["States"]
    for name in ("BuildRequest", "Enrich", "PersistResult", "AuditFailure"):
        assert "Retry" not in states[name]
    retry = states["LoadEvidence"]["Retry"]
    assert len(retry) == 1
    assert retry[0]["MaxAttempts"] <= 2
    assert "States.ALL" not in retry[0]["ErrorEquals"]


def test_caught_error_payload_is_not_forwarded(definition):
    states = definition["States"]

    for name in TASKS:
        assert states[name]["Catch"][0]["ResultPath"] is None

    assert states["AuditFailure"]["Parameters"]["Payload"] == {
        "execution_id.$": "$$.Execution.Id",
        "error_code": "KumaStageFailed",
    }

    assert "$.failure" not in json.dumps(states)


def test_execution_state_contains_references_not_model_text(definition):
    states = definition["States"]
    expected_fields = {
        "LoadEvidence": {"context_ref.$", "artifact_id.$", "extraction_run_id.$"},
        "BuildRequest": {"request_ref.$"},
        "Enrich": {"enrichment_ref.$"},
        "PersistResult": {"result_ref.$", "sha256.$"},
    }
    for name, expected in expected_fields.items():
        task = states[name]
        assert set(task["ResultSelector"]) == expected
        assert task["ResultPath"] != "$"
        assert "Payload.$" not in task["Parameters"]
    assert set(states["AuditFailure"]["Parameters"]["Payload"]) == {
        "execution_id.$",
        "error_code",
    }


def test_no_missing_transitions_or_unreachable_states(definition):
    states = definition["States"]
    reached = set()
    pending = [definition["StartAt"]]
    while pending:
        name = pending.pop()
        assert name in states
        if name in reached:
            continue
        reached.add(name)
        state = states[name]
        if "Next" in state:
            pending.append(state["Next"])
        for catcher in state.get("Catch", []):
            pending.append(catcher["Next"])
    assert reached == set(states)
