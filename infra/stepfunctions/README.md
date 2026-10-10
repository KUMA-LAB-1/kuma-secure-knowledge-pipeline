# KUMA Secure Knowledge Pipeline | Step Functions contract (C02-ORCH-002)

**Engineering asset, independent of any course or bootcamp.** This directory
contains a planned AWS Standard Workflow definition using Amazon States Language
(JSONPath) and an offline structural test. It does **not** deploy, invoke AWS,
prove AWS-side ASL validation, or claim the Lambda handlers already exist.

## Purpose and boundaries

The existing `genai_workflow.run_local_workflow` remains the working local
implementation: `LOAD_EVIDENCE -> BUILD_REQUEST -> ENRICH -> SUCCEEDED`, with
safe failures. This ASL file describes a **future cloud orchestration** using
reference-only handoffs:

`LoadEvidence -> BuildRequest -> Enrich -> PersistResult -> Succeeded`

Catchable task errors go to `AuditFailure -> Failed`, including an
audit-handler failure. Uncatchable AWS runtime errors or the whole-execution
timeout may fail without running the audit handler; AWS execution history must
therefore also be protected and monitored. The success path requires a successful durable result write.

Do not put the OCR document, extracted text, prompts, raw model output, tokens,
secrets or personally identifiable content in Step Functions execution input,
outputs, task errors or CloudWatch logs. Store bulky or sensitive artifacts in
a controlled encrypted store; exchange only validated references. An execution
history remains sensitive metadata and must have narrowly scoped access.

## Required external Lambda handler contracts (NOT IMPLEMENTED YET)

The deploy pipeline must replace `${...LambdaArn}` with actual permitted
function ARNs, and must create the handlers, IAM roles, storage, and controls
before this state machine is executable. Never deploy this template verbatim.

Input to StartExecution (example only):

```json
{"bundle_ref": "opaque-bundle-reference", "model_profile": "approved-bedrock-profile"}
```

Handlers return (inside the Step Functions Lambda integration `Payload`):

| Handler | Required response | Security requirement |
|---|---|---|
| `LoadEvidence` | `context_ref`, `artifact_id`, `extraction_run_id` | Validate provenance and bundle contents with existing domain code; verify tenant/access rights; immutable reference |
| `BuildRequest` | `request_ref` | Reuse existing request validation; check reference ownership |
| `Enrich` | `enrichment_ref` | Allowlist `model_profile`; call configured cloud adapter; validate structured citations; restrict model output |
| `PersistResult` | `result_ref`, `sha256` | Durable atomic/idempotent write tied to `execution_id`, artifact, and run; verify digest and access controls |
| `AuditFailure` | Response ignored | Log sanitized error code and execution identity, never full `.Cause` or document content; must not suppress terminal failure |

The `Lambda` service retries in `LoadEvidence` cover limited transient errors
only. No automatic retries for inference or persistence until their idempotency
and cost semantics are implemented and demonstrated. Per-task timeouts and a
300-second execution timeout bound cloud orchestration, not arbitrary internal
I/O actions. Lambda timeout values must also be configured consistently.

The historical OCR provider name is provenance metadata, **not independent
proof of live AWS invocation**. Synthetic fixtures must remain clearly labeled.

## Validation and deployment boundary

Local tests (`tests/test_stepfunctions_definition.py`) check the project-specific
structural contract only. They cannot establish full AWS ASL validity. Before
production or a controlled cloud demonstration, run AWS
`ValidateStateMachineDefinition` with *read-only permissions*, inspect warnings,
then provision cloud resources only after explicit cost, IAM, privacy and
teardown review. See [AWS CLI validation reference](https://docs.aws.amazon.com/cli/latest/reference/stepfunctions/validate-state-machine-definition.html).

This milestone intentionally does not invoke `ollama`, `bedrock`, Lambda,
Step Functions, or any other external service.
