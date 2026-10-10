# KUMA C02-ORCH-003 | Offline stage handlers and durable references

This is an independent product engineering increment. It **does not** deploy AWS
Lambda, provision S3, connect to Bedrock, or charge AWS. Its five handler methods
accept the exact Lambda `Payload` fields in `kuma_pipeline.asl.json` and produce
matching `Payload` response fields. Integrations to actual Lambda runtimes and
cloud storage will require an explicit deployment adapter and IAM/cost review.

## Storage and boundaries

The trusted application chooses a **private, local, absolute** storage root and
an approved evidence root. Only trusted application code calls
`register_bundle(path, execution_id=...)`; task payloads receive an opaque
`bundle_ref` and never provide file paths. The store uses content-addressed
references (`kind:sha256`), hardlink-based atomic publication, SHA-256 checks
on read, and a commit index allowing **one result reference per execution ID**.
Reads revalidate bundle lineage through the existing domain functions. Handlers
validate execution ownership and pass only references between stages.

**Important limits:** reference hashes detect corruption, not a malicious
administrator who can rewrite both store objects and indexes. Use restrictive
OS ACLs/permissions and keep the store off untrusted/network-shared disks.
This implementation is for local demos and tests. The cloud production store
still needs encryption, authorization per tenant, authenticated writes,
stronger durability semantics, retention, idempotency across services,
observability, and AWS IAM least privilege. A state-machine timeout is not
proof that a model or database operation terminates on time.

## Minimal offline exercise

In Python, with an already validated synthetic OCR bundle directory and
`FakeGenAIProvider` instance:

```python
from kuma_secure_knowledge_pipeline.stepfunctions_store import LocalStageStore
from kuma_secure_knowledge_pipeline.stepfunctions_handlers import OfflineStepHandlers

store = LocalStageStore(root=private_root, evidence_root=evidence_root)
handlers = OfflineStepHandlers(store=store, providers={"offline-fake": provider})
execution_id = "local-demo-001"
bundle_ref = handlers.register_bundle(bundle, execution_id=execution_id)
context = handlers.load_evidence({"bundle_ref": bundle_ref, "execution_id": execution_id})
request = handlers.build_request(
    {"context_ref": context["context_ref"], "execution_id": execution_id}
)
enrichment = handlers.enrich(
    {
        "request_ref": request["request_ref"],
        "model_profile": "offline-fake",
        "execution_id": execution_id,
    }
)
result = handlers.persist_result(
    {
        "artifact_id": context["artifact_id"],
        "extraction_run_id": context["extraction_run_id"],
        "enrichment_ref": enrichment["enrichment_ref"],
        "execution_id": execution_id,
    }
)
```

This is a local replay of the five task payloads, **not a Step Functions execution**.
For task errors, `audit_failure({"execution_id": execution_id, "error_code": "States.TaskFailed"})`
records only the sanitized error code and execution identity, not the exception
cause, OCR text, model response, or prompt.

### Deliberate design choices

- The local fake provider is preferred for frequent test runs. Qwen inference is
  optional and is not invoked by the installer or tests.
- No automatic retries for the inference and persistence stages. An existing
  commit index prevents conflicting persistence outputs for the same execution.
- Future production Lambda handlers will retrieve references from a restricted
  cloud storage service rather than from the local filesystem.
- The historical provider field in provenance **does not prove** live use of
  Textract or other AWS services.
