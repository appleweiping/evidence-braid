# Authenticated local workflow service

`LocalWorkflowService` and synchronous `WorkflowClient` provide three bounded
HTTP operations over one pinned, existing `SQLiteWorkflowStore`, with no runtime
dependency. The listener binds only **127.0.0.1**, port 0 by default. Construction
does not listen; `start()`/context entry acquires the listener after an externally
trusted full startup checkpoint is verified.

```sh
python examples/local_workflow_service.py
python -O examples/local_workflow_service.py
```

The self-contained example owns a temporary database and real loopback listener,
generates ephemeral tokens, uses two actors and recovers an earlier append after
a later operation. It compares full independently calculated receipt, operation
and checkpoint rows with direct SQLite results. Checks survive `-O`; no token or
invented external offset is printed.

## Provisioning and security boundary

Supply a separately trusted `AuthorityPolicy`, workflow ID, context digest, full
startup `WorkflowCheckpoint`, service ID and immutable credential registry. There
is no implicit database creation, policy discovery, repinning or migration.
`WorkflowServiceCredential(credential_id, actor_id, token_sha256, access)` maps a
credential to an existing actor. Generate 32 random bytes using
`secrets.token_hex(32)`; configure SHA-256 of the decoded bytes on the server and
give the 64-character lowercase token explicitly to its client. Format checking
cannot prove entropy. No default password, env/file discovery or secure erasure
of Python immutable token strings is provided.

`read` permits snapshot/lookup; `act` also permits append. **Both disclose the
entire workflow**, including other scopes, evidence, artifact metadata, actor IDs,
statements and reasons. Do not provision a token for a scope-limited reader.
Every transition actor must equal the authenticated actor before any store call.
Mismatched/mixed batches are rejected, never rewritten. Existing exact-scope
roles, human-kind, review separation/quorum and revision checks remain unchanged.
Identity/kind and distinct-person assertions remain trusted operator claims, not
identity-provider attestation or proof of claim truth.

This is a limited local boundary, **not an untrusted/public deployment**. It
excludes stolen tokens, malicious operator/in-process code, same-user debuggers,
privileged network/OS observers, hostile filesystem/kernel and direct CLI/database
writers. Plain loopback bearer authentication does not authenticate the server
cryptographically: trust endpoint/token distribution and never send tokens to an
arbitrary URL/port. Do not expose it through a proxy or tunnel. No TLS, IPv6,
browser client, CORS/cookie auth, tenant routing, MCP, upload, general query or
service CLI is supplied.

Registry changes require restart. Multiple credentials for one actor share rate
limits and request identity; rotation can recover earlier operations. Portable
bundles are not signed proof that every actor used this service. Namespace/hash
chains are not origin signatures. Trusted direct writers reserve `svc1.` IDs.

## SDK, CAS and acknowledgement

Construct `WorkflowClient` with numeric `(127.0.0.1, port)`, token, trusted authority
and service/actor/workflow/context pins. Constructor opens no socket. The SDK does
not resolve DNS/proxy environment, follow redirects, retry or rebase.

- `snapshot(expected=checkpoint_or_none)` returns `StoredWorkflow`. An anchor
  matches exact-current state, not a minimum/prefix checkpoint.
- `prepare_append(transitions, request_id=..., expected=checkpoint)` performs no
  I/O and returns immutable, token-free `PreparedWorkflowAppend`. Persist
  `to_dict()` before sending; `from_dict()` revalidates it without I/O.
- `append(prepared)` invokes one durable append and returns `WorkflowCommit`.
- `lookup(request_id=..., expected_request_digest=...)` returns the actor's exact
  historical commit or an authenticated absence observation at that read.

Public IDs use the existing identifier alphabet, length 1–58. The core ID is
`svc1.<namespace SHA-256>.<public ID>`, at most 128 characters. Namespace input is
existing canonical JSON with `kind` equal to
`evidence-braid-workflow-service-request-namespace`, `schema_version` `1.0`,
`service_id`, `context_digest`, and authenticated `actor_id`. Token/credential ID
is absent. The unchanged core request digest binds that ID, full checkpoint and
ordered transitions.

Identical retries recover the original prefix even after later operations;
changed intent or a new stale request conflicts. Never change actor, rebase or
reuse an uncertain ID for new intent. The SDK locally verifies returned models,
identity pins, request/operation binding and intended transition range. A snapshot
does not expose the operation journal as an independent proof. Startup pinning
alone cannot defeat later valid rollback/fork; external checkpoints remain
separate trust anchors.

`WorkflowServiceError` carries fixed `code`, `outcome`, and admitted public ID/
digest when known. `none` describes this attempt, not absence of an earlier
commit. `unknown` requires retained-intent recovery. `complete` survives encoding,
write and cleanup failures after append/found lookup has returned. Socket write
acceptance is not application acknowledgement. Truncated/malformed responses
cannot downgrade uncertainty. A complete error is not a synthetic commit: look
it up. Absent lookup is not a future-absence promise or permission for ID reuse.
No transport failure authorizes rollback of a possibly committed database.

The client has one network owner: overlapping operations are rejected, never
concurrently canceled. Failed socket close retains that one socket plus verified
outcome/identity. New network calls are rejected until explicit `client.close()`
succeeds; it retries cleanup, not active-call cancellation. Retain the client
itself after failure. Pure preparation acquires no socket.

## Restricted HTTP/1.1 profile

One POST and response per connection, then close. No keep-alive, compression,
chunking, streaming, redirect or upgrade. Only these routes exist:

| Route | Exact body keys besides `schema_version: "1.0"` |
| --- | --- |
| `/v1/workflow/snapshot` | `expected_checkpoint` (existing object or null) |
| `/v1/workflow/append` | `request_id`, `request_digest`, `expected_checkpoint`, `transitions` |
| `/v1/workflow/lookup` | `request_id`, `request_digest` |

Required headers: Host, Authorization, Content-Type, Content-Length. Optional:
Connection (`close`), Accept (`application/json`). Content-Type is exactly
`application/json`; Host is `127.0.0.1:<bound port>`. Reject duplicate/unknown
headers, Origin/Referer/fetch metadata, ambiguous whitespace/line endings,
absolute/encoded/query targets, transfer/content encodings and Expect. At most
the first frame is processed; pipelined bytes are never another operation.

Bodies are canonical compact sorted UTF-8 JSON without LF. Reject duplicate
keys, nonfinite/overflowing numbers, invalid UTF-8, noncanonical serialization,
unknown fields and inexact scalar types. Byte/lexical admission precedes JSON
parsing. Numeric admission preserves 640-digit integers plus optional negative
sign. This uses existing Python canonicalization, not an RFC-8785 claim.

Status 200 has exactly `schema_version`, `service_id`, `workflow_id`,
`context_digest`, `actor_id`, `operation`, `request_id`, `request_digest`,
`outcome`, `result`. Snapshot has null IDs/`none`; append has `complete`; found
lookup has `complete` and absent lookup has `none`/null result. Results are
unchanged stored-workflow/commit objects. Error shape is exactly `schema_version`,
`error_code`, `outcome`, `request_id`, `request_digest`; IDs can be null in
preadmission/emergency diagnostics. No raw body, token or exception logging.

Statuses: 400 invalid frame/schema, 401 auth, 403 capability/actor, 404 route,
405 method, 409 conflict, 413 input bound, 415 media type, 422 core rejection,
429 rate, 503 capacity/storage, 500 internal/report failure. Only 500/503 can
carry a non-`none` outcome. A missing/partial reply remains transport failure
regardless of which status the sender tried to write.

## Limits and ownership

`WorkflowServiceLimits` can lower, not remove/raise, these profile bounds:

| Dimension | Default ceiling |
| --- | --- |
| Credentials / authority bytes | 256 / 4 MiB |
| Worker owners / core operations | 4 / 1 |
| Request line / header bytes / count / line bytes | 2 KiB / 16 KiB / 32 / 4 KiB |
| Request/prepared bytes / depth / key-and-value count | 1 MiB / 16 / 8,192 |
| Append / retained records / operations | 128 / 1,000 / 1,000 |
| Receipt / bundle / operation / total journal | 128 KiB / 8 MiB / 8 KiB / 1 MiB |
| Response bytes | Effective bundle cap + 64 KiB, derived rather than independently lowered |
| SDK response headers / JSON depth | 4 KiB, 8 headers, 1 KiB per line / 128 |

One accept-loop handoff socket is additionally retained until handed to a worker
or successfully closed; no work queue exists. Worker permits are released only
after actual thread termination and acknowledged socket cleanup. Saturation
closes new sockets without allocating more workers. Actor buckets allow 4
requests/second, burst 4; the global bucket allows 16/second, burst 16. Buckets
are preallocated and shared across credentials belonging to the same actor.

Absolute deadlines do not reset on progress: header/connect 5s, body 10s,
response/request I/O 10s, core admission 2s, SQLite busy wait 1s, close/join 10s.
Configurable ceilings respectively allow 10/30/30/5/5/30s. Server reads poll the
owned stop event at most every 50ms of socket wait: OS shutdown alone need not
wake timeout-mode reads promptly. Client calls are not concurrently cancellable.

These are I/O/admission/busy-wait bounds, **not hard native CPU/filesystem deadlines
or RSS limits**. Complete history replay/serialization is materialized. No DB
transaction/core slot spans socket I/O. Complete response bytes are staged while
the one core slot is owned; at most four worker response buffers coexist.
History-cap exhaustion refuses new writes but leaves snapshot/recovery available.

State progresses NEW → STARTING → RUNNING → DRAINING → CLOSED. Close stops
admission, wakes unadmitted readers, lets admitted native work settle and joins
owned threads. Timeout retains DRAINING and handles for another close attempt;
no CLOSED claim while live work/failed-close sockets remain. `check()`/close
retain worker control failures; original body controls win secondary cleanup
controls. `last_error` retains one bounded nonfatal request/delivery diagnostic.
Before worker handoff, an original control also survives connection cleanup;
after handoff, the worker retains its socket and permit until actual termination
and acknowledged close, even if its thread-start call raised after starting it.
No daemon thread hides unfinished ownership.

Existing authority/workflow/store/CLI semantics and wires remain unchanged.
Richer epistemic lifecycle, policy evolution, scope-redacted views, independent
witnesses, identity/signatures, hosted/MCP/distributed services and full frozen
reference parity remain open. See [whole-repository inventory](parity-ledger.md)
and the [durable-store contract](durable-workflows.md).
