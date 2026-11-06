# Structured secret-field fixtures

`secret-fields.json` is a language-neutral synthetic regression corpus for the
existing exact-key redaction policy. Each case has a name, input JSON, expected
JSON, and ASCII canary markers that must be absent after output serialization.
All values are synthetic; none is a real credential or usable private key.

The cases exercise multiline private-key values, nested arrays, JSON escaping,
Unicode adjacency, mixed-case keys, Basic authorization values, complete secret
subtree replacement, idempotence, and preservation of operational code fields.
They adapt the kinds of boundary cases seen in analytics and administration
response adapters without importing a provider-specific error taxonomy.

These fixtures test `redact_json_keys`, not arbitrary free-text detection. They
also cover the additional default `private_key`, `password`, and `api_key` keys;
explicit caller key lists retain their existing behavior. Exact keys do not
match suffixes such as `private_key_id` or `api_key_count`.

This is heuristic telemetry defense in depth, not proof that provider output is
safe to return to clients. The recursive helper has no depth or size admission
contract. Callers must bound inputs and use allowlisted client error fields;
these fixtures do not claim otherwise.
