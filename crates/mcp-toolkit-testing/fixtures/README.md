# Descriptor profile fixtures

`descriptor-profiles-v1.json` is a portable, synthetic corpus for comparing
intentionally different descriptor acceptance profiles. Each case contains a
complete descriptor, a stable ID, and separate expectations. This is a regression
baseline, not a claim of ChatGPT certification or a normative schema validator.

## Profiles and provenance

- `toolkit_tool_only_required_output`: `OpenAiAppsConformanceProfile::new` with
  no required scopes, `with_tool_only_connector_metadata()` and
  `with_required_output_schema()`. The integration test replays every case
  against the actual toolkit helper, catching assertion failures per case.
- `probe_chatgpt_tool`: expected error and warning codes from
  `audit_tool_schema_compatibility_for_profile({"tools": [descriptor]},
  ToolDescriptorProfile::ChatgptTool)`. Codes are compared as multisets, not
  ordering guarantees. These expectations are source-reviewed against
  [mcp-probe at 051f32b](https://github.com/sednalabs/mcp-probe/blob/051f32b242953bb167a82484f26bfedf7df71775/src/probe/schema_compat.rs).
  The toolkit test does not execute mcp-probe. Downstream probe adoption should
  replay these same descriptors using its real implementation, not copy its
  validator into the toolkit.

The corpus records source revisions in `sources`. Changing a profile's policy
requires reviewing its expectations independently; never change both columns
just to make them agree. Keep v1 IDs and layout stable when adding cases. A
breaking corpus format change requires a new filename and format version.

## Intentional differences captured

| Concern | Toolkit selected profile | Probe ChatgptTool |
| --- | --- | --- |
| Widget access omitted | Rejects; explicit false required | Accepts omitted false default |
| Visibility omitted or string `model` | Rejects; exact `["model"]` required | Accepts |
| Model plus app visibility | Rejects | Warning, not error |
| Nested boolean/array schema nodes | No recursive schema audit | Audits nested nodes |
| Input root array type | Accepts JSON object descriptor shape | Rejects non-object schema root |
| Output root without type | Rejects | Allows absent type |
| Annotation requirements | All four booleans | Read-only and destructive booleans |
| Security schemes | Validates top-level/mirrored equality and scheme contents | Requires nonempty metadata array |
| Invocation status | Not checked | Nonblank and at most 64 Unicode scalar values |

The Unicode fixtures deliberately distinguish characters from UTF-8 bytes.
Accepting a fixture in one column is not an endorsement of its production use.
Schema audits, auth policy, page-byte limits and complete paginated catalogue
validation remain separate responsibilities. Existing page/catalogue contract
helpers should be applied in addition to descriptor checks.

## Run

`cargo test -p mcp-toolkit-testing --test descriptor_profile_fixtures`

No network or real credentials are needed by this test. Hosted workspace
validation remains the landing gate. The fixture-only contribution does not
change descriptor acceptance behavior or introduce another public validator.
