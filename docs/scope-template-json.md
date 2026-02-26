# scope.template.json Reference

`adversa init` creates a starter `scope.template.json` used as a human-editable authorization and scope template.

## Default Template

```json
{
  "authorized": true,
  "target": "https://staging.example.com",
  "out_of_scope": ["production"]
}
```

## Fields

- `authorized` (boolean)
  - Declares that you are authorized to test this target.
  - Keep this true only for approved environments.

- `target` (string)
  - Canonical target URL, typically staging.
  - Should match `--url` used in `adversa run`.

- `out_of_scope` (array of strings)
  - Names, hosts, or environment tags that must not be tested.
  - Example values: `"production"`, `"payments-prod"`, `"*.internal"`.

## Recommended Usage

1. Run `adversa init`.
2. Edit `scope.template.json` with your approved target and exclusions.
3. Run Adversa against the same approved staging URL:

```bash
adversa run \
  --repo repos/my-target-repo \
  --url https://staging.example.com \
  --workspace my-target \
  --i-acknowledge
```

## Notes

- This template is currently a scoped input artifact for operators.
- Runtime enforcement still depends on CLI/config safety checks (for example repo-root restrictions and acknowledgement).
