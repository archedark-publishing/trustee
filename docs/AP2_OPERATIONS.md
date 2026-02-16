# AP2 Operations Runbook

This runbook covers key operational controls for AP2 mandates in Trustee.

## Key Rotation

1. Add new issuer trust:
   - `trustee mandate trust-issuer --agent <agent> --issuer <new_issuer> --allow`
2. Issue replacement mandates with overlapping validity:
   - `trustee mandate issue ... --issuer-key <new_key>`
3. Verify replacement mandates are active:
   - `trustee mandate list --agent <agent> --include-inactive`
4. Revoke old mandates:
   - `trustee mandate revoke --mandate-hash <old_hash> --issuer-key <old_key>`
5. Remove old issuer trust:
   - `trustee mandate trust-issuer --agent <agent> --issuer <old_issuer> --deny`

## Emergency Kill Switch

1. Pause the affected agent immediately:
   - `trustee mandate pause-agent --agent <agent> --pause true`
2. Confirm paused state:
   - `trustee mandate status --mandate-hash <hash>` (registry active should be false)
3. Revoke all high-risk active mandates for the agent.
4. Rotate issuer keys before unpausing.

To resume:
- `trustee mandate pause-agent --agent <agent> --pause false`

## Outage / Degraded Mode

Fail-closed policy for agent-initiated path:
- If registry status cannot be fetched, signing must fail.
- If local mandate integrity verification fails, signing must fail.
- If budget reserve/finalize path errors, signing/payment must fail.

Operator actions:
1. Identify failing dependency (RPC, local state, credential service).
2. Keep agent paused until root cause is resolved.
3. Re-run status checks and a dry-run payment before unpausing.

## Break-Glass (Manual-Only)

Break-glass is for explicit human operation only and is out-of-band from autonomous flow.

Requirements:
- Time-boxed approval window.
- Logged operator identity and reason.
- Post-incident revocation/rotation of temporary credentials.
- Incident summary recorded in project docs.
