# Credential Templates

VeriCred uses a pluggable **Credential Template Registry** (`src/credentials/registry.ts`).
Each template defines what claims are issued, what source data is required, and what is
deliberately **never** included in the credential.

Configure the active template in `vericred.config.json`:

```json
{
  "credential": { "type": "AgeCredential", "expiresInDays": 30 },
  "templateOptions": { "ageThresholds": [18, 21], "jurisdiction": "EU" },
  "fieldMappings": { "dateOfBirth": "dateOfBirth" }
}
```

---

## AgeCredential

**Purpose:** Prove the holder meets an age threshold without revealing their date of birth.

| | Fields |
|---|---|
| Required source | `dateOfBirth` (ISO date YYYY-MM-DD) |
| Optional source | `jurisdiction` (string) |
| Issued claims | `age_over_{N}` (boolean), `age_attested_at` (YYYY-MM-DD), `jurisdiction` (string, if set) |
| **Never issued** | `dateOfBirth` — privacy invariant, enforced in code |

**templateOptions:**

| Key | Type | Default | Description |
|---|---|---|---|
| `ageThresholds` | integer[] | `[18, 21]` | Age thresholds to evaluate. Max 10 entries, each 0–130, no duplicates. |
| `jurisdiction` | string | — | Jurisdiction tag emitted in the credential (e.g. "EU", "AT"). |

**Example issued claims:**
```json
{
  "age_over_18": true,
  "age_over_21": false,
  "age_attested_at": "2026-06-03",
  "jurisdiction": "EU"
}
```

**Age calculation:** UTC-based, exact birthday boundary. A person born on 2008-06-03
becomes `age_over_18 = true` on 2026-06-03, not 2026-06-02 or 2026-06-04.

---

## EmployeeCredential

**Purpose:** Verify employment status at an organization with a specific role.
No private contact details, no personal address, no date of birth.

| | Fields |
|---|---|
| Required source | `given_name`, `family_name`, `organization`, `role` |
| Optional source | `department`, `employeeId`, `validUntil` (ISO date) |
| Issued claims | `given_name`, `family_name`, `organization`, `role`, `department`?, `employee_id`?, `valid_until`? |
| **Never issued** | `email`, `dateOfBirth`, `address`, any personal contact data |

**fieldMappings example:**
```json
{
  "given_name": "given_name",
  "family_name": "family_name",
  "organization": "organization",
  "role": "role"
}
```

---

## MembershipCredential

**Purpose:** Prove membership in an organization. Designed to work with only a member ID —
no name or email required.

| | Fields |
|---|---|
| Required source | `organization`, `membershipType` |
| Optional source | `memberId`, `memberSince` (ISO date), `memberUntil` (ISO date), `given_name`, `family_name` |
| Issued claims | `organization`, `membership_type`, `member_id`?, `member_since`?, `member_until`?, `given_name`?, `family_name`? |
| **Never issued** | `email` — even if present in holder data |

**fieldMappings example (minimal):**
```json
{
  "organization": "organization",
  "membershipType": "membershipType"
}
```

---

## Adding a new template

1. Create `src/credentials/templates/mytype.ts`
2. Import `registerTemplate` from `../registry.js`
3. Call `registerTemplate({ id, displayName, requiredFields, optionalFields, buildClaims, validateMappings })`
4. Add a side-effect import to `src/server.ts` and `src/oid4vci/issuer.ts`
5. Add a `fieldMappings` entry for each required field in `vericred.config.json`
6. Write tests in `src/credentials/__tests__/templates.test.ts`:
   - Claims that must never appear
   - Boundary conditions
   - Missing required field behavior

The server will **refuse to start** (`process.exit(1)`) if:
- `config.credential.type` does not match a registered template
- `config.fieldMappings` does not cover the template's required fields
