# Data Principal rights and erasure

Answering access requests (Section 11), carrying out erasure (Sections 8(7) and 12), and
deciding when erasure is due.

From [NIST Privacy Framework and DPDPA](https://statechecksecurity.com/blog/nist-privacy-framework-dpdpa),
[SOC 2 and DPDPA](https://statechecksecurity.com/blog/soc-2-dpdpa-compliance) and
[ISO 27001 and DPDPA](https://statechecksecurity.com/blog/dpdpa-iso-27001-mapping).

| File | What it is |
|---|---|
| `rights_service.py` | Access summary (data, purposes, the processors and fiduciaries it was shared with) and erasure across every system in the inventory, skipping systems under a legal hold and saying so |
| `erasure_triggers.py` | Decides whether erasure is due: consent withdrawn, Data Principal request, purpose completed, or inactivity past a prescribed period |

### Correction & Nomination Services (Statutory Extension)

| Feature | Statutory Basis | Description |
|---|---|---|
| Correction & Updating | Section 12(1)–(2) | Updates personal data across all affected systems (including held systems, as retention obligations do not justify retaining inaccurate data) and notifies downstream entities |
| Nomination | Section 14, Rule 14 | Registers and retrieves nomination for death or incapacity, recording privacy-preserving reference tokens in audit logs |

## Before you use it

- **Inventory.** Implement `DataInventory` against your data catalogue or CMDB.
  `InMemoryInventory` shows the shape.
- **Inactivity periods.** Configure `retention_config` only for purposes that carry a
  prescribed period. The Third Schedule's three years applies to the listed large e-commerce,
  online-gaming and social-media platforms; others have no inactivity trigger. Before an
  inactivity erasure, tell the Data Principal at least 48 hours ahead (Rule 8(2)).
- **Legal holds.** Retention another law requires (tax, RBI, court orders) overrides erasure;
  `legal_holds()` is where that decision lives.
- **Processors.** Section 8(7)(b) makes you cause your processors to erase too; the
  evaluation says when to cascade, and the fan-out table in `../consent/schema.sql` tracks it.

## Tests

`tests/test_rights_and_erasure.py`.
