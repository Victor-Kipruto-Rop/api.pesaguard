# Reconciliation Certification

Ground truth must be approved before production precision and recall are considered certified.

## Register Approved Cases

Registration creates expected outcomes but does not mark them validated:

```powershell
python pesaguard_backend_pipeline/operations/ground_truth_certification.py register `
  --tenant-id tenant-a `
  --fixture pesaguard_backend_pipeline/tests/fixtures/phase3_golden_dataset.json `
  --approved-by APPROVER_ID `
  --approval-reference APPROVAL_TICKET_OR_DOCUMENT `
  --database-url $env:DATABASE_URL
```

The command requires both `--approved-by` and `--approval-reference`. It is safe to rerun for the same approved cases.

## Validate Observed Results

After the reconciliation engine has produced `reconciliation_matches` rows:

```powershell
python pesaguard_backend_pipeline/operations/ground_truth_certification.py validate `
  --tenant-id tenant-a `
  --validated-by REVIEWER_ID `
  --database-url $env:DATABASE_URL
```

The command prints a scorecard with precision, recall, false positives, false
negatives, and the approved-case count. It exits with status `0` only when every
approved case has a match, every actual status equals its expected status,
precision and recall are both `1.0`, and false positives and false negatives are
both zero. A dataset without any expected `MATCHED` case has undefined precision
and recall and cannot certify. It exits with status `2` when the scorecard does
not pass.

## Metrics

Prometheus metrics remain non-ready until at least one approved case has been validated:

- `pesaguard_reconciliation_certification_ready`
- `pesaguard_reconciliation_certification_cases`
- `pesaguard_reconciliation_precision`
- `pesaguard_reconciliation_recall`
- `pesaguard_reconciliation_false_positives`
- `pesaguard_reconciliation_false_negatives`

A production certification claim requires:

```text
certification_ready = 1
precision = 1.0
recall = 1.0
false positives = 0
false negatives = 0
```
