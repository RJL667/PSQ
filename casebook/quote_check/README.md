# Returned-quote checker

Checks that what the quoting team issues matches what we instructed: the quote PDF first, then the cover email to the broker.
It stays useful after the in-house ERP goes live, because only the quote adapter changes.

## Run

```
python3 check_quote.py --instruction <sent_instruction.txt> [--section <b1_xx>] \
    --quote <quote1.pdf> [--quote <quote2.pdf>] \
    [--entity "<Insured name>"] [--cover-email <cover_email.txt>] [--json out.json]
```

Exit code: 0 = all match, 1 = at least one MISMATCH, 2 = only CHECK items.

## What it compares

- Insured name, product (corporate / business), turnover, main and sub-industry.
- Per limit: cover limit, annual premium ex RM, every benefit, CBI endorsement, BI and CBI waiting periods, excess.
- Pending-reinsurer endorsement where the instruction says so.
- Computer Crime absent when Funds Protect is on; Funds Protect fraud-control conditions present.
- RM fee is 6% on top when the instruction says "without RM fee", total = premium + fee; no fee when "no RM".
- Conditions of cover word for word; wording drift, missing and extra conditions are flagged.
- Every instructed limit has a quote file.
- Cover email (optional): every rand amount must exist on the issued quote(s), each limit is named, conditions are referred to, pending reinsurer approval is stated.

## Design

```
instruction email text -> parse_instruction()
quote PDF / text       -> parse_quote_text()
future ERP record      -> quote_from_erp_json()   (placeholder, same output shape)
compare() + check_cover_email() -> rows of (limit, item, instruction, quote, status)
```

## Validation on past quotes

| Case | Result |
|---|---|
| b1_01 | 0 mismatch |
| b1_02 | 0 mismatch (R10M quote file not in casebook) |
| b1_04 | 0 mismatch (R60M quote file not in casebook) |
| b1_05 | 0 mismatch (R5M quote file not in casebook) |
| b1_07 | 1 mismatch: sub-industry issued as "Administration Of Economic Programs", instructed "Administration Of Environmental Quality And Housing Programs" |

A planted typo amount in a test cover email was caught as "not on quote".

## Known limits

- The instruction rarely names the insured, so the name is a CHECK unless `--entity` is passed.
- RM exceptions written in prose ("except Aon") are flagged as CHECK, not interpreted.
- The quote reader is built on the current admin-system PDF layout; a layout change needs `parse_quote_text()` updated.
