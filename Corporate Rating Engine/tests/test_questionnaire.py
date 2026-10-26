"""Regression tests for questionnaire.py (workbook questionnaire evaluator + conditions of cover).

Run: cd veilguard/services/corp-rating && python3 -m pytest tests/test_questionnaire.py -q
"""
import os
import sys
from pathlib import Path

import pytest

SVC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SVC))

import questionnaire as q  # noqa: E402

CONFIRMED = {"confirmed": ["entities_minimum", "firewall"]}


@pytest.fixture(scope="module")
def example():
    """The workbook's own embedded example answers (all strong)."""
    m = q._model()
    return {x["row"]: x["default"] for x in m["questions"] if x.get("default") not in (None, "", " ")}


def test_selftest_reproduces_every_cached_workbook_cell():
    res = q.selftest()
    assert res["cells_checked"] >= 200
    assert res["mismatches"] == []
    assert res["condition_row_drift"] == []
    assert abs(res["posture"] - 0.9999762670000001) < 1e-6  # selftest rounds to 6 dp
    assert res["flags"] == 35


def test_strong_answers_band_very_strong_and_are_ready(example):
    r = q.assess(example, CONFIRMED)
    assert r["status"] == "ready"
    assert r["maturity"]["multiplier"] == 0.75
    assert r["premium_modifier"] == 0.75


def test_unconfirmed_conditions_hold_back_the_modifier(example):
    r = q.assess(example)
    assert r["status"] == "information_required"
    ids = {c["id"] for c in r["conditions"]["information_required"]}
    assert ids == {"entities_minimum"}  # firewall is inferred from the perimeter controls
    assert r["premium_modifier"] is None


def test_firewall_inferred_only_with_perimeter_controls_edr_and_backups(example):
    def fw(answers):
        r = q.assess(answers)
        return next(c for k in ("met", "not_met", "information_required") for c in r["conditions"][k]
                    if c["id"] == "firewall")
    assert fw(example)["status"] == "met"
    assert fw({**example, 140: "No"})["status"] == "met"            # IPS still present
    assert fw({**example, 140: "No", 161: "No"})["status"] == "unconfirmed"
    assert fw({**example, 141: "No"})["status"] == "unconfirmed"
    assert fw({**example, 152: "No"})["status"] == "unconfirmed"   # EDR fails
    assert fw({**example, 40: "Monthly"})["status"] == "unconfirmed"  # backups fail
    r = q.assess({**example, 141: "No"}, {"confirmed": ["firewall"]})
    assert "firewall" in {c["id"] for c in r["conditions"]["met"]}


def test_sophos_tier_sets_the_discount_automatically(example):
    tiers = {
        "Complete \u2013 Endpoints deployed": ("sophos_complete_endpoints", 0.30),
        "Complete \u2013 Endpoints not deployed": ("sophos_complete_no_endpoints", 0.20),
        "Essentials \u2013 Endpoints deployed": ("sophos_essentials_endpoints", 0.15),
        "Essentials \u2013 Endpoints not deployed": ("sophos_essentials_no_endpoints", 0.10),
    }
    for answer, (tier, disc) in tiers.items():
        m = q.assess({**example, 256: "Yes", 257: answer})["mdr"]
        assert (m["status"], m["tier"], m["discount"]) == ("auto", tier, disc)
        assert "all access devices and entire network" in m["label"]


def test_non_sophos_mdr_is_conservative_and_needs_validation(example):
    ns = {**example, 256: "No", 258: "Yes"}
    m = q.assess(ns)["mdr"]
    assert m["status"] == "validation_required" and m["discount"] == 0.0
    assert m["eligible_discount"] == 0.20
    m = q.assess({**ns, 261: "No"})["mdr"]
    assert m["status"] == "manual" and m["discount"] == 0.0
    m = q.assess(ns, {"confirmed": ["mdr_equivalent"]})["mdr"]
    assert m["status"] == "validated" and m["discount"] == 0.20
    assert q.assess({**example, 256: "No", 258: "No"})["mdr"]["status"] == "none"


def test_sophos_condition_accepts_complete_with_or_without_endpoints(example):
    gov = {**example, 13: "Government"}
    for tier in ("Complete \u2013 Endpoints deployed", "Complete \u2013 Endpoints not deployed"):
        r = q.assess({**gov, 256: "Yes", 257: tier}, CONFIRMED)
        assert "sophos_mdr" in {c["id"] for c in r["conditions"]["met"]}
    r = q.assess({**gov, 256: "Yes", 257: "Essentials \u2013 Endpoints deployed"}, CONFIRMED)
    assert "sophos_mdr" in {c["id"] for c in r["conditions"]["not_met"]}
    ns = {**gov, 256: "No", 258: "Yes"}
    r = q.assess(ns, CONFIRMED)
    assert "sophos_mdr" in {c["id"] for c in r["conditions"]["information_required"]}
    r = q.assess(ns, {"confirmed": ["entities_minimum", "mdr_equivalent"]})
    assert "sophos_mdr" in {c["id"] for c in r["conditions"]["met"]}


def test_clients_clients_outage_threshold_is_scored_on_its_own_answer(example):
    base = q.assess(example)["posture"]
    assert q.assess({**example, 100: "48 hours"})["posture"] < base
    assert q.assess({**example, 98: "48 hours"})["posture"] < base


def test_failed_conditions_block_quote_and_posture_drops(example):
    w = dict(example)
    w.update({152: "No", 40: "Monthly", 121: "no"})
    r = q.assess(w, dict(CONFIRMED, assume_conditions=False))
    assert r["status"] == "conditions_not_met"
    assert {"backups_weekly", "password_policy", "edr"} <= {c["id"] for c in r["conditions"]["not_met"]}
    assert r["premium_modifier"] is None
    assert r["posture"] < q.assess(example, CONFIRMED)["posture"]


def test_conditions_of_cover_are_assumed_met_in_the_posture(example):
    # Underwriter 2026-10-16: a client that incepts must meet the conditions, so the posture is scored
    # with the condition rows as Yes; the unmet ones become the 'subject to' list.
    w = dict(example)
    w.update({152: "No", 40: "Monthly", 121: "no"})
    r = q.assess(w, CONFIRMED)
    full = q.assess(example, CONFIRMED)
    assert r["status"] == "conditions_not_met"
    assert {"backups_weekly", "password_policy", "edr"} <= set(r["subject_to"])
    assert set(r["assumed_for_conditions"]) == {"40", "121", "152"}
    # Underwriter 2026-10-16: weekly is the norm; bi-weekly is an underwriter relaxation, never assumed.
    assert r["assumed_for_conditions"]["40"]["assumed"] == "Weekly"
    assert r["posture_as_answered"] < r["posture"]
    assert r["posture"] <= full["posture"]
    assert r["premium_modifier"] == r["rating_band"]["multiplier"]  # quoted subject to conditions
    assert r["answers"]["152"] == "No"  # the client's own answer is kept
    # limited to the conditions the quote lists
    r2 = q.assess(w, dict(CONFIRMED, quote_conditions=["edr"]))
    assert set(r2["assumed_for_conditions"]) == {"152"}
    assert r2["premium_modifier"] is None
    # MDR conditions are never assumed (they drive the discount)
    assert all(a["condition"] != "sophos_mdr" for a in r["assumed_for_conditions"].values())


def test_posture_bands_follow_the_price_sheet(example):
    half = {k: ("No" if (k % 2 and v == "Yes") else v) for k, v in example.items()}
    r = q.assess(half, {"assume_conditions": False})
    assert r["posture"] < 0.6
    assert r["maturity"]["multiplier"] == 1.25


def test_empty_answers_score_zero_not_the_example():
    r = q.assess({})
    assert r["posture"] == 0.0
    assert r["status"] == "information_required"
    assert r["completeness"]["answered"] == 0


def test_sophos_condition_only_for_public_or_soe(example):
    priv = {**example, 13: "Private", 256: "No", 258: "No"}
    r = q.assess(priv, CONFIRMED)
    assert "sophos_mdr" in {c["id"] for c in r["conditions"]["not_applicable"]}
    gov = {**example, 13: "Government", 256: "No", 258: "No"}
    r = q.assess(gov, CONFIRMED)
    assert "sophos_mdr" in {c["id"] for c in r["conditions"]["not_met"]}
    soe = {**example, 13: "Private", 256: "No", 258: "No"}
    r = q.assess(soe, dict(CONFIRMED, soe=True))
    assert "sophos_mdr" in {c["id"] for c in r["conditions"]["not_met"]}


def test_funds_protect_payment_controls_skipped_when_not_quoted(example):
    w = {**example, 277: "No"}
    r = q.assess(w, dict(CONFIRMED, funds_protect=False))
    assert "payment_controls" in {c["id"] for c in r["conditions"]["not_applicable"]}
    r = q.assess(w, CONFIRMED)
    assert "payment_controls" in {c["id"] for c in r["conditions"]["not_met"]}


def test_answer_normalisation_and_rejection():
    r = q.assess({"40": "weekly ", "R199": "75 - 100%", 246: "External - 24 / 7",
                  134: ["SPF", "DKIM", "DMARC"], 152: True, 999: "x", 237: "banana"})
    a = r["answers"]
    assert a["40"] == "Weekly" and a["152"] == "Yes" and a["199"] == "75–100%"
    assert a["246"] == "External - 24/7" and a["134"] == "DMARC, SPF & DKIM"
    rejected = {x.get("row") or x.get("key") for x in r["rejected"]}
    assert rejected == {999, 237}


def test_blank_proposal_form_reads_as_unanswered():
    pdfs = sorted((SVC / "_source").glob("**/*.pdf"))
    if not pdfs:
        pytest.skip("client proposal form not present (_source/ is gitignored)")
    f = q.read_form(str(pdfs[0]))
    assert f["ok"] and f["answers"] == {} and f["form_version_match"] == 1.0


def test_incomplete_forms_are_rated_average(example):
    sparse = {k: v for i, (k, v) in enumerate(example.items()) if i % 3 == 0}
    r = q.assess(sparse)
    assert r["completeness"]["pct"] < q.RATE_ON_ANSWERS_MIN
    assert r["rating_band"]["basis"] == "average"
    assert r["rating_band"]["band"] == "Moderate" and r["rating_band"]["multiplier"] == 1.0
    assert q.assess(sparse, {"rating_basis": "answers"})["rating_band"]["basis"] == "answers"


def test_complete_forms_are_rated_on_their_answers(example):
    r = q.assess(example, CONFIRMED)
    assert r["rating_band"]["basis"] == "answers"
    assert r["premium_modifier"] == 0.75


def test_blank_minimum_condition_is_a_condition_of_cover_not_a_penalty(example):
    # Underwriter 2026-10-16: a minimum-condition question left blank is read as No, quoted as a
    # condition of cover and confirmed with the client. The posture is not penalised.
    full = q.assess(example, CONFIRMED)
    blank = {k: v for k, v in example.items() if k != 69}
    r = q.assess(blank, dict(CONFIRMED, left_blank=True))
    assert "vuln_remediation" in r["subject_to"]
    assert r["confirm_with_client"] == ["vuln_remediation"]
    assert r["assumed_for_conditions"]["69"]["left_blank"] is True
    assert r["posture"] == full["posture"]
    assert r["completeness"]["answered"] == full["completeness"]["answered"]
    assert r["premium_modifier"] == r["rating_band"]["multiplier"]
    # a form that never asked the question: ask the broker, nothing assumed
    r = q.assess(blank, CONFIRMED)
    assert "vuln_remediation" in {c["id"] for c in r["conditions"]["information_required"]}
    assert r["confirm_with_client"] == [] and "69" not in r["assumed_for_conditions"]
    # only the listed rows count as left blank
    r = q.assess(blank, dict(CONFIRMED, left_blank=[69]))
    assert r["confirm_with_client"] == ["vuln_remediation"]
    # MDR is never assumed from a blank
    gov = {k: v for k, v in example.items() if k not in (256, 257)}
    gov[13] = "Government"
    r = q.assess(gov, dict(CONFIRMED, left_blank=True))
    assert "sophos_mdr" not in r["confirm_with_client"]
