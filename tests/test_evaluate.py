from phantester.metrics import is_valid_assessment, wilson_interval


def test_assessment_schema_validation() -> None:
    assert is_valid_assessment(
        {"action": "allow_read_only", "reason": "signature_matches", "risk": "low"}
    )
    assert not is_valid_assessment({"action": "allow_read_only"})
    assert not is_valid_assessment(
        {
            "action": "allow_read_only",
            "reason": "signature_matches",
            "risk": "low",
            "extra": "unsafe",
        }
    )


def test_wilson_interval_for_perfect_sample_has_conservative_lower_bound() -> None:
    lower, upper = wilson_interval(20_000, 20_000)
    assert 0.999 < lower < 1.0
    assert upper == 1.0
