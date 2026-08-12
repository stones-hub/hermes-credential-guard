"""R2A/A1: strict <CREDENTIAL:name> logical reference analysis."""

from __future__ import annotations

import copy

import pytest

from credential_guard.references import (
    CredentialReference,
    ReferenceAnalysis,
    ReferenceError,
    analyze_references,
)


REGISTERED = frozenset({"jenkins-token", "db-password", "api-key"})


def test_01_no_reference_returns_empty_and_deepcopy_equivalent():
    args = {"target": "jenkins-production", "note": "hello", "n": 1}
    original = copy.deepcopy(args)
    result = analyze_references(args, REGISTERED)
    assert isinstance(result, ReferenceAnalysis)
    assert result.has_reference is False
    assert result.references == ()
    assert result.args == original
    assert result.args is not args
    args["note"] = "mutated"
    assert result.args["note"] == "hello"


def test_02_legal_full_value_reference():
    args = {
        "target": "jenkins-production",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    result = analyze_references(args, REGISTERED)
    assert result.has_reference is True
    assert len(result.references) == 1
    ref = result.references[0]
    assert isinstance(ref, CredentialReference)
    assert ref.credential_name == "jenkins-token"
    assert result.args["credential"] == "<CREDENTIAL:jenkins-token>"


def test_03_records_exact_arg_path():
    args = {
        "target": "jenkins-production",
        "auth": {"credential": "<CREDENTIAL:jenkins-token>"},
        "items": [{"x": 1}, {"credential": "<CREDENTIAL:api-key>"}],
    }
    # Two refs → rejected in test_06; use single nested path here.
    args = {
        "target": "jenkins-production",
        "auth": {"credential": "<CREDENTIAL:jenkins-token>"},
    }
    result = analyze_references(args, REGISTERED)
    assert result.references[0].arg_path == ("auth", "credential")


def test_04_name_must_match_name_re_and_be_registered():
    with pytest.raises(ReferenceError) as unreg:
        analyze_references(
            {"credential": "<CREDENTIAL:not-registered>"},
            REGISTERED,
        )
    assert unreg.value.code == "UNREGISTERED_CREDENTIAL"

    with pytest.raises(ReferenceError) as bad:
        analyze_references(
            {"credential": "<CREDENTIAL:Jenkins-Token>"},
            REGISTERED,
        )
    # Uppercase breaks exact pattern → malformed, or name re fail.
    assert bad.value.code in {"MALFORMED_REFERENCE", "INVALID_CREDENTIAL_NAME"}


def test_05_reject_bearer_whitespace_case_truncation_nested_encoded():
    cases = [
        "Bearer <CREDENTIAL:jenkins-token>",
        " <CREDENTIAL:jenkins-token>",
        "<CREDENTIAL:jenkins-token> ",
        "<credential:jenkins-token>",
        "<CREDENTIAL:jenkins-token",
        "<CREDENTIAL:jenkins-token>>",
        "<CREDENTIAL:<CREDENTIAL:jenkins-token>>",
        "%3CCREDENTIAL%3Ajenkins-token%3E",
        "<CREDENTIAL:jenkins-token>\u200b",
    ]
    for value in cases:
        with pytest.raises(ReferenceError) as exc:
            analyze_references({"credential": value}, REGISTERED)
        assert exc.value.code == "MALFORMED_REFERENCE", value


def test_06_reject_two_or_more_references_in_one_call():
    args = {
        "a": "<CREDENTIAL:jenkins-token>",
        "b": "<CREDENTIAL:api-key>",
    }
    with pytest.raises(ReferenceError) as exc:
        analyze_references(args, REGISTERED)
    assert exc.value.code == "MULTIPLE_REFERENCES"


def test_07_reject_reference_in_dict_key_or_non_string_structure():
    with pytest.raises(ReferenceError) as key_exc:
        analyze_references(
            {"<CREDENTIAL:jenkins-token>": "x"},
            REGISTERED,
        )
    assert key_exc.value.code == "REFERENCE_IN_KEY"

    with pytest.raises(ReferenceError) as bytes_exc:
        analyze_references(
            {"credential": b"<CREDENTIAL:jenkins-token>"},
            REGISTERED,
        )
    assert bytes_exc.value.code == "UNSUPPORTED_STRUCTURE"


def test_08_any_credential_marker_residue_fail_closed():
    residues = [
        "prefix <CREDENTIAL:jenkins-token> suffix",
        "see < CREDENTIAL:jenkins-token>",
        "x<CREDENTIAL:y",
        "almost <CREDENTIAL:",
    ]
    for value in residues:
        with pytest.raises(ReferenceError) as exc:
            analyze_references({"note": value}, REGISTERED)
        assert exc.value.code == "MALFORMED_REFERENCE", value


def test_09_module_has_no_restore_api_and_plain_text_untouched():
    import credential_guard.references as mod

    assert not hasattr(mod, "restore")
    assert not hasattr(mod, "resolve")
    assert not hasattr(mod, "materialize")
    assert not hasattr(mod, "inject")
    text = "docs mention <CREDENTIAL:name> only as documentation"
    # Plain chat-like string that contains a malformed marker must still
    # fail closed when present as a tool arg value — but ordinary content
    # without the marker is fine.
    plain = {"path": "/tmp/notes.txt", "content": "use a password manager"}
    result = analyze_references(plain, REGISTERED)
    assert result.has_reference is False
    assert result.args == plain
    # Documentation-like residue in tool args is still fail closed.
    with pytest.raises(ReferenceError):
        analyze_references({"content": text}, REGISTERED)
