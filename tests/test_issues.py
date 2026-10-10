from __future__ import annotations

from ids.issues import Issue, Issues, ParseError, jsonable


class Opaque:
    def __repr__(self) -> str:
        return "<opaque>"


def test_jsonable_converts_bytes_tuples_keys_and_unknown_objects():
    value = {1: b"\x00\xff", "nested": (bytearray(b"ab"), memoryview(b"c")), "obj": Opaque()}
    assert jsonable(value) == {"1": "00ff", "nested": ["6162", "63"], "obj": "<opaque>"}


def test_jsonable_passes_json_scalars_through():
    assert jsonable([None, "s", 1, 2.5, True]) == [None, "s", 1, 2.5, True]


def test_add_stamps_the_collector_stage_and_makes_context_jsonable():
    issues = Issues("network")
    issues.add("truncated_packet", "short header", needed=20, data=b"\x45")
    assert issues.records == [
        Issue("network", "truncated_packet", "short header", {"needed": 20, "data": "45"})
    ]


def test_scoped_collectors_share_one_record_list_in_order():
    root = Issues("transport")
    app = root.scoped("application")
    root.add("a", "first")
    app.add("b", "second")
    assert app.records is root.records
    assert [(issue.stage, issue.code) for issue in root.records] == [
        ("transport", "a"),
        ("application", "b"),
    ]


def test_capture_parse_error_keeps_code_message_and_context():
    issues = Issues("link")
    error = ParseError("unsupported_protocol", "linktype 999", linktype=999, raw=b"\x01")
    issues.capture(error)
    assert str(error) == "linktype 999"
    assert issues.records == [
        Issue("link", "unsupported_protocol", "linktype 999", {"linktype": 999, "raw": "01"})
    ]


def test_capture_other_exception_becomes_internal_error():
    issues = Issues("decoder")
    issues.capture(ValueError("bad value"))
    issues.capture(KeyError())
    assert issues.records == [
        Issue("decoder", "internal_error", "bad value", {"exception": "ValueError"}),
        Issue("decoder", "internal_error", "KeyError", {"exception": "KeyError"}),
    ]


def test_truthiness_and_length_follow_the_records():
    issues = Issues("load")
    assert not issues
    assert len(issues) == 0
    issues.add("invalid_type", "x")
    assert issues
    assert len(issues) == 1


def test_issue_defaults_are_independent():
    first, second = Issue(), Issue()
    first.context["k"] = 1
    assert second.context == {}
    assert (second.stage, second.code, second.message) == (None, None, None)
