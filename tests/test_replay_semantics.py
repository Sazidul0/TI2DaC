"""Sigma matching semantics of the local replay engine (SQLite-backed)."""
from ti2dac import replay


def _rule(sel: str, condition: str = "sel", extra: str = "") -> str:
    return ("title: t\nlogsource: {product: windows, category: process_creation}\ndetection:\n"
            f"  sel: {sel}\n{extra}  condition: {condition}\n")


def test_numeric_looking_strings_are_matched_verbatim():
    assert replay.evaluate(_rule("{CommandLine|contains: '1e5'}"), [{"CommandLine": "x 1e5"}, {"CommandLine": "100000"}]) == [0]
    assert replay.evaluate(_rule("{CommandLine: '0012'}"), [{"CommandLine": "0012"}, {"CommandLine": "12"}]) == [0]
    assert replay.evaluate(_rule("{CommandLine|startswith: '00'}"), [{"CommandLine": "0012"}]) == [0]


def test_numeric_comparisons_stay_numeric():
    evs = [{"DestinationPort": "443"}, {"DestinationPort": "8443"}, {"DestinationPort": "n/a"}, {}]
    assert replay.evaluate(_rule("{DestinationPort|gte: 1024}"), evs) == [1]
    assert replay.evaluate(_rule("{DestinationPort|lt: 1024}"), evs) == [0]
    assert replay.evaluate(_rule("{DestinationPort|gt: 443}"), evs) == [1]
    assert replay.evaluate(_rule("{DestinationPort|lte: 443}"), evs) == [0]
    assert replay.evaluate(_rule("{EventID: 1}"), [{"EventID": 1}, {"EventID": "1"}, {"EventID": "10"}]) == [0, 1]


def test_null_matches_absent_or_empty_field():
    evs = [{"CommandLine": "a"}, {"CommandLine": "a", "ParentUser": None},
           {"CommandLine": "a", "ParentUser": ""}, {"CommandLine": "a", "ParentUser": "x"}]
    assert replay.evaluate(_rule("{ParentUser: null}"), evs) == [0, 1, 2]
    assert replay.evaluate(_rule("{CommandLine: a}", "sel and not f", "  f: {ParentUser: null}\n"), evs) == [3]


def test_absent_fields_under_not_and_exists():
    f = "  f: {ParentImage|endswith: '\\\\x.exe'}\n"
    evs = [{"CommandLine": "a"}, {"CommandLine": "a", "ParentImage": "C:\\x.exe"}]
    assert replay.evaluate(_rule("{CommandLine: a}", "sel and not f", f), evs) == [0]
    assert replay.evaluate(_rule("{CommandLine: a}", "sel and not (f or f2)", f + "  f2: {User: bob}\n"), evs) == [0]
    assert replay.evaluate(_rule("{ParentImage|exists: true}"), evs) == [1]
    assert replay.evaluate(_rule("{ParentImage|exists: false}"), evs) == [0]


def test_case_insensitive_matching_is_unicode_aware():
    evs = [{"User": "ÄÖ\\ADMINISTRATÖR"}, {"User": "other"}]
    assert replay.evaluate(_rule("{User|contains: 'äö'}"), evs) == [0]
    assert replay.evaluate(_rule("{User: 'äö\\administratör'}"), evs) == [0]
    assert replay.evaluate(_rule("{User|endswith: 'TÖR'}"), evs) == [0]
    assert replay.evaluate(_rule("{User: 'äö*'}"), evs) == [0]


def test_like_wildcards_and_escapes_are_literal():
    evs = [{"CommandLine": "100% done_ok"}, {"CommandLine": "1000 doneXok"}]
    assert replay.evaluate(_rule("{CommandLine|contains: '100%'}"), evs) == [0]
    assert replay.evaluate(_rule("{CommandLine|contains: 'done_ok'}"), evs) == [0]
    assert replay.evaluate(_rule("{Image|endswith: '\\\\cmd.exe'}"), [{"Image": "C:\\Windows\\CMD.EXE"}, {"Image": "xcmd.exe"}]) == [0]


def test_cased_modifier_is_case_sensitive():
    evs = [{"CommandLine": "Foo"}, {"CommandLine": "foo"}, {"CommandLine": "xFoox"}, {"CommandLine": "F*o"}]
    assert replay.evaluate(_rule("{CommandLine|cased: Foo}"), evs) == [0]
    assert replay.evaluate(_rule("{CommandLine|cased|contains: Foo}"), evs) == [0, 2]
    assert replay.evaluate(_rule("{CommandLine|cased|startswith: xF}"), evs) == [2]
    assert replay.evaluate(_rule("{CommandLine|cased|endswith: oo}"), evs) == [0, 1]
    assert replay.evaluate(_rule("{CommandLine|cased: 'F\\*o'}"), evs) == [3]      # escaped '*' is literal
    assert replay.evaluate(_rule("{CommandLine|cased: 'F?o'}"), [{"CommandLine": "Fxo"}, {"CommandLine": "fxo"}]) == [0]


def test_regex_with_single_quote():
    assert replay.evaluate(_rule("{CommandLine|re: \"it's\"}"), [{"CommandLine": "it's"}, {"CommandLine": "its"}]) == [0]
