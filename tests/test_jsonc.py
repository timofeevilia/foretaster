import json

import pytest

from foretaster.jsonc import strip_jsonc


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('{"a": 1}', {"a": 1}),
        ('{"a": 1 // note\n}', {"a": 1}),
        ('{/* lead */ "a": /* mid */ 1}', {"a": 1}),
        ('{"a": [1, 2,], "b": {"c": 3,},}', {"a": [1, 2], "b": {"c": 3}}),
        ('{"a": 1, // trailing comma before comment\n}', {"a": 1}),
        ('{"a": 1} // comment at end of file', {"a": 1}),
        ('{"a": 1} /* unterminated', {"a": 1}),
    ],
)
def test_parses_after_stripping(source: str, expected: object) -> None:
    assert json.loads(strip_jsonc(source)) == expected


@pytest.mark.parametrize(
    "value",
    ["http://example.com/a", "/* not a comment */", "a,]", "a,}", 'quote \\" // still string'],
)
def test_string_contents_are_untouched(value: str) -> None:
    source = json.dumps({"key": value})
    assert json.loads(strip_jsonc(source)) == {"key": value}


def test_offsets_and_lines_are_preserved() -> None:
    source = '{\n  // comment\n  "a": 1, /* x\n y */\n  "b": 2,\n}'
    stripped = strip_jsonc(source)
    assert len(stripped) == len(source)
    assert stripped.count("\n") == source.count("\n")
    assert stripped.index('"b"') == source.index('"b"')


def test_unterminated_string_does_not_hang() -> None:
    assert strip_jsonc('{"a": "abc') == '{"a": "abc'
    assert strip_jsonc('{"a": "abc\\') == '{"a": "abc\\'
