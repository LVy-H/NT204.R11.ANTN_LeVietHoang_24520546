from __future__ import annotations

import html

from ids.decoder.html import decode_entities


def test_t02_named_hex_and_unknown_entities():
    text, count = decode_entities("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#x27; &bogus;")

    assert text == "<script>alert(1)</script> & ' &bogus;"
    assert count == 6


def test_decimal_and_uppercase_hex_references():
    assert decode_entities("&#60;&#X3E;&#x1F600;") == ("<>\U0001f600", 3)


def test_named_entity_without_semicolon_is_replaced_like_html_unescape():
    assert decode_entities("a &amp b &copy2024") == ("a & b ©2024", 2)


def test_text_without_references_is_returned_as_is():
    assert decode_entities("plain & simple; a&&b") == ("plain & simple; a&&b", 0)


def test_unknown_named_and_bare_ampersand_hash_stay_literal():
    assert decode_entities("&zzz; &#; &#x; &") == ("&zzz; &#; &#x; &", 0)


def test_legacy_prefix_entity_is_replaced_like_browsers_do():
    # HTML5 reads "&not" without a semicolon, so "&notit;" is "¬it;"
    assert decode_entities("&notit;") == ("¬it;", 1)


def test_text_matches_html_unescape_on_mixed_input():
    sample = "&lt;a href=&quot;x?a=1&amp;b=2&quot;&gt; &#39;&#x2F; &bogus; &ampx &#99999999;"

    text, count = decode_entities(sample)

    assert text == html.unescape(sample)
    assert count == 9


def test_already_decoded_output_is_not_decoded_again():
    assert decode_entities("&amp;lt;") == ("&lt;", 1)


def test_invalid_code_point_reference_counts_as_replaced():
    assert decode_entities("&#0;") == ("\ufffd", 1)
