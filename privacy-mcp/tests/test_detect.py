from privacy_mcp.core.pii_detect import detect_regex

def test_regex_detects_email():
    text = "contact me at alice@example.com"
    f = detect_regex(text)
    assert any(x["entity"]=="EMAIL" for x in f)
