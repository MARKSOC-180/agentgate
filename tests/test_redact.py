"""redact.py 的单元测试：密钥/PII 双向脱敏。"""

from agentgate.redact import redact


def test_redacts_openai_key():
    text = "key=sk-AbCdEf0123456789ZyXwVu98765432QqQq done"
    out, found = redact(text)
    assert "sk-AbCdEf0123456789" not in out
    assert found.get("OpenAI key") == 1
    assert "[OpenAI key:" in out


def test_redacts_email():
    out, found = redact("contact jane.doe@example.com please")
    assert "jane.doe@example.com" not in out
    assert found.get("Email") == 1


def test_redacts_private_key_header():
    out, found = redact("-----BEGIN RSA PRIVATE KEY-----")
    assert found.get("Private key") == 1


def test_recurses_into_dict_and_list():
    payload = {"a": "sk-AbCdEf0123456789ZyXwVu98765432QqQq",
               "b": ["x@y.com", "ok"]}
    out, found = redact(payload)
    assert out["a"].startswith("[OpenAI key:")
    assert out["b"][0].startswith("[Email:")
    assert out["b"][1] == "ok"
    assert found["OpenAI key"] == 1
    assert found["Email"] == 1


def test_does_not_mutate_original():
    original = {"secret": "x@y.com"}
    redact(original)
    assert original["secret"] == "x@y.com"


def test_found_accumulates_across_calls():
    found = {}
    redact("a@b.com", found)
    redact("c@d.com", found)
    assert found["Email"] == 2


def test_redacts_cn_id_and_mobile():
    out, found = redact("id=110101199001011234 phone=13800138000")
    assert "110101199001011234" not in out
    assert "13800138000" not in out
    assert found.get("CN ID card") == 1
    assert found.get("CN mobile") == 1


def test_redacts_cn_uscc():
    out, found = redact("credit 91110000MA01234567 registered")
    assert "91110000MA01234567" not in out
    assert found.get("CN USCC") == 1


def test_clean_text_unchanged():
    out, found = redact("nothing sensitive here")
    assert out == "nothing sensitive here"
    assert found == {}
