from rimscan_cli.recon._http import USER_AGENT, make_session, read_capped


class Resp:
    def __init__(self, data: bytes, headers=None, encoding="ISO-8859-1"):
        self._data, self.headers, self.encoding = data, headers or {}, encoding
        self.closed = False

    def iter_content(self, chunk_size=0):
        for i in range(0, len(self._data), 4):
            yield self._data[i:i + 4]

    def close(self):
        self.closed = True


def test_session_identifies_itself_and_limits_redirects():
    session = make_session()
    assert session.headers["User-Agent"] == USER_AGENT and "rimscan-cli/" in USER_AGENT
    assert session.max_redirects == 5


def test_retry_count_is_configurable():
    assert make_session().get_adapter("https://a.example").max_retries.total == 2
    assert make_session(retries=0).get_adapter("https://a.example").max_retries.total == 0


def test_body_is_capped_and_response_closed():
    response = Resp(b"x" * 100)
    assert read_capped(response, 10) == "x" * 10
    assert response.closed


def test_undeclared_charset_is_decoded_as_utf8_not_latin1():
    text = "Ошибка 402"
    response = Resp(text.encode(), {"Content-Type": "text/html"}, encoding="ISO-8859-1")
    assert read_capped(response, 1000) == text


def test_declared_charset_is_honored():
    text = "Ошибка"
    response = Resp(text.encode("cp1251"), {"Content-Type": 'text/html; charset="windows-1251"'})
    assert read_capped(response, 1000) == text


def test_unknown_charset_falls_back_to_utf8():
    response = Resp(b"hello", {"Content-Type": "text/plain; charset=nonsense"})
    assert read_capped(response, 1000) == "hello"


def test_truncated_multibyte_character_does_not_raise():
    assert read_capped(Resp("é".encode()), 1) == "\ufffd"
