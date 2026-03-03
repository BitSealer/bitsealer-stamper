import tempfile


def write_temp_file(raw: bytes, suffix: str = "") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(raw)
        return tmp.name