def is_int(s, base=10):
    try:
        int(s, base)
        return True
    except Exception:
        return False
