def observer_engine(O):
    metadata = {
        "length": O.get("length", None),
        "byte_sum": sum(O.get("bytes", b"")),
    }
    return {"O": O, "metadata": metadata}
