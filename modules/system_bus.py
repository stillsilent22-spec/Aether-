def bus_dispatch(event: dict, handlers: dict) -> dict:
    if "type" not in event:
        return {"status": "error"}
    t = event["type"]
    if t not in handlers:
        return {"status": "error"}
    fn = handlers[t]
    fn(event["payload"])
    return {"status": "ok"}

def bus_register(handlers: dict, name: str, fn):
    handlers[name] = fn
