from . import terminal, json_out, sarif, vex, evidence

FORMATTERS = {
    "terminal": terminal.render,
    "json": json_out.render,
    "sarif": sarif.render,
    "vex": vex.render,
}

__all__ = ["terminal", "json_out", "sarif", "vex", "evidence", "FORMATTERS"]
