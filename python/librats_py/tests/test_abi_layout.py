"""The ctypes structs against the C header they mirror.

ctypes cannot see rats.h, so a field added there and not here still loads and
runs: on 64-bit it may even land in padding and look fine, while on 32-bit every
later field shifts. This reads the struct definitions out of the header and
compares field order and types, so such a change fails here instead.

Needs the source tree (the header is not shipped with the package); skipped
without it. Does not need the shared library.
"""

import os
import re
from ctypes import c_char, c_char_p, c_double, c_int, c_size_t, c_uint16, c_uint32, c_uint64

import pytest

from librats_py.ctypes_wrapper import (
    RatsBtConfig, RatsConfig, RatsFileProgress, RatsPathStats, RatsPeerInfo,
)

HEADER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "..", "..", "src", "librats", "bindings", "rats.h")

STRUCTS = {
    "rats_config_t": RatsConfig,
    "rats_peer_info_t": RatsPeerInfo,
    "rats_path_stats_t": RatsPathStats,
    "rats_file_progress_t": RatsFileProgress,
    "rats_bt_config_t": RatsBtConfig,
}

SCALARS = {
    "uint16_t": c_uint16,
    "uint32_t": c_uint32,
    "uint64_t": c_uint64,
    "size_t": c_size_t,
    "int": c_int,
    "double": c_double,
}


def _c_structs(text):
    """{name: [(c_type, field, array_len or None)]} for every typedef'd struct."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    out = {}
    for body, name in re.findall(r"typedef\s+struct\s*\{(.*?)\}\s*(\w+)\s*;", text, flags=re.S):
        fields = []
        for decl in body.split(";"):
            decl = " ".join(decl.split())
            if not decl:
                continue
            m = re.fullmatch(r"(.+?)\s*\b(\w+)\s*(?:\[(\d+)\])?", decl)
            assert m, f"{name}: cannot parse {decl!r}"
            fields.append((m.group(1).strip(), m.group(2), int(m.group(3)) if m.group(3) else None))
        out[name] = fields
    return out


def _expected_ctype(c_type, array_len):
    if array_len is not None:
        assert c_type == "char", f"only char arrays are mirrored, got {c_type}[]"
        return c_char * array_len
    if c_type.replace(" ", "") == "constchar*":
        return c_char_p
    if c_type in SCALARS:
        return SCALARS[c_type]
    if re.fullmatch(r"rats_\w+_t", c_type):
        return c_int  # an enum: int-sized in C, int-based in C++
    raise AssertionError(f"no ctypes mapping for C type {c_type!r}")


@pytest.mark.skipif(not os.path.exists(HEADER), reason="rats.h not found (not a source tree)")
@pytest.mark.parametrize("c_name", sorted(STRUCTS))
def test_struct_matches_header(c_name):
    with open(HEADER, encoding="utf-8") as f:
        c_structs = _c_structs(f.read())
    assert c_name in c_structs, f"{c_name} not found in rats.h"

    want = [(field, _expected_ctype(t, n)) for t, field, n in c_structs[c_name]]
    have = list(STRUCTS[c_name]._fields_)

    assert [f for f, _ in have] == [f for f, _ in want], f"{c_name}: field names or order differ"
    for (field, got), (_, expected) in zip(have, want):
        if hasattr(expected, "_length_"):  # a char array: ctypes makes a new type per call
            ok = getattr(got, "_type_", None) is c_char and getattr(got, "_length_", None) == expected._length_
        else:
            ok = got is expected
        assert ok, f"{c_name}.{field}: ctypes {got.__name__}, C wants {expected.__name__}"
