"""
Callback type definitions for the librats Python bindings.

The ``*Type`` names are the raw ``ctypes`` CFUNCTYPE prototypes that match the
typedefs in the C ABI (``src/bindings/rats.h``). Every C callback takes an
opaque ``void* user`` as its first argument. Binary payloads arrive as a
``void*`` + ``size_t`` length pair (declared ``c_void_p`` + ``c_size_t``);
string-ish arguments (peer ids, topics, type names, JSON text) arrive as
``c_char_p``.

The matching ``*Callback`` aliases describe the Pythonic signatures exposed by
:class:`~librats_py.core.RatsClient`, after the wrappers in ``core.py`` decode
hex ids and copy payload bytes.
"""

from typing import Any, Callable, Optional
from ctypes import (
    CFUNCTYPE, c_void_p, c_char_p, c_size_t, c_int, c_uint64, c_int64,
)

# --- Raw C callback prototypes (must mirror rats.h exactly) ---

# rats_peer_cb(user, peer_id_hex)
PeerCallbackType = CFUNCTYPE(None, c_void_p, c_char_p)

# rats_message_cb(user, peer_id_hex, data, len)
MessageCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_void_p, c_size_t)

# rats_topic_cb(user, peer_id_hex, topic, data, len)
TopicCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_char_p, c_void_p, c_size_t)

# rats_json_cb(user, peer_id_hex, json)
JsonCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_char_p)

# rats_file_offer_cb(user, peer_id_hex, transfer_id, name, size, is_directory)
FileOfferCallbackType = CFUNCTYPE(
    None, c_void_p, c_char_p, c_uint64, c_char_p, c_uint64, c_int
)

# rats_file_progress_cb(user, transfer_id, peer_id_hex, bytes_transferred, total_bytes, status)
FileProgressCallbackType = CFUNCTYPE(
    None, c_void_p, c_uint64, c_char_p, c_uint64, c_uint64, c_int
)

# rats_file_complete_cb(user, transfer_id, success, path)
FileCompleteCallbackType = CFUNCTYPE(None, c_void_p, c_uint64, c_int, c_char_p)


# --- Pythonic callback signatures (post-decoding) ---

# (peer_id: str) -> None
PeerCallback = Optional[Callable[[str], None]]
# (peer_id: str, data: bytes) -> None
MessageCallback = Optional[Callable[[str, bytes], None]]
# (peer_id: str, topic: str, data: bytes) -> None
TopicCallback = Optional[Callable[[str, str, bytes], None]]
# (peer_id: str, payload: Any) -> None  (payload is parsed JSON)
JsonCallback = Optional[Callable[[str, Any], None]]
# (peer_id: str, transfer_id: int, name: str, size: int, is_directory: bool) -> None
FileOfferCallback = Optional[Callable[[str, int, str, int, bool], None]]
# (transfer_id: int, peer_id: str, bytes_transferred: int, total_bytes: int, status: int) -> None
FileProgressCallback = Optional[Callable[[int, str, int, int, int], None]]
# (transfer_id: int, success: bool, path: str) -> None
FileCompleteCallback = Optional[Callable[[int, bool, str], None]]
