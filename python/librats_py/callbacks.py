"""
Callback types of the librats Python bindings.

The ``*Type`` names are the raw ``CFUNCTYPE`` prototypes matching the typedefs
in ``src/librats/bindings/rats.h``; every C callback takes ``void* user`` first.
Struct pointers (path stats, file progress) arrive as ``c_void_p`` and are read
in ``core.py``. The other names are the Pythonic signatures
:class:`~librats_py.core.RatsNode` calls once ids, payloads and structs are
decoded.
"""

from typing import Any, Callable
from ctypes import CFUNCTYPE, c_void_p, c_char_p, c_size_t, c_int, c_uint64

from .enums import CloseReason, FileProgress, PathStats

# --- Raw C prototypes (must mirror rats.h exactly) ---

# rats_peer_cb(user, peer_id)
PeerCallbackType = CFUNCTYPE(None, c_void_p, c_char_p)
# rats_disconnect_cb(user, peer_id, reason)
DisconnectCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_int)
# rats_dial_failed_cb(user, address)
DialFailedCallbackType = CFUNCTYPE(None, c_void_p, c_char_p)
# rats_message_cb(user, peer_id, data, len)
MessageCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_void_p, c_size_t)
# rats_path_cb(user, peer_id, const rats_path_stats_t*)
PathCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_void_p)
# rats_topic_cb(user, peer_id, topic, data, len)
TopicCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_char_p, c_void_p, c_size_t)
# rats_json_cb(user, peer_id, json)
JsonCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_char_p)
# rats_file_offer_cb(user, peer_id, transfer_id, name, size, is_directory)
FileOfferCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_uint64, c_char_p, c_uint64, c_int)
# rats_file_progress_cb(user, const rats_file_progress_t*)
FileProgressCallbackType = CFUNCTYPE(None, c_void_p, c_void_p)
# rats_file_complete_cb(user, peer_id, transfer_id, success, path)
FileCompleteCallbackType = CFUNCTYPE(None, c_void_p, c_char_p, c_uint64, c_int, c_char_p)

# --- Pythonic signatures ---

PeerCallback = Callable[[str], None]                          # (peer_id)
DisconnectCallback = Callable[[str, CloseReason], None]       # (peer_id, reason)
DialFailedCallback = Callable[[str], None]                    # (address "ip:port")
MessageCallback = Callable[[str, bytes], None]                # (peer_id, data)
PathCallback = Callable[[str, PathStats], None]               # (peer_id, stats)
TopicCallback = Callable[[str, str, bytes], None]             # (peer_id, topic, data)
JsonCallback = Callable[[str, Any], None]                     # (peer_id, parsed value)
FileOfferCallback = Callable[[str, int, str, int, bool], None]
#                            (peer_id, transfer_id, name, size, is_directory)
FileProgressCallback = Callable[[FileProgress], None]
FileCompleteCallback = Callable[[str, int, bool, str], None]  # (peer_id, transfer_id, success, path)
