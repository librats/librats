import { NitroModules } from 'react-native-nitro-modules'
import type {
  DhtConfig,
  DhtStatus,
  FileEntry,
  FileOffer,
  FileProgress,
  FileTransferConfig,
  HolePunchConfig,
  MdnsConfig,
  NatMapping,
  NatStatus,
  PeerExchangeConfig,
  PortMappingConfig,
  PortMappingStatus,
  PubSubConfig,
  RatsConfig,
  RatsNode,
  RelayConfig,
  StorageChangeEvent,
  StorageConfig,
  StorageOperation,
  StorageStats,
  StorageValueType,
  TransferDirection,
  TransferStats,
  TransferStatus,
} from './specs/RatsNode.nitro'

export type {
  FileEntry,
  FileOffer,
  FileProgress,
  DhtConfig,
  DhtStatus,
  FileTransferConfig,
  HolePunchConfig,
  MdnsConfig,
  NatMapping,
  NatStatus,
  PeerExchangeConfig,
  PortMappingConfig,
  PortMappingStatus,
  PubSubConfig,
  RatsConfig,
  RatsNode,
  RelayConfig,
  StorageChangeEvent,
  StorageConfig,
  StorageOperation,
  StorageStats,
  StorageValueType,
  TransferDirection,
  TransferStats,
  TransferStatus,
}

/**
 * Create a librats node.
 *
 * Configuration is applied here rather than later because librats fixes it at
 * construction: pass it now, then attach listeners, then `start()`.
 *
 * ```ts
 * const node = createNode({ listenPort: 8080, protocol: 'myapp/1.0' })
 * node.onPeerConnected((id) => console.log('peer', id))
 * node.onMessage('chat', (id, data) => console.log(id, decodeUtf8(data)))
 * node.start()
 * ```
 *
 * Every `on*` registration must come before `start()` -- librats keeps those
 * handlers in unsynchronized state that reactor threads read, so the binding
 * throws rather than let a registration race with live traffic.
 *
 * Remember that a node holds live sockets and threads: stop it when the app goes
 * to the background (iOS suspends the process and tears the sockets down
 * regardless) and start it again on resume.
 */
export function createNode(config?: RatsConfig): RatsNode {
  const node = NitroModules.createHybridObject<RatsNode>('RatsNode')
  if (config !== undefined) {
    node.configure(config)
  }
  return node
}

// --- UTF-8 helpers ---------------------------------------------------------
// librats channels carry raw bytes, so text has to be encoded somewhere. These
// live here because Hermes does **not** provide `TextDecoder` (it does provide
// `TextEncoder`), so the obvious symmetric pair is not available on React
// Native and reaching for it fails only at runtime, inside a message handler.

/** Encode a string as UTF-8 bytes suitable for `send()` / `broadcast()`. */
export function encodeUtf8(text: string): ArrayBuffer {
  const out: number[] = []
  for (const char of text) {
    const c = char.codePointAt(0) as number
    if (c < 0x80) {
      out.push(c)
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f))
    } else if (c < 0x10000) {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    } else {
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 0x3f),
        0x80 | ((c >> 6) & 0x3f),
        0x80 | (c & 0x3f)
      )
    }
  }
  return new Uint8Array(out).buffer
}

/** Decode UTF-8 bytes received on a channel back into a string. */
export function decodeUtf8(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let out = ''
  let i = 0
  while (i < bytes.length) {
    const b0 = bytes[i] as number
    if (b0 < 0x80) {
      out += String.fromCodePoint(b0)
      i += 1
    } else if (b0 < 0xe0) {
      out += String.fromCodePoint(((b0 & 0x1f) << 6) | ((bytes[i + 1] as number) & 0x3f))
      i += 2
    } else if (b0 < 0xf0) {
      out += String.fromCodePoint(
        ((b0 & 0x0f) << 12) |
          (((bytes[i + 1] as number) & 0x3f) << 6) |
          ((bytes[i + 2] as number) & 0x3f)
      )
      i += 3
    } else {
      out += String.fromCodePoint(
        ((b0 & 0x07) << 18) |
          (((bytes[i + 1] as number) & 0x3f) << 12) |
          (((bytes[i + 2] as number) & 0x3f) << 6) |
          ((bytes[i + 3] as number) & 0x3f)
      )
      i += 4
    }
  }
  return out
}
