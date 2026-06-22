# CLAUDE.md

## Known Issues

### Wasted per-attachment `readBinary` in attachment-path resolution → bulk-deletion freeze

Originally measured 2026-06-22 by CPU-profiling the real vault `F:\Obsidian` (~90k files)
while Advanced Exclude hid a large folder in `Full` mode (Obsidian runs a per-file
`removeFile` cascade — ~943 files in the test). `consistent-attachments-and-links`'s
delete/rename handler resolves an attachment path once per attachment link per affected
file, and each call is costly, so the bulk operation became O(N × cost) and froze the UI.

- **Contribution to the freeze: ~22–35 s** for ~943 files (the single largest contributor
  among the measured plugins).

**Root cause (confirmed 2026-06-22 by the performance integration test below).** The
consumer calls the dev-utils core `getAttachmentFilePath`, which — whenever this plugin's
patched `Vault.getAvailablePathForAttachments.extended` handler is installed — eagerly does
`await app.vault.readBinary(attachmentFile)` to read the WHOLE binary of each attachment
*before* dispatching to the handler. That read is the dominant, size-proportional cost, and
it is **pure waste** for the default templates: the only built-in token that consumes
attachment content is `${attachmentFileSize}`, and it reads `content.byteLength`, which
equals the already-available `attachmentFileStats.size` (the date tokens already use
`stats`). No default-reachable token needs the raw bytes.

The earlier "per-call `getAvailablePath` folder scan" hypothesis was wrong: every consumer
call site passes `shouldSkipDuplicateCheck: true`, so the core skips `app.vault.getAvailablePath`
(the folder-scanning duplicate check) entirely.

**Empirical per-call decomposition** (real Obsidian, 601-file temp vault, warm SSD — see
`src/attachment-path-bottleneck.desktop-performance.integration.test.ts`):

| Measurement                       | Small (1 KB) | Large (512 KB) |
|-----------------------------------|--------------|----------------|
| `readBinary` only                 | 0.618 ms     | 1.637 ms       |
| Full consumer call (read+handler) | 1.003 ms     | 1.963 ms       |
| Handler only, with content        | —            | 0.200 ms       |
| Handler only, without content     | —            | 0.165 ms       |
| Handler, thin note (1 link)       | 0.122 ms     |                |
| Handler, fat note (200 links)     | 0.173 ms     |                |

`readBinary` is ~83% of the large-attachment call and grows 2.6× from small→large; the
handler is flat (~0.2 ms) and content-independent. Absolute times here are modest because
the temp vault is warm SSD with 512 KB attachments — real vaults with multi-MB
images/PDFs/videos and cold/cloud-synced reads explain the 22–35 s field measurement.

**Fix directions (in order of impact):**

- **dev-utils core (best — fixes every consumer):** make attachment content lazy in
  `getAttachmentFilePath` — pass a `getAttachmentFileContent: () => Promise<ArrayBuffer>`
  provider in `GetAvailablePathForAttachmentsExtendedFnParams` instead of an eagerly-read
  `attachmentFileContent`, so the read happens only if a token actually pulls the bytes.
  With default settings that is zero reads.
- **This plugin:** make `attachment-file-size-token` prefer `attachmentFileStats?.size` over
  `content.byteLength`, and collapse the duplicate `getCacheSafe` + `getAllLinks` walk that
  `getCursorLine` and `getSequenceNumber` each do into a single pass. (Helps, but cannot
  avoid the core's read on its own — that has to move to a lazy provider upstream.)
- **`consistent-attachments-and-links`:** its `dirname(newPath) === dirname(file.path)`
  short-circuit only needs the attachment *folder*, not a per-file name — it could call a
  folder-only API with a DUMMY attachment (no real file ⇒ no `readBinary`).
