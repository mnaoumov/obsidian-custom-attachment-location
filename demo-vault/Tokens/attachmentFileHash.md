# `{{attachmentFileHash}}`

Hash of the attachment file's content, in hex. While pasting, the incoming file's - after any conversion to JPEG.

Unlike [`{{uuid}}`](<./uuid.md>) or [`{{random}}`](<./random.md>), the same bytes always give the same name, so `Collect attachments` and `Move attachment to proper folder` leave an unchanged file where it is. The name is not kept in step with the content by itself: when you edit an attachment (say you annotate a PDF), it keeps its old name until one of those commands runs on it again. Two files with the same content get the same hash, so pasting the second one places it beside the first with the usual numeric suffix (`2cf24dba5fb0 1.png`). Turn on **Deduplicate identical attachments** and the next `Collect attachments` or `Move attachment to proper folder` points its links at the first file and moves the copy to the trash.

The whole file is read to hash it, so a large attachment costs a read the other tokens avoid.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  algorithm?: 'BLAKE3' | 'CRC32' | 'MD5' | 'SHA-1' | 'SHA-224' | 'SHA-256' | 'SHA-384' | 'SHA-512' | 'SHA3-224' | 'SHA3-256' | 'SHA3-384' | 'SHA3-512'; // default: 'SHA-256'
  case?: 'lower' | 'upper'; // default: 'lower'
  length?: number; // default: the full hash
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{attachmentFileHash}}`: `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`.
- `{{attachmentFileHash:{length:12}}}`: `2cf24dba5fb0`.
- `{{attachmentFileHash:{algorithm:'SHA-1',case:'upper',length:8}}}`: `AAF4C61D`.
- `{{attachmentFileHash:{algorithm:'MD5'}}}`: `5d41402abc4b2a76b9719d911017c592`.
- `{{attachmentFileHash:{algorithm:'CRC32'}}}`: `3610a686`, the same 8 digits Total Commander writes to an `.sfv` file.
