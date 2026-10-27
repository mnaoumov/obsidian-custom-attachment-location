import { AttachmentFileModificationDateToken } from '../attachment/attachment-file-modification-date-token.ts';

/**
 * The name this token had before `{{attachmentFileModificationDate}}` existed. It reads the same date: the file's own,
 * which a rename does not change.
 */
export class OriginalAttachmentFileModificationDateToken extends AttachmentFileModificationDateToken {
  public constructor() {
    super('originalAttachmentFileModificationDate');
  }
}
