import { AttachmentFileCreationDateToken } from '../attachment/attachment-file-creation-date-token.ts';

/**
 * The name this token had before `{{attachmentFileCreationDate}}` existed. It reads the same date: the file's own,
 * which a rename does not change.
 */
export class OriginalAttachmentFileCreationDateToken extends AttachmentFileCreationDateToken {
  public constructor() {
    super('originalAttachmentFileCreationDate');
  }
}
