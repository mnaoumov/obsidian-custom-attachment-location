import { NewAttachmentOperation } from '../attachment-saving/new-attachment-operation.ts';

/**
 * Every operation that names or places an attachment, each with its own templates.
 *
 * The four new-attachment operations mirror {@link NewAttachmentOperation}, which is what `PastedImageMarker` records
 * per `ArrayBuffer`; the other three act on an attachment that already exists.
 */
export enum AttachmentOperation {
  /**
   * `Collect attachments`: moving an attachment to where its note's settings say it belongs.
   */
  Collect = 'Collect',

  /**
   * A file dropped into a note, a canvas, the file explorer or a base.
   */
  DroppedFile = 'DroppedFile',

  /**
   * The note the attachment belongs to was renamed or moved.
   */
  NoteRename = 'NoteRename',

  /**
   * A new attachment saved with no paste or drop: another plugin, or a core feature such as the audio recorder.
   */
  OtherNewAttachment = 'OtherNewAttachment',

  /**
   * A pasted file that is not a screenshot.
   */
  PastedFile = 'PastedFile',

  /**
   * A pasted screenshot.
   */
  PastedImage = 'PastedImage',

  /**
   * The `Rename attachments in current note` command. It never moves a file, so it has no folder template.
   */
  RenameCommand = 'RenameCommand'
}

/**
 * A settings key that holds a per-operation template.
 */
export type AttachmentOperationTemplateKey =
  | 'collectedAttachmentFileName'
  | 'collectedAttachmentFolderPath'
  | 'droppedFileAttachmentFileName'
  | 'droppedFileAttachmentFolderPath'
  | 'manuallyRenamedAttachmentFileName'
  | 'otherNewAttachmentFileName'
  | 'otherNewAttachmentFolderPath'
  | 'pastedFileAttachmentFileName'
  | 'pastedFileAttachmentFolderPath'
  | 'pastedImageAttachmentFileName'
  | 'pastedImageAttachmentFolderPath'
  | 'renamedAttachmentFileName';

/**
 * The settings keys holding an operation's templates.
 *
 * Every key follows one pattern, `<operation>AttachmentFolderPath` / `<operation>AttachmentFileName`, and an empty
 * value in any of them means "use the default". The keys are the persisted ones, unchanged, so this table is the one
 * shape over them rather than a new place the values live.
 */
export interface AttachmentOperationTemplateKeys {
  readonly fileName: AttachmentOperationTemplateKey;
  readonly folderPath: AttachmentOperationTemplateKey | null;
}

/**
 * Which keys hold which operation's templates, in the order the settings tab lists the operations.
 */
export const ATTACHMENT_OPERATION_TEMPLATE_KEYS: Readonly<Record<AttachmentOperation, AttachmentOperationTemplateKeys>> = {
  /* eslint-disable perfectionist/sort-objects -- The order is the one the settings tab shows. */
  [AttachmentOperation.PastedImage]: { fileName: 'pastedImageAttachmentFileName', folderPath: 'pastedImageAttachmentFolderPath' },
  [AttachmentOperation.PastedFile]: { fileName: 'pastedFileAttachmentFileName', folderPath: 'pastedFileAttachmentFolderPath' },
  [AttachmentOperation.DroppedFile]: { fileName: 'droppedFileAttachmentFileName', folderPath: 'droppedFileAttachmentFolderPath' },
  [AttachmentOperation.OtherNewAttachment]: { fileName: 'otherNewAttachmentFileName', folderPath: 'otherNewAttachmentFolderPath' },
  [AttachmentOperation.Collect]: { fileName: 'collectedAttachmentFileName', folderPath: 'collectedAttachmentFolderPath' },
  [AttachmentOperation.NoteRename]: { fileName: 'renamedAttachmentFileName', folderPath: null },
  [AttachmentOperation.RenameCommand]: { fileName: 'manuallyRenamedAttachmentFileName', folderPath: null }
  /* eslint-enable perfectionist/sort-objects -- The order is the one the settings tab shows. */
};

const NEW_ATTACHMENT_OPERATIONS: Readonly<Record<NewAttachmentOperation, AttachmentOperation>> = {
  [NewAttachmentOperation.DroppedFile]: AttachmentOperation.DroppedFile,
  [NewAttachmentOperation.Other]: AttachmentOperation.OtherNewAttachment,
  [NewAttachmentOperation.PastedFile]: AttachmentOperation.PastedFile,
  [NewAttachmentOperation.PastedImage]: AttachmentOperation.PastedImage
};

/**
 * The operation a new attachment's arrival maps to.
 *
 * @param newAttachmentOperation - How the attachment arrived.
 * @returns The operation whose templates apply.
 */
export function getAttachmentOperation(newAttachmentOperation: NewAttachmentOperation): AttachmentOperation {
  return NEW_ATTACHMENT_OPERATIONS[newAttachmentOperation];
}
