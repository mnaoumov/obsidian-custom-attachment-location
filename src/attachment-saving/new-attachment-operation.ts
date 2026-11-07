/**
 * How a new attachment arrived, which is what picks its operation's folder and file name templates.
 *
 * Recorded per attachment `ArrayBuffer` by `PastedImageMarker` while the paste or drop is being dispatched, and read
 * back by `AttachmentSaver`, the one place every such attachment passes through.
 */
export enum NewAttachmentOperation {
  /**
   * A file dropped into a note, a canvas, the file explorer or a base.
   */
  DroppedFile = 'DroppedFile',

  /**
   * Saved with no paste or drop being dispatched: another plugin, or a core feature such as the audio recorder.
   */
  Other = 'Other',

  /**
   * A pasted file that is not a screenshot: a file copied in a file manager.
   */
  PastedFile = 'PastedFile',

  /**
   * A pasted screenshot: image data on the clipboard, or an image file `pasted-image-classifier.ts` counts as pasted.
   */
  PastedImage = 'PastedImage'
}
