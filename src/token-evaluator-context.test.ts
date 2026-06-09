import { AttachmentPathContext } from 'obsidian-dev-utils/obsidian/attachment-path';
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  ActionContext,
  actionContextToAttachmentPathContext,
  attachmentPathContextToActionContext
} from './token-evaluator-context.ts';

describe('actionContextToAttachmentPathContext', () => {
  it('should map DeleteNote', () => {
    expect(actionContextToAttachmentPathContext(ActionContext.DeleteNote)).toBe(AttachmentPathContext.DeleteNote);
  });

  it('should map RenameNote', () => {
    expect(actionContextToAttachmentPathContext(ActionContext.RenameNote)).toBe(AttachmentPathContext.RenameNote);
  });

  it('should map every other context to Unknown', () => {
    expect(actionContextToAttachmentPathContext(ActionContext.SaveAttachment)).toBe(AttachmentPathContext.Unknown);
    expect(actionContextToAttachmentPathContext(ActionContext.Unknown)).toBe(AttachmentPathContext.Unknown);
  });
});

describe('attachmentPathContextToActionContext', () => {
  it('should map DeleteNote', () => {
    expect(attachmentPathContextToActionContext(AttachmentPathContext.DeleteNote)).toBe(ActionContext.DeleteNote);
  });

  it('should map RenameNote', () => {
    expect(attachmentPathContextToActionContext(AttachmentPathContext.RenameNote)).toBe(ActionContext.RenameNote);
  });

  it('should map every other context to Unknown', () => {
    expect(attachmentPathContextToActionContext(AttachmentPathContext.Unknown)).toBe(ActionContext.Unknown);
  });
});
