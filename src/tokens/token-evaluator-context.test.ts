import { AttachmentPathContext } from '@mnaoumov/obsidian-lib/attachment-path';
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  ActionContext,
  actionContextToAttachmentPathContext,
  attachmentPathContextToActionContext,
  isCollectActionContext,
  isNonInteractiveActionContext
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

describe('isCollectActionContext', () => {
  it('should hold for a collect and its plan only', () => {
    expect(isCollectActionContext(ActionContext.CollectAttachments)).toBe(true);
    expect(isCollectActionContext(ActionContext.PlanCollectAttachments)).toBe(true);
    expect(isCollectActionContext(ActionContext.MoveAttachmentToProperFolder)).toBe(false);
  });
});

describe('isNonInteractiveActionContext', () => {
  it('should hold for the collect plan, an API read and token validation', () => {
    expect(isNonInteractiveActionContext(ActionContext.PlanCollectAttachments)).toBe(true);
    expect(isNonInteractiveActionContext(ActionContext.ReadApi)).toBe(true);
    expect(isNonInteractiveActionContext(ActionContext.ValidateTokens)).toBe(true);
    expect(isNonInteractiveActionContext(ActionContext.CollectAttachments)).toBe(false);
  });
});
