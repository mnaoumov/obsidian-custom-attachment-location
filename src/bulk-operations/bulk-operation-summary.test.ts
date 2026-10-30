import type { TAbstractFile } from 'obsidian';

import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  describe,
  expect,
  it
} from 'vitest';

import { buildBulkOperationSummary } from './bulk-operation-summary.ts';

function createAbstractFile(path: string): TAbstractFile {
  return strictProxy<TAbstractFile>({ path });
}

describe('buildBulkOperationSummary', () => {
  it('should read as the entire vault when no files are given', () => {
    expect(buildBulkOperationSummary('Collect attachments')).toBe('Collect attachments in entire vault');
  });

  it('should read as the entire vault when the vault root is among the files', () => {
    expect(buildBulkOperationSummary('Collect attachments', [createAbstractFile('a.md'), createAbstractFile('/')])).toBe('Collect attachments in entire vault');
  });

  it('should name the one file it ran on', () => {
    expect(buildBulkOperationSummary('Delete unused attachments', [createAbstractFile('Notes/a.md')])).toBe('Delete unused attachments in Notes/a.md');
  });

  it('should name the first file and count the rest', () => {
    const files = [createAbstractFile('Notes/a.md'), createAbstractFile('b.md'), createAbstractFile('c')];
    expect(buildBulkOperationSummary('Collect attachments', files)).toBe('Collect attachments in Notes/a.md and 2 more');
  });
});
