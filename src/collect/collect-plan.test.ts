import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import {
  beforeAll,
  describe,
  expect,
  it
} from 'vitest';

import type { CollectPlanEntry } from './collect-plan.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import {
  buildCollectPlanMessage,
  classifyCollectMove,
  CollectPlanConflictReason,
  CollectPlanEntryKind,
  CollectPlanSkipReason,
  countCollectPlanEntries,
  createSkippedCollectPlanEntry,
  findCollectPlanConflicts,
  removeRepeatedCollectPlanEntries
} from './collect-plan.ts';

function entry(overrides: Partial<CollectPlanEntry>): CollectPlanEntry {
  return {
    attachmentPath: 'img.png',
    isUnitFolder: false,
    kind: CollectPlanEntryKind.Move,
    notePath: 'note.md',
    ownerNotePath: null,
    skipReason: null,
    targetPath: 'attachments/img.png',
    ...overrides
  };
}

function render(fragment: DocumentFragment): HTMLDivElement {
  const div = createDiv();
  div.append(fragment);
  return div;
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('classifyCollectMove', () => {
  it('should call a change of folder a move', () => {
    expect(classifyCollectMove('img.png', 'attachments/img.png')).toBe(CollectPlanEntryKind.Move);
  });

  it('should call a new name in the same folder a rename', () => {
    expect(classifyCollectMove('folder/img.png', 'folder/note-1.png')).toBe(CollectPlanEntryKind.Rename);
  });
});

describe('countCollectPlanEntries', () => {
  it('should count each kind present', () => {
    const counts = countCollectPlanEntries([entry({}), entry({}), entry({ kind: CollectPlanEntryKind.Keep })]);
    expect(counts.get(CollectPlanEntryKind.Move)).toBe(2);
    expect(counts.get(CollectPlanEntryKind.Keep)).toBe(1);
    expect(counts.has(CollectPlanEntryKind.Copy)).toBe(false);
  });
});

describe('createSkippedCollectPlanEntry', () => {
  it('should build a skip entry with no destination', () => {
    expect(createSkippedCollectPlanEntry({ attachmentPath: 'a.png', notePath: 'n.md', skipReason: CollectPlanSkipReason.RawPath })).toEqual({
      attachmentPath: 'a.png',
      isUnitFolder: false,
      kind: CollectPlanEntryKind.Skip,
      notePath: 'n.md',
      ownerNotePath: null,
      skipReason: CollectPlanSkipReason.RawPath,
      targetPath: null
    });
  });
});

describe('findCollectPlanConflicts', () => {
  it('should report a destination another file holds', () => {
    const moved = entry({});
    expect(findCollectPlanConflicts([moved], (path) => path === 'attachments/img.png')).toEqual([
      { entry: moved, otherAttachmentPath: null, reason: CollectPlanConflictReason.DestinationTaken }
    ]);
  });

  it('should report a second attachment claiming the same destination, whatever its case', () => {
    const first = entry({ attachmentPath: 'a/img.png' });
    const second = entry({ attachmentPath: 'b/img.png', targetPath: 'Attachments/IMG.png' });
    expect(findCollectPlanConflicts([first, second], () => false)).toEqual([
      { entry: second, otherAttachmentPath: 'a/img.png', reason: CollectPlanConflictReason.SameDestination }
    ]);
  });

  it('should not report the same attachment planned twice for one destination', () => {
    expect(findCollectPlanConflicts([entry({}), entry({ notePath: 'other.md' })], () => false)).toEqual([]);
  });

  it('should ignore entries that write no destination', () => {
    const entries = [
      entry({ kind: CollectPlanEntryKind.Keep, targetPath: null }),
      entry({ kind: CollectPlanEntryKind.Merge }),
      entry({ kind: CollectPlanEntryKind.Shared })
    ];
    expect(findCollectPlanConflicts(entries, () => true)).toEqual([]);
  });

  it('should check copies and renames', () => {
    const entries = [entry({ kind: CollectPlanEntryKind.Copy }), entry({ attachmentPath: 'x.png', kind: CollectPlanEntryKind.Rename, targetPath: 'y.png' })];
    expect(findCollectPlanConflicts(entries, () => true).map((conflict) => conflict.reason)).toEqual([
      CollectPlanConflictReason.DestinationTaken,
      CollectPlanConflictReason.DestinationTaken
    ]);
  });
});

describe('removeRepeatedCollectPlanEntries', () => {
  it('should drop a repeated move from another note', () => {
    const first = entry({});
    expect(removeRepeatedCollectPlanEntries([first, entry({ notePath: 'other.md', ownerNotePath: 'note.md' })])).toEqual([first]);
  });

  it('should keep entries that write nothing, and shared ones', () => {
    const entries = [
      entry({ kind: CollectPlanEntryKind.Keep, targetPath: null }),
      entry({ kind: CollectPlanEntryKind.Keep, notePath: 'other.md', targetPath: null }),
      entry({ kind: CollectPlanEntryKind.Shared }),
      entry({ kind: CollectPlanEntryKind.Shared, notePath: 'other.md' })
    ];
    expect(removeRepeatedCollectPlanEntries(entries)).toEqual(entries);
  });

  it('should keep moves of one attachment to different destinations', () => {
    const entries = [entry({}), entry({ notePath: 'other.md', targetPath: 'other/img.png' })];
    expect(removeRepeatedCollectPlanEntries(entries)).toEqual(entries);
  });
});

describe('buildCollectPlanMessage', () => {
  it('should name the folders, count each kind and list what changes by note', () => {
    const div = render(buildCollectPlanMessage({
      abstractFilePaths: ['folder'],
      plan: {
        conflicts: [],
        entries: [
          entry({}),
          entry({ attachmentPath: 'r.png', kind: CollectPlanEntryKind.Rename, targetPath: 'r-1.png' }),
          entry({ kind: CollectPlanEntryKind.Copy, notePath: 'other.md' }),
          entry({ kind: CollectPlanEntryKind.Merge }),
          entry({ kind: CollectPlanEntryKind.Shared, targetPath: null }),
          entry({ attachmentPath: 'kept.png', kind: CollectPlanEntryKind.Keep, targetPath: null }),
          createSkippedCollectPlanEntry({ attachmentPath: 's1.png', notePath: 'note.md', skipReason: CollectPlanSkipReason.Excluded }),
          createSkippedCollectPlanEntry({ attachmentPath: 's2.png', notePath: 'note.md', skipReason: CollectPlanSkipReason.RawPath }),
          createSkippedCollectPlanEntry({ attachmentPath: 's3.png', notePath: 'note.md', skipReason: CollectPlanSkipReason.Shared }),
          createSkippedCollectPlanEntry({ attachmentPath: 's4.png', notePath: 'note.md', skipReason: CollectPlanSkipReason.UnitFolderShared }),
          entry({ attachmentPath: 'owned.png', ownerNotePath: 'drawing.md' })
        ]
      }
    }));

    const text = div.textContent;
    expect(div.querySelector('code')?.textContent).toBe('folder');
    expect(div.querySelector('.custom-attachment-location-collect-plan-summary')?.textContent).toBe(
      'Plan: 2 to move, 1 to rename, 1 to copy, 1 to merge, 1 to ask about, 1 already in place, 4 skipped.'
    );
    expect([...div.querySelectorAll('summary')].map((summary) => summary.textContent)).toEqual(['note.md (9)', 'other.md (1)']);
    expect(text).toContain('Move: img.png → attachments/img.png');
    expect(text).toContain('Rename: r.png → r-1.png');
    expect(text).toContain('Copy: img.png → attachments/img.png');
    expect(text).toContain('Merge into the identical file: img.png → attachments/img.png');
    expect(text).toContain('Referenced by several notes, asked when the plan applies: img.png');
    expect(text).not.toContain('kept.png');
    expect(text).toContain('Skip: s1.png (excluded from collecting)');
    expect(text).toContain('Skip: s2.png (referenced by a raw path)');
    expect(text).toContain('Skip: s3.png (referenced by several notes)');
    expect(text).toContain('Skip: s4.png (its attachment unit folder is referenced by several notes)');
    expect(text).toContain('Move: owned.png → attachments/img.png (collected into drawing.md, the note of highest priority)');
    expect(text).toContain('This is a preview.');
  });

  it('should list each conflict', () => {
    const taken = entry({});
    const second = entry({ attachmentPath: 'b.png' });
    const div = render(buildCollectPlanMessage({
      abstractFilePaths: ['/'],
      plan: {
        conflicts: [
          { entry: taken, otherAttachmentPath: null, reason: CollectPlanConflictReason.DestinationTaken },
          { entry: second, otherAttachmentPath: 'img.png', reason: CollectPlanConflictReason.SameDestination }
        ],
        entries: [taken, second]
      }
    }));

    expect(div.textContent).toContain('Conflicts: 2');
    expect([...div.querySelectorAll(':scope .custom-attachment-location-collect-plan-conflicts li')].map((li) => li.textContent)).toEqual([
      'attachments/img.png is taken by another file, so img.png will get a duplicate-name suffix.',
      'b.png and img.png are both planned for attachments/img.png, so the later one will get a duplicate-name suffix.'
    ]);
  });

  it('should say when nothing would change', () => {
    const div = render(buildCollectPlanMessage({
      abstractFilePaths: ['/'],
      plan: { conflicts: [], entries: [entry({ kind: CollectPlanEntryKind.Keep, targetPath: null })] }
    }));
    expect(div.textContent).toContain('No attachment would move, rename or copy.');
    expect(div.querySelector('details')).toBeNull();
  });

  it('should count the entries past the listing limit', () => {
    const div = render(buildCollectPlanMessage({
      abstractFilePaths: ['/'],
      maxListedEntries: 1,
      plan: { conflicts: [], entries: [entry({}), entry({ attachmentPath: 'b.png' }), entry({ attachmentPath: 'c.png' })] }
    }));
    expect(div.querySelectorAll('li[data-kind]')).toHaveLength(1);
    expect(div.textContent).toContain('And 2 more, not shown.');
  });

  it('should throw on an unknown kind, skip reason or conflict reason', () => {
    function build(planEntry: CollectPlanEntry, reason = CollectPlanConflictReason.DestinationTaken): DocumentFragment {
      return buildCollectPlanMessage({ abstractFilePaths: [], plan: { conflicts: [{ entry: planEntry, otherAttachmentPath: null, reason }], entries: [planEntry] } });
    }
    expect(() => build(entry({ kind: castTo<CollectPlanEntryKind>('Bogus') }))).toThrow('Unknown collect plan entry kind: Bogus');
    expect(() => build(entry({ kind: CollectPlanEntryKind.Skip, skipReason: castTo<CollectPlanSkipReason>('Bogus') }))).toThrow(
      'Unknown collect plan skip reason: Bogus'
    );
    expect(() => build(entry({}), castTo<CollectPlanConflictReason>('Bogus'))).toThrow('Unknown collect plan conflict reason: Bogus');
  });

  it('should render a conflict whose paths are missing as empty code spans', () => {
    const planEntry = entry({ targetPath: null });
    const div = render(buildCollectPlanMessage({
      abstractFilePaths: [],
      plan: {
        conflicts: [{ entry: planEntry, otherAttachmentPath: null, reason: CollectPlanConflictReason.SameDestination }],
        entries: []
      }
    }));
    expect(div.querySelector(':scope .custom-attachment-location-collect-plan-conflicts li')?.textContent).toBe(
      'img.png and  are both planned for , so the later one will get a duplicate-name suffix.'
    );
  });
});
