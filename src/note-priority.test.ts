import {
  describe,
  expect,
  it
} from 'vitest';

import {
  findNoPriorityWinnerReason,
  findNotePriorityRank,
  NO_PRIORITY_MATCH,
  NoPriorityWinnerReason,
  pickHighestPriorityNotePath
} from './note-priority.ts';

interface NonWinningCase {
  notePaths: string[];
  ranks: Record<string, number>;
}

function rankOf(notePath: string, entries: string[], frontmatter: null | Record<string, unknown> = null): number {
  return findNotePriorityRank({ entries, frontmatter, notePath });
}

describe('findNotePriorityRank', () => {
  it('should rank by position in the list', () => {
    const entries = ['.md', '.excalidraw.md'];
    expect(rankOf('note.md', entries)).toBe(0);
  });

  it('should let the longest matching entry decide, so a nested extension can rank below a plain one', () => {
    // The example the request is built on. `drawing.excalidraw.md` also ends with `.md`, so without
    // Most-specific-wins the two notes would tie and the priority would never resolve.
    const entries = ['.md', '.excalidraw.md'];
    expect(rankOf('note.md', entries)).toBe(0);
    expect(rankOf('drawing.excalidraw.md', entries)).toBe(1);
  });

  it('should still honor the order when the specific entry is listed first', () => {
    const entries = ['.excalidraw.md', '.md'];
    expect(rankOf('drawing.excalidraw.md', entries)).toBe(0);
    expect(rankOf('note.md', entries)).toBe(1);
  });

  it('should not let a dot inside a file name defeat an extension entry', () => {
    expect(rankOf('my.note.md', ['.md'])).toBe(0);
  });

  it('should fall to the earlier entry when two matching entries are the same length', () => {
    expect(rankOf('note.md', ['/note/', String.raw`/\.md/`])).toBe(0);
  });

  it('should match an extension case-insensitively', () => {
    expect(rankOf('Note.MD', ['.md'])).toBe(0);
  });

  it('should not match an extension appearing mid-name', () => {
    expect(rankOf('note.md.backup', ['.md'])).toBe(NO_PRIORITY_MATCH);
  });

  it('should match a path from the vault root', () => {
    expect(rankOf('journal/2026/note.md', ['journal'])).toBe(0);
    expect(rankOf('journal/2026/note.md', ['journal/2026'])).toBe(0);
    expect(rankOf('other/note.md', ['journal'])).toBe(NO_PRIORITY_MATCH);
  });

  it('should not treat a sibling with the same prefix as a match', () => {
    expect(rankOf('journalism/note.md', ['journal'])).toBe(NO_PRIORITY_MATCH);
  });

  it('should accept a path entry written with a trailing slash', () => {
    expect(rankOf('journal/note.md', ['journal/'])).toBe(0);
    expect(rankOf('journalism/note.md', ['journal/'])).toBe(NO_PRIORITY_MATCH);
  });

  it('should match the note itself named as a path', () => {
    expect(rankOf('journal/note.md', ['journal/note.md'])).toBe(0);
  });

  it('should match a regular expression against the path', () => {
    expect(rankOf('journal/2026/note.md', [String.raw`/\d{4}/`])).toBe(0);
    expect(rankOf('journal/note.md', [String.raw`/\d{4}/`])).toBe(NO_PRIORITY_MATCH);
  });

  it('should treat an unparseable regular expression as matching nothing rather than throwing', () => {
    // A bad entry must not abort a collection midway through.
    expect(() => rankOf('note.md', ['/[/'])).not.toThrow();
    expect(rankOf('note.md', ['/[/'])).toBe(NO_PRIORITY_MATCH);
  });

  it('should match the presence of a frontmatter property', () => {
    // The form asked for in the issue comment: identify a note by property, not only by extension.
    expect(rankOf('drawing.md', ['property:excalidraw-plugin'], { 'excalidraw-plugin': 'parsed' })).toBe(0);
    expect(rankOf('note.md', ['property:excalidraw-plugin'], { title: 'x' })).toBe(NO_PRIORITY_MATCH);
  });

  it('should match a frontmatter property value when one is given', () => {
    expect(rankOf('drawing.md', ['property:type=drawing'], { type: 'drawing' })).toBe(0);
    expect(rankOf('drawing.md', ['property:type=drawing'], { type: 'note' })).toBe(NO_PRIORITY_MATCH);
  });

  it('should not match a property value when the property is absent entirely', () => {
    expect(rankOf('drawing.md', ['property:type=drawing'], { title: 'x' })).toBe(NO_PRIORITY_MATCH);
  });

  it('should match a non-string frontmatter value by its rendering', () => {
    expect(rankOf('note.md', ['property:pinned=true'], { pinned: true })).toBe(0);
    expect(rankOf('note.md', ['property:order=2'], { order: 2 })).toBe(0);
  });

  it('should match any entry of an array-valued property', () => {
    expect(rankOf('note.md', ['property:tags=drawing'], { tags: ['note', 'drawing'] })).toBe(0);
    expect(rankOf('note.md', ['property:tags=missing'], { tags: ['note', 'drawing'] })).toBe(NO_PRIORITY_MATCH);
  });

  it('should not match a property when the note has no frontmatter', () => {
    expect(rankOf('note.md', ['property:type'], null)).toBe(NO_PRIORITY_MATCH);
  });

  it('should ignore an empty entry', () => {
    expect(rankOf('note.md', ['', '.md'])).toBe(1);
  });

  it('should return no match for an empty list', () => {
    expect(rankOf('note.md', [])).toBe(NO_PRIORITY_MATCH);
  });
});

describe('pickHighestPriorityNotePath', () => {
  function pick(notePaths: string[], ranks: Record<string, number>): null | string {
    return pickHighestPriorityNotePath({
      notePaths,
      rank: (notePath) => ranks[notePath] ?? NO_PRIORITY_MATCH
    });
  }

  it('should pick the note with the lowest rank', () => {
    expect(pick(['a.md', 'b.excalidraw.md'], { 'a.md': 0, 'b.excalidraw.md': 1 })).toBe('a.md');
  });

  it('should pick a matching note over one that matches nothing', () => {
    expect(pick(['a.md', 'b.canvas'], { 'a.md': 1 })).toBe('a.md');
  });

  it('should return null when the best rank is shared', () => {
    // Two notes of equal priority is exactly what the multiple-notes mode setting is for, so this
    // Must not silently pick one.
    expect(pick(['a.md', 'b.md'], { 'a.md': 0, 'b.md': 0 })).toBeNull();
  });

  it('should return null when no note matches anything', () => {
    expect(pick(['a.canvas', 'b.canvas'], {})).toBeNull();
  });

  it('should return null for a single note that matches nothing', () => {
    expect(pick(['a.canvas'], {})).toBeNull();
  });

  it('should return the single note when it matches', () => {
    expect(pick(['a.md'], { 'a.md': 0 })).toBe('a.md');
  });

  it('should return null for an empty list', () => {
    expect(pick([], {})).toBeNull();
  });

  it('should keep the first note when a later one ties with it', () => {
    expect(pick(['a.md', 'b.md', 'c.excalidraw.md'], { 'a.md': 0, 'b.md': 0, 'c.excalidraw.md': 1 })).toBeNull();
  });
});

describe('findNoPriorityWinnerReason', () => {
  function reason(entries: string[], notePaths: string[], ranks: Record<string, number>): NoPriorityWinnerReason {
    return findNoPriorityWinnerReason({
      entries,
      notePaths,
      rank: (notePath) => ranks[notePath] ?? NO_PRIORITY_MATCH
    });
  }

  it('should report an empty list before ranking anything', () => {
    expect(reason([], ['a.md', 'b.md'], {})).toBe(NoPriorityWinnerReason.EmptyList);
  });

  it('should report no match when every note matches nothing', () => {
    expect(reason(['.md'], ['a.canvas', 'b.canvas'], {})).toBe(NoPriorityWinnerReason.NoMatch);
  });

  it('should report a tie when the best rank is shared', () => {
    expect(reason(['.md'], ['a.md', 'b.md'], { 'a.md': 0, 'b.md': 0 })).toBe(NoPriorityWinnerReason.Tie);
  });

  it('should report a tie even when only some notes match', () => {
    // A tie among the matching notes is still a tie: the unmatched one never competes.
    expect(reason(['.md'], ['a.md', 'b.md', 'c.canvas'], { 'a.md': 0, 'b.md': 0 })).toBe(NoPriorityWinnerReason.Tie);
  });

  it('should agree with pickHighestPriorityNotePath on every non-winning case', () => {
    const cases: NonWinningCase[] = [
      { notePaths: ['a.canvas', 'b.canvas'], ranks: {} },
      { notePaths: ['a.md', 'b.md'], ranks: { 'a.md': 0, 'b.md': 0 } }
    ];

    for (const testCase of cases) {
      function rank(notePath: string): number {
        return testCase.ranks[notePath] ?? NO_PRIORITY_MATCH;
      }

      expect(pickHighestPriorityNotePath({ notePaths: testCase.notePaths, rank })).toBeNull();
      expect(findNoPriorityWinnerReason({ entries: ['.md'], notePaths: testCase.notePaths, rank })).not.toBe(NoPriorityWinnerReason.EmptyList);
    }
  });
});
