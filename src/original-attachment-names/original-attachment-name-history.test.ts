import {
  describe,
  expect,
  it
} from 'vitest';

import { OriginalAttachmentNameHistory } from './original-attachment-name-history.ts';

describe('OriginalAttachmentNameHistory', () => {
  it('ignores unrecognized or damaged shared records while retaining valid metadata', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['null', null],
      ['primitive', 4],
      ['empty', {}],
      ['time', { kind: 'remove', path: 'a.pdf', time: NaN }],
      ['folder', { isFolder: 'yes', kind: 'remove', path: 'a.pdf', time: 2 }],
      ['observed', { kind: 'remove', observed: [4], path: 'a.pdf', time: 2 }],
      ['kind', { kind: 'unsupported', path: 'a.pdf', time: 2 }],
      ['valid', { fileName: 'first.pdf', kind: 'arrival', path: 'a.pdf', time: 1 }]
    ]);
    expect([...history.names]).toStrictEqual([['a.pdf', 'first.pdf']]);
  });

  it('preserves the destination metadata when concurrent histories move another file onto it', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['source', { fileName: 'source.pdf', kind: 'arrival', path: 'a.pdf', time: 1 }],
      ['target', { fileName: 'target.pdf', kind: 'arrival', path: 'b.pdf', time: 2 }],
      ['rename', { kind: 'rename', path: 'a.pdf', target: 'b.pdf', time: 3 }]
    ]);
    expect([...history.names]).toStrictEqual([['b.pdf', 'target.pdf']]);
  });
  it('does not apply a delayed duplicate rename to a reused path', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['old', { fileName: 'old.pdf', kind: 'arrival', path: 'a.pdf', time: 1 }],
      ['rename', { kind: 'rename', observed: ['old'], path: 'a.pdf', target: 'b.pdf', time: 2 }],
      ['new', { fileName: 'new.pdf', kind: 'arrival', path: 'a.pdf', time: 3 }],
      ['duplicate', { kind: 'rename', observed: ['old'], path: 'a.pdf', target: 'b.pdf', time: 4 }]
    ]);
    expect([...history.names]).toStrictEqual([['b.pdf', 'old.pdf'], ['a.pdf', 'new.pdf']]);
  });

  it('moves the earliest concurrent arrival even when a rename observed the later arrival', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['first', { fileName: 'first.pdf', kind: 'arrival', path: 'a.pdf', time: 1 }],
      ['later', { fileName: 'later.pdf', kind: 'arrival', path: 'a.pdf', time: 2 }],
      ['rename', { kind: 'rename', observed: ['later'], path: 'a.pdf', target: 'b.pdf', time: 3 }]
    ]);
    expect([...history.names]).toStrictEqual([['b.pdf', 'first.pdf']]);
  });

  it('keeps explicit edits and optional source paths through rename and late migration', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['arrival', { fileName: 'first.pdf', kind: 'arrival', path: 'a.pdf', time: 1 }],
      ['source', { kind: 'source', originalPath: '/Downloads/first.pdf', path: 'a.pdf', time: 2 }],
      ['edit', { fileName: 'corrected.pdf', kind: 'edit', path: 'a.pdf', time: 3 }],
      ['rename', { kind: 'rename', path: 'a.pdf', target: 'b.pdf', time: 4 }],
      ['legacy', { fileName: 'legacy.pdf', kind: 'arrival', path: 'a.pdf', time: 0 }]
    ]);
    expect([...history.names]).toStrictEqual([['b.pdf', 'corrected.pdf']]);
    expect([...history.originalPaths]).toStrictEqual([['b.pdf', '/Downloads/first.pdf']]);
  });
  it('keeps the earliest arrival when devices deliver records in reverse order', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['later', { fileName: 'later.pdf', kind: 'arrival', path: 'a.pdf', time: 20 }],
      ['earlier', { fileName: 'first.pdf', kind: 'arrival', path: 'a.pdf', time: 10 }]
    ]);
    expect(history.names.get('a.pdf')).toBe('first.pdf');
  });

  it('replays a rename delivered before its arrival and accepts a new file at the old path', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([['rename', { kind: 'rename', path: 'a.pdf', target: 'b.pdf', time: 20 }]]);
    history.merge([
      ['arrival', { fileName: 'first.pdf', kind: 'arrival', path: 'a.pdf', time: 10 }],
      ['reuse', { fileName: 'second.pdf', kind: 'arrival', path: 'a.pdf', time: 30 }]
    ]);
    expect([...history.names]).toStrictEqual([['b.pdf', 'first.pdf'], ['a.pdf', 'second.pdf']]);
  });

  it('keeps removals when a legacy migration arrives late and permits later reuse', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['remove', { kind: 'remove', path: 'a.pdf', time: 20 }],
      ['legacy', { fileName: 'old.pdf', kind: 'arrival', path: 'a.pdf', time: 0 }]
    ]);
    expect(history.names.has('a.pdf')).toBe(false);
    history.merge([['reuse', { fileName: 'new.pdf', kind: 'arrival', path: 'a.pdf', time: 30 }]]);
    expect(history.names.get('a.pdf')).toBe('new.pdf');
  });

  it('moves folder descendants without touching a similarly named sibling', () => {
    const history = new OriginalAttachmentNameHistory();
    history.merge([
      ['a', { fileName: 'first.pdf', kind: 'arrival', path: 'old/a.pdf', time: 1 }],
      ['b', { fileName: 'second.pdf', kind: 'arrival', path: 'older/a.pdf', time: 2 }],
      ['move', { isFolder: true, kind: 'rename', path: 'old', target: 'new', time: 3 }],
      ['delete', { isFolder: true, kind: 'remove', path: 'new', time: 4 }]
    ]);
    expect([...history.names]).toStrictEqual([['older/a.pdf', 'second.pdf']]);
  });

  it('ignores malformed operations and resolves equal-time arrivals deterministically', () => {
    const first = new OriginalAttachmentNameHistory();
    const second = new OriginalAttachmentNameHistory();
    const entries: [string, unknown][] = [
      ['b', { fileName: 'b.pdf', kind: 'arrival', path: 'a.pdf', time: 1 }],
      ['a', { fileName: 'a.pdf', kind: 'arrival', path: 'a.pdf', time: 1 }],
      ['bad', { kind: 'rename', path: 'a.pdf', time: 2 }]
    ];
    first.merge(entries);
    second.merge([...entries].reverse());
    expect([...first.names]).toStrictEqual([['a.pdf', 'a.pdf']]);
    expect([...second.names]).toStrictEqual([...first.names]);
  });
});
