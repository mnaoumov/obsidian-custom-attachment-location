import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import {
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type {
  DropEditorSelection,
  DropEditorView
} from './drop-insert-position.ts';

import { keepDropInsertPositionInBody } from './drop-insert-position.ts';

interface FakeRange {
  readonly from: number;
  readonly to: number;
}

interface FakeView {
  readonly dispatch: ReturnType<typeof vi.fn>;
  readonly view: DropEditorView;
}

const NOTE_WITH_FRONTMATTER = '---\ntags: a\n---\nBody line\n';
const BODY_START = NOTE_WITH_FRONTMATTER.indexOf('Body');
const DOCUMENT_TOP = 100;
const ON_THE_TEXT = DOCUMENT_TOP + 10;
const ABOVE_THE_TEXT = DOCUMENT_TOP - 10;

function createSelection(...ranges: FakeRange[]): DropEditorSelection {
  return castTo<DropEditorSelection>({ ranges });
}

function createView(text: string, selection: DropEditorSelection): FakeView {
  const dispatch = vi.fn();
  const view = castTo<DropEditorView>({
    dispatch,
    documentTop: DOCUMENT_TOP,
    state: {
      doc: {
        length: text.length,
        sliceString: (from: number, to: number): string => text.slice(from, to),
        toString: (): string => text
      },
      selection
    }
  });
  return { dispatch, view };
}

describe('keepDropInsertPositionInBody', () => {
  it('leaves a drop point in the body alone', () => {
    const { dispatch, view } = createView(NOTE_WITH_FRONTMATTER, createSelection({ from: BODY_START + 4, to: BODY_START + 4 }));
    keepDropInsertPositionInBody({ dropClientY: ON_THE_TEXT, selectionBeforeDrop: createSelection({ from: BODY_START, to: BODY_START }), view });
    expect(dispatch).not.toHaveBeenCalled();
  });

  it('restores the selection the user had when the drop point is above the frontmatter', () => {
    const before = createSelection({ from: BODY_START + 2, to: BODY_START + 2 });
    const { dispatch, view } = createView(NOTE_WITH_FRONTMATTER, createSelection({ from: 0, to: 0 }));
    keepDropInsertPositionInBody({ dropClientY: ON_THE_TEXT, selectionBeforeDrop: before, view });
    expect(dispatch).toHaveBeenCalledWith({ selection: before });
  });

  it('treats a missing drop point (CodeMirror answered null) like one outside the body', () => {
    const before = createSelection({ from: BODY_START, to: BODY_START + 4 });
    const { dispatch, view } = createView(
      NOTE_WITH_FRONTMATTER,
      createSelection({ from: castTo<number>(null), to: castTo<number>(null) })
    );
    keepDropInsertPositionInBody({ dropClientY: ON_THE_TEXT, selectionBeforeDrop: before, view });
    expect(dispatch).toHaveBeenCalledWith({ selection: before });
  });

  it('moves to the start of the body when the earlier selection was in the frontmatter too', () => {
    const { dispatch, view } = createView(NOTE_WITH_FRONTMATTER, createSelection({ from: 0, to: 0 }));
    keepDropInsertPositionInBody({ dropClientY: ON_THE_TEXT, selectionBeforeDrop: createSelection({ from: 5, to: 5 }), view });
    expect(dispatch).toHaveBeenCalledWith({ selection: { anchor: BODY_START } });
  });

  it('opens a body line when the file ends on the closing frontmatter delimiter', () => {
    const text = '---\ntags: a\n---';
    const { dispatch, view } = createView(text, createSelection({ from: 0, to: 0 }));
    keepDropInsertPositionInBody({ dropClientY: ON_THE_TEXT, selectionBeforeDrop: createSelection({ from: 0, to: 0 }), view });
    expect(dispatch).toHaveBeenCalledWith({
      changes: { from: text.length, insert: '\n' },
      selection: { anchor: text.length + 1 }
    });
  });

  it('restores the selection the user had for a drop above the text that Obsidian mapped into the body', () => {
    const before = createSelection({ from: BODY_START + 4, to: BODY_START + 4 });
    const { dispatch, view } = createView(NOTE_WITH_FRONTMATTER, createSelection({ from: BODY_START, to: BODY_START }));
    keepDropInsertPositionInBody({ dropClientY: ABOVE_THE_TEXT, selectionBeforeDrop: before, view });
    expect(dispatch).toHaveBeenCalledWith({ selection: before });
  });

  it('trusts the drop point when the drop position is not known', () => {
    const { dispatch, view } = createView(NOTE_WITH_FRONTMATTER, createSelection({ from: BODY_START, to: BODY_START }));
    keepDropInsertPositionInBody({ dropClientY: null, selectionBeforeDrop: createSelection({ from: BODY_START + 4, to: BODY_START + 4 }), view });
    expect(dispatch).not.toHaveBeenCalled();
  });

  it('leaves the start of a note without frontmatter alone', () => {
    const { dispatch, view } = createView('Body line\n', createSelection({ from: 0, to: 0 }));
    keepDropInsertPositionInBody({ dropClientY: ON_THE_TEXT, selectionBeforeDrop: createSelection({ from: 3, to: 3 }), view });
    expect(dispatch).not.toHaveBeenCalled();
  });
});
