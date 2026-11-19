import type { Editor } from 'obsidian';

import { getFrontMatterInfo } from 'obsidian';

/**
 * The editor's selection, as CodeMirror holds it.
 */
export type DropEditorSelection = DropEditorView['state']['selection'];

/**
 * The CodeMirror view a drop lands in.
 */
export type DropEditorView = NonNullable<Editor['activeCM']>;

/**
 * What {@link keepDropInsertPositionInBody} needs to know about a drop.
 */
export interface KeepDropInsertPositionInBodyParams {
  /**
   * The drop's `clientY`, or `null` when it is not known.
   */
  readonly dropClientY: null | number;

  /**
   * The selection the editor had before Obsidian handled the drop.
   */
  readonly selectionBeforeDrop: DropEditorSelection;

  /**
   * The editor view the files were dropped into.
   */
  readonly view: DropEditorView;
}

/**
 * Puts the selection back where the user had it, in the note's body, after Obsidian moved it for a drop.
 *
 * Obsidian's editor drop handler moves the selection to `posAtCoords` of the drop point, and the links its
 * `insertFiles` writes go wherever the selection is when each file has been saved. A drop on the inline title or the
 * Properties block is above the text and names no position in it, yet `posAtCoords` still answers one: `0` in Source
 * mode, where the frontmatter is text, so the links went in before the opening `---`, and the start of the body in Live
 * Preview, wherever the cursor was. Off the rendered viewport it answers `null`, which CodeMirror also treats as `0`.
 *
 * A drop on the text, at a position in the body, is left alone. A drop above the text, or one that landed in the
 * frontmatter, goes back to the selection the user had before the drop, when that was in the body, and else to the
 * first position of the body.
 *
 * @param params - The drop.
 */
export function keepDropInsertPositionInBody(params: KeepDropInsertPositionInBodyParams): void {
  const { dropClientY, selectionBeforeDrop, view } = params;
  const doc = view.state.doc;
  const frontMatterInfo = getFrontMatterInfo(doc.toString());
  const bodyStart = frontMatterInfo.exists ? frontMatterInfo.contentStart : 0;

  const isDropAboveText = typeof dropClientY === 'number' && Number.isFinite(dropClientY) && dropClientY < view.documentTop;
  if (!isDropAboveText && isInBody(view.state.selection, bodyStart, doc.length)) {
    return;
  }

  if (isInBody(selectionBeforeDrop, bodyStart, doc.length)) {
    view.dispatch({ selection: selectionBeforeDrop });
    return;
  }

  // A file that ends on the closing `---` has no body line yet; a link written straight after it would break the
  // frontmatter, so open the line first.
  if (bodyStart > 0 && doc.sliceString(bodyStart - 1, bodyStart) !== '\n') {
    view.dispatch({
      changes: { from: bodyStart, insert: '\n' },
      selection: { anchor: bodyStart + 1 }
    });
    return;
  }

  view.dispatch({ selection: { anchor: bodyStart } });
}

function isInBody(selection: DropEditorSelection, bodyStart: number, docLength: number): boolean {
  return selection.ranges.every((range) => isPositionInBody(range.from, bodyStart, docLength) && isPositionInBody(range.to, bodyStart, docLength));
}

function isPositionInBody(position: number, bodyStart: number, docLength: number): boolean {
  return Number.isSafeInteger(position) && position >= bodyStart && position <= docLength;
}
