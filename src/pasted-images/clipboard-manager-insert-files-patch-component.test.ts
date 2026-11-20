import type {
  ClipboardManager,
  ImportedAttachment
} from '@obsidian-typings/obsidian-public-latest';
import type { TFile } from 'obsidian';

import {
  noop,
  noopAsync
} from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { SidecarAttachmentsComponent } from '../sidecars/sidecar-attachments-component.ts';
import type { InsertGestureTrackerComponent } from './insert-gesture-tracker-component.ts';
import type { PastedImageMarker } from './pasted-image-marker.ts';

import { ClipboardManagerInsertFilesPatchComponent } from './clipboard-manager-insert-files-patch-component.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';

interface ClipboardManagerPrototype {
  readonly insertAttachmentEmbed: InsertAttachmentEmbedFunction;
  readonly insertFiles: InsertFilesFunction;
}

interface EmbedWriter {
  readonly info: EmbedWriterInfo;
}

interface EmbedWriterEditor {
  readonly replaceSelection: (text: string) => void;
}

interface EmbedWriterInfo {
  readonly editor: EmbedWriterEditor;
}

interface GestureHolder {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  gesture: InsertGesture | null;
}

type InsertAttachmentEmbedFunction = (this: EmbedWriter, file: TFile, hasNext: boolean) => Promise<void>;
type InsertFilesFunction = (this: ClipboardManagerPrototype, importedAttachments: ImportedAttachment[]) => Promise<void>;

class FakeDoc {
  public readonly length: number;

  public constructor(private readonly text: string) {
    this.length = text.length;
  }

  public sliceString(from: number, to: number): string {
    return this.text.slice(from, to);
  }

  public toString(): string {
    return this.text;
  }
}

class FakeState {
  public get selection(): unknown {
    return this.getSelection();
  }

  public constructor(public readonly doc: FakeDoc, private readonly getSelection: () => unknown) {}
}

const NOTE_TEXT = '---\ntags: a\n---\nBody line\n';
const BODY_START = NOTE_TEXT.indexOf('Body');

describe('ClipboardManagerInsertFilesPatchComponent', () => {
  let gestureHolder: GestureHolder;
  let insertFilesMock: ReturnType<typeof vi.fn<InsertFilesFunction>>;
  let clipboardManager: ClipboardManager;
  let recordMock: ReturnType<typeof vi.fn<PastedImageMarker['record']>>;
  let editorDispatchMock: ReturnType<typeof vi.fn>;
  let replaceSelectionMock: ReturnType<typeof vi.fn<(text: string) => void>>;
  let editorSelection: unknown;

  function createSelection(position: number): unknown {
    return { ranges: [{ from: position, to: position }] };
  }

  it('puts a drop that Obsidian moved above the frontmatter back where the cursor was, before anything is inserted', async () => {
    const component = createComponent();
    component.load();
    gestureHolder.gesture = InsertGesture.Drop;
    const selectionBeforeDrop = createSelection(BODY_START + 2);
    editorSelection = selectionBeforeDrop;
    insertFilesMock.mockImplementation(() => {
      expect(editorDispatchMock).toHaveBeenCalledWith({ selection: selectionBeforeDrop });
      return noopAsync();
    });

    const promise = strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([createAttachment('a.png')]);
    // What Obsidian's drop handler does right after insertFiles returns, for a drop on the Properties block.
    editorSelection = createSelection(0);
    gestureHolder.gesture = null;
    await promise;

    expect(insertFilesMock).toHaveBeenCalledTimes(1);
  });

  it('does not touch the selection for a paste', async () => {
    const component = createComponent();
    component.load();
    gestureHolder.gesture = InsertGesture.Paste;
    editorSelection = createSelection(0);

    await strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([createAttachment('a.png')]);

    expect(editorDispatchMock).not.toHaveBeenCalled();
  });

  it('keeps sidecar batch handling around the full editor import after gesture recording', async () => {
    const trace: string[] = [];
    const attachments = [createAttachment('doc.html'), createAttachment('doc.html.p7s')];
    recordMock.mockImplementation(() => {
      trace.push('gesture');
      return noopAsync();
    });
    async function runImportBatch<T>(items: readonly ImportedAttachment[], run: () => Promise<T>): Promise<T> {
      expect(items).toBe(attachments);
      trace.push('batch-start');
      const result = await run();
      trace.push('batch-end');
      return result;
    }
    insertFilesMock.mockImplementation(() => {
      trace.push('save');
      return noopAsync();
    });
    const component = new ClipboardManagerInsertFilesPatchComponent({
      clipboardManager,
      insertGestureTrackerComponent: strictProxy<InsertGestureTrackerComponent>({ dropClientY: null, gesture: InsertGesture.Drop }),
      pastedImageMarker: strictProxy<PastedImageMarker>({ record: recordMock }),
      sidecarAttachmentsComponent: strictProxy<SidecarAttachmentsComponent>({ runImportBatch })
    });
    component.load();
    await clipboardManager.insertFiles(attachments);
    expect(trace).toEqual(['gesture', 'batch-start', 'save', 'batch-end']);
  });

  beforeEach(() => {
    gestureHolder = { gesture: null };
    insertFilesMock = vi.fn<InsertFilesFunction>().mockResolvedValue(undefined);
    const clipboardManagerPrototype: ClipboardManagerPrototype = {
      // Core's own body (Obsidian 1.15.1): build the embed, append a separator when more follow, write it.
      insertAttachmentEmbed(file: TFile, hasNext: boolean): Promise<void> {
        this.info.editor.replaceSelection(`![[${file.path}]]${hasNext ? '\n\n' : ''}`);
        return noopAsync();
      },
      insertFiles: insertFilesMock
    };
    const clipboardManagerObject = castTo<Record<string, unknown>>(Object.create(clipboardManagerPrototype));
    editorDispatchMock = vi.fn();
    replaceSelectionMock = vi.fn<(text: string) => void>();
    editorSelection = createSelection(BODY_START);
    clipboardManagerObject['info'] = {
      editor: {
        activeCM: {
          dispatch: editorDispatchMock,
          documentTop: 0,
          // Class instances, not plain objects: the strict proxy would answer `toString` itself and cache the
          // selection it read first.
          state: new FakeState(new FakeDoc(NOTE_TEXT), () => editorSelection)
        },
        replaceSelection: replaceSelectionMock
      }
    };
    clipboardManager = strictProxy<ClipboardManager>(clipboardManagerObject);
    recordMock = vi.fn<PastedImageMarker['record']>().mockResolvedValue(undefined);
  });

  function createComponent(): ClipboardManagerInsertFilesPatchComponent {
    return new ClipboardManagerInsertFilesPatchComponent({
      clipboardManager,
      insertGestureTrackerComponent: strictProxy<InsertGestureTrackerComponent>({
        dropClientY: null,
        get gesture(): InsertGesture | null {
          return gestureHolder.gesture;
        }
      }),
      pastedImageMarker: strictProxy<PastedImageMarker>({ record: recordMock })
    });
  }

  function createFile(path: string): TFile {
    return strictProxy<TFile>({ path });
  }

  function createAttachment(filepath: string): ImportedAttachment {
    return {
      data: Promise.resolve(new ArrayBuffer(4)),
      extension: 'png',
      filepath,
      name: 'attachment'
    };
  }

  it('should patch insertFiles and insertAttachmentEmbed on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy.mock.calls.map(([params]) => params.methodName)).toEqual(['insertFiles', 'insertAttachmentEmbed']);
  });

  it('writes a whole batch into the editor once, after every file is saved', async () => {
    const component = createComponent();
    component.load();
    const writesDuringSave: number[] = [];
    insertFilesMock.mockImplementation(async function insertFiles(this: ClipboardManagerPrototype) {
      await this.insertAttachmentEmbed.call(castTo<EmbedWriter>(this), createFile('a.png'), true);
      writesDuringSave.push(replaceSelectionMock.mock.calls.length);
      await this.insertAttachmentEmbed.call(castTo<EmbedWriter>(this), createFile('b.png'), false);
      writesDuringSave.push(replaceSelectionMock.mock.calls.length);
    });

    await strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([createAttachment('a.png'), createAttachment('b.png')]);

    expect(writesDuringSave).toEqual([0, 0]);
    expect(replaceSelectionMock.mock.calls).toEqual([['![[a.png]]\n\n![[b.png]]']]);
  });

  it('writes the embeds saved before a failure, and lets the failure through', async () => {
    const component = createComponent();
    component.load();
    insertFilesMock.mockImplementation(async function insertFiles(this: ClipboardManagerPrototype) {
      await this.insertAttachmentEmbed.call(castTo<EmbedWriter>(this), createFile('a.png'), true);
      throw new Error('disk full');
    });

    await expect(strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([createAttachment('a.png')])).rejects.toThrow('disk full');

    expect(replaceSelectionMock.mock.calls).toEqual([['![[a.png]]\n\n']]);
  });

  it('joins a batch started while another is saving, and writes both when the last one ends', async () => {
    const component = createComponent();
    component.load();
    let releaseFirst = noop;
    const firstSaved = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    insertFilesMock.mockImplementationOnce(async function insertFiles(this: ClipboardManagerPrototype) {
      await this.insertAttachmentEmbed.call(castTo<EmbedWriter>(this), createFile('a.png'), false);
      await firstSaved;
    });
    insertFilesMock.mockImplementationOnce(async function insertFiles(this: ClipboardManagerPrototype) {
      await this.insertAttachmentEmbed.call(castTo<EmbedWriter>(this), createFile('b.png'), false);
    });

    const proxy = strictProxy<ClipboardManagerPrototype>(clipboardManager);
    const first = proxy.insertFiles([createAttachment('a.png')]);
    await proxy.insertFiles([createAttachment('b.png')]);
    expect(replaceSelectionMock).not.toHaveBeenCalled();
    releaseFirst();
    await first;

    expect(replaceSelectionMock.mock.calls).toEqual([['![[a.png]]![[b.png]]']]);
  });

  it('leaves an editor whose replaceSelection lives on its prototype as it found it', async () => {
    const component = createComponent();
    component.load();
    const editorPrototype: EmbedWriterEditor = { replaceSelection: replaceSelectionMock };
    const editor = castTo<EmbedWriterEditor>(Object.create(editorPrototype));
    const writer = strictProxy<ClipboardManagerPrototype>(clipboardManager);
    castTo<Record<string, unknown>>(castTo<Record<string, unknown>>(clipboardManager)['info'])['editor'] = editor;
    insertFilesMock.mockImplementation(async function insertFiles(this: ClipboardManagerPrototype) {
      await this.insertAttachmentEmbed.call(castTo<EmbedWriter>(this), createFile('a.png'), false);
    });

    await writer.insertFiles([createAttachment('a.png')]);

    expect(Object.hasOwn(editor, 'replaceSelection')).toBe(false);
    expect(replaceSelectionMock.mock.calls).toEqual([['![[a.png]]']]);
  });

  it('writes an embed straight away outside a batch', async () => {
    const component = createComponent();
    component.load();

    await strictProxy<ClipboardManagerPrototype>(clipboardManager).insertAttachmentEmbed.call(castTo<EmbedWriter>(clipboardManager), createFile('a.png'), false);

    expect(replaceSelectionMock.mock.calls).toEqual([['![[a.png]]']]);
  });

  it('should record the attachments with the gesture in progress, then delegate to the original method', async () => {
    const component = createComponent();
    component.load();
    gestureHolder.gesture = InsertGesture.Drop;

    const attachments = [createAttachment('folder/a.png'), createAttachment('folder/b.png')];
    const promise = strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles(attachments);
    // The gesture is read synchronously, before the tracker forgets it.
    gestureHolder.gesture = null;
    await promise;

    expect(recordMock).toHaveBeenCalledWith(attachments, InsertGesture.Drop);
    expect(insertFilesMock).toHaveBeenCalledWith(attachments);
  });

  it('should record with no gesture when insertFiles is called outside a paste or drop', async () => {
    const component = createComponent();
    component.load();

    await strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([]);

    expect(recordMock).toHaveBeenCalledWith([], null);
    expect(insertFilesMock).toHaveBeenCalledTimes(1);
  });
});
