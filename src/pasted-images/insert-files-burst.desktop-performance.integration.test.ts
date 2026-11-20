import {
  evalInObsidian,
  pollInObsidian
} from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { PERFORMANCE_VAULT_TOTAL_FILE_COUNT } from '../../scripts/helpers/generate-performance-vault.ts';

/*
 * A multi-file paste or drop goes through core's `ClipboardManager.insertFiles`, which saves the files one after
 * another and wrote each link as its file was saved. On a 71K-file vault a batch crawled in one link at a time. This
 * drives the real sink with a batch of files backed by real files outside the vault, the shape a drop from Explorer
 * has, and times the batch and its phases. `CAL_PERF_FILLER_FILE_COUNT` grows the vault with empty notes.
 */

const INDEX_WAIT_IN_MS = 600_000;
const CACHE_CLEAN_WAIT_IN_MS = 180_000;
const INDEX_POLL_IN_MS = 2000;
const SCENARIO_TIMEOUT_IN_MS = 900_000;
const BATCH_SIZE = 20;
/*
 * A loose bound, so a busy machine does not fail it: an idle one saves a file in a few milliseconds. The bound is per
 * file and holds whatever the vault size.
 */
const PER_FILE_BUDGET_IN_MS = 150;

interface AdapterWithFsPromises {
  readonly fsPromises: FsPromisesLike;
}

interface ClipboardManagerLike {
  readonly insertFiles: (importedAttachments: unknown[]) => Promise<void>;
}

interface EditModeLike {
  readonly clipboardManager?: ClipboardManagerLike;
}

interface EditorLike {
  readonly getValue: () => string;
}

interface FsPromisesLike {
  readonly mkdtemp: (prefix: string) => Promise<string>;
  readonly rm: (path: string, options: RemoveOptions) => Promise<void>;
  readonly writeFile: (path: string, data: Uint8Array) => Promise<void>;
}

interface InsertFilesBurstResult {
  readonly batchMs: number;
  readonly editorWriteAtMs: readonly number[];
  readonly error: null | string;
  readonly fileCount: number;
  readonly insertedLinkCount: number;
  readonly phaseCalls: PhaseTimings;
  readonly phaseMs: PhaseTimings;
  readonly vaultFileCount: number;
}

interface ObsidianLibState {
  readonly pluginApiRegistry?: RegistryWrapper;
}

interface ObsidianLibWrapper {
  readonly __obsidianLib?: ObsidianLibState;
}

interface OsModuleLike {
  readonly tmpdir: () => string;
}

interface PathModuleLike {
  readonly join: (...parts: string[]) => string;
}

type PhaseTimings = Readonly<Record<string, number>>;

interface RegistryRecords {
  readonly records?: Record<string, unknown[]>;
}

interface RegistryWrapper {
  readonly value?: RegistryRecords;
}

interface RemoveOptions {
  readonly force: boolean;
  readonly recursive: boolean;
}

interface ViewLike {
  readonly editMode?: EditModeLike;
  readonly editor?: EditorLike;
}

describe('Inserting a batch of attachments', () => {
  it('saves a batch of dropped files and writes their links in one go, quickly, on a large vault', async () => {
    const vaultPath = getTemporaryVault().path;
    await pollInObsidian({
      intervalInMilliseconds: INDEX_POLL_IN_MS,
      poll: ({ app }) => app.vault.getFiles().length,
      timeoutInMilliseconds: INDEX_WAIT_IN_MS,
      timeoutMessage: `The vault was not indexed within ${String(INDEX_WAIT_IN_MS)} ms`,
      until: (fileCount) => fileCount >= PERFORMANCE_VAULT_TOTAL_FILE_COUNT,
      vaultPath
    });
    // On a large vault the plugin's dependency gate can open after the index fills; until it does, core saves alone.
    await pollInObsidian({
      intervalInMilliseconds: INDEX_POLL_IN_MS,
      // The closure is serialized by its source text, so the id is spelled here rather than captured.
      poll: () => (window as ObsidianLibWrapper).__obsidianLib?.pluginApiRegistry?.value?.records?.['obsidian-custom-attachment-location']?.length ?? 0,
      timeoutInMilliseconds: INDEX_WAIT_IN_MS,
      timeoutMessage: 'The plugin API was not published',
      until: (recordCount) => recordCount > 0,
      vaultPath
    });
    /*
     * Until the metadata cache has parsed every note, each `createBinary` competes with that parse, which made one batch
     * on a 20K-file vault six times slower than the same batch half a minute later.
     */
    await pollInObsidian({
      intervalInMilliseconds: INDEX_POLL_IN_MS,
      poll: ({ app }) => app.metadataCache.isCacheClean(),
      timeoutInMilliseconds: CACHE_CLEAN_WAIT_IN_MS,
      timeoutMessage: 'The metadata cache did not settle',
      until: (isClean) => isClean,
      vaultPath
    });

    const result = await evalInObsidian({
      async callback({ app, BATCH_SIZE: batchSize }): Promise<InsertFilesBurstResult> {
        type AnyMethod = (this: unknown, ...callArguments: unknown[]) => unknown;
        const phaseMs: Record<string, number> = {};
        const phaseCalls: Record<string, number> = {};
        const restorers: (() => void)[] = [];

        function recordPhase(phase: string, start: number): void {
          phaseMs[phase] = (phaseMs[phase] ?? 0) + performance.now() - start;
        }

        function time(target: object, methodName: string, phase: string): void {
          const record = target as Record<string, unknown>;
          const hasOwnMethod = Object.hasOwn(record, methodName);
          const ownValue = record[methodName];
          const original = record[methodName] as AnyMethod;
          record[methodName] = function timedMethod(this: unknown, ...callArguments: unknown[]): unknown {
            const start = performance.now();
            phaseCalls[phase] = (phaseCalls[phase] ?? 0) + 1;
            const value = original.apply(this, callArguments);
            if (value instanceof Promise) {
              return value.finally(() => {
                recordPhase(phase, start);
              });
            }
            recordPhase(phase, start);
            return value;
          };
          restorers.push(() => {
            if (hasOwnMethod) {
              record[methodName] = ownValue;
            } else {
              Reflect.deleteProperty(record, methodName);
            }
          });
        }

        const empty: InsertFilesBurstResult = {
          batchMs: -1,
          editorWriteAtMs: [],
          error: null,
          fileCount: batchSize,
          insertedLinkCount: -1,
          phaseCalls: {},
          phaseMs: {},
          vaultFileCount: app.vault.getFiles().length
        };

        const adapterUnknown: unknown = app.vault.adapter;
        const fsPromises = (adapterUnknown as AdapterWithFsPromises).fsPromises;
        // eslint-disable-next-line @typescript-eslint/no-require-imports, unicorn/prefer-module -- Electron renderer require.
        const os = require('node:os') as OsModuleLike;
        // eslint-disable-next-line @typescript-eslint/no-require-imports, unicorn/prefer-module -- Electron renderer require.
        const nodePath = require('node:path') as PathModuleLike;
        const sourceFolder = await fsPromises.mkdtemp(nodePath.join(os.tmpdir(), 'insert-burst-'));

        const stamp = Date.now().toString();
        const note = await app.vault.create(`insert-burst-${stamp}.md`, '');
        const leaf = app.workspace.getLeaf(true);
        try {
          await leaf.openFile(note, { state: { mode: 'source' } });
          await app.workspace.revealLeaf(leaf);
          const viewUnknown: unknown = leaf.view;
          const view = viewUnknown as ViewLike;
          const clipboardManager = view.editMode?.clipboardManager;
          if (!clipboardManager || !view.editor) {
            return { ...empty, error: 'No clipboard manager on the opened note' };
          }

          const importedAttachments = [];
          for (let index = 0; index < batchSize; index++) {
            const name = `burst-${stamp}-${String(index)}`;
            const filePath = nodePath.join(sourceFolder, `${name}.pdf`);
            const bytes = new Uint8Array(4096).fill(index);
            await fsPromises.writeFile(filePath, bytes);
            importedAttachments.push({
              data: Promise.resolve(bytes.buffer),
              extension: 'pdf',
              filepath: filePath,
              name
            });
          }

          time(app, 'saveAttachment', 'app.saveAttachment');
          time(app.vault, 'getAvailablePathForAttachments', 'vault.getAvailablePathForAttachments');
          time(app.vault, 'createBinary', 'vault.createBinary');
          time(app.vault, 'exists', 'vault.exists');
          time(app.fileManager, 'generateMarkdownLink', 'fileManager.generateMarkdownLink');
          time(app.metadataCache, 'getFirstLinkpathDest', 'metadataCache.getFirstLinkpathDest');

          // Each editor write, and when it came: core wrote one per file as its file was saved.
          const editorWriteAtMs: number[] = [];
          let start = performance.now();
          const editorUnknown: unknown = view.editor;
          const editorRecord = editorUnknown as Record<string, unknown>;
          const replaceSelectionOriginal = editorRecord['replaceSelection'] as AnyMethod;
          editorRecord['replaceSelection'] = function replaceSelection(this: unknown, ...callArguments: unknown[]): unknown {
            const value = replaceSelectionOriginal.apply(this, callArguments);
            editorWriteAtMs.push(performance.now() - start);
            return value;
          };
          restorers.push(() => {
            Reflect.deleteProperty(editorRecord, 'replaceSelection');
          });

          start = performance.now();
          await clipboardManager.insertFiles(importedAttachments);
          const batchMs = performance.now() - start;

          const insertedLinkCount = (view.editor.getValue().match(/!\[/g) ?? []).length;
          return {
            ...empty,
            batchMs,
            editorWriteAtMs,
            insertedLinkCount,
            phaseCalls,
            phaseMs
          };
        } catch (error) {
          return { ...empty, error: String(error) };
        } finally {
          for (const restore of restorers.reverse()) {
            restore();
          }
          leaf.detach();
          await fsPromises.rm(sourceFolder, { force: true, recursive: true });
        }
      },
      input: { BATCH_SIZE },
      vaultPath
    });

    // `console.warn` is the only console level the lint config permits here, and it keeps the numbers visible on a pass.
    console.warn('Insert-files burst:', JSON.stringify(result, null, 2));

    expect(result.error).toBeNull();
    expect(result.insertedLinkCount).toBe(BATCH_SIZE);
    // The whole batch reaches the note in one editor transaction, so it is one undo step and typing cannot split it.
    expect(result.editorWriteAtMs).toHaveLength(1);
    // Saving makes no disk round trip to learn whether a folder the vault index already knows exists.
    expect(result.phaseCalls['vault.exists'] ?? 0).toBeLessThanOrEqual(1);
    expect(result.batchMs).toBeLessThan(BATCH_SIZE * PER_FILE_BUDGET_IN_MS);
  }, SCENARIO_TIMEOUT_IN_MS);
});
