import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { ImportedAttachment } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  TFile
} from 'obsidian';

import { AttachmentPathContext } from '@mnaoumov/obsidian-lib/attachment-path';
import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import {
  dirname,
  makeFileName
} from '@mnaoumov/typescript-lib/path';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import { TFile as ObsidianFile } from 'obsidian';

import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { AttachmentSaver } from '../attachment-saving/attachment-saver.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { SidecarBase } from './sidecar-matcher.ts';

import { selfWriteRegistry } from '../externally-created-attachments/self-write-registry.ts';
import {
  ActionContext,
  isNonInteractiveActionContext
} from '../tokens/token-evaluator-context.ts';
import {
  findSidecarBase,
  getSidecarPath
} from './sidecar-matcher.ts';

interface CompanionMove {
  readonly file: TFile;
  readonly newPath: string;
  readonly oldPath: string;
}

interface ExistingSidecarBase {
  readonly base: TFile;
  readonly pairing: SidecarBase;
}

interface ImportEntry {
  readonly attachment: ImportedAttachment;
  readonly batch: ImportEntry[];
  readonly content: ArrayBuffer;
  readonly name: string;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  saved?: Promise<TFile>;
}

interface SidecarAttachmentsComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly attachmentSaver: AttachmentSaver;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
Keeps companions with their base across imports and awaited file moves.
*/
export class SidecarAttachmentsComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly attachmentSaver: AttachmentSaver;
  private readonly entries = new WeakMap<ArrayBuffer, ImportEntry>();
  private readonly moving = new Set<TFile>();
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: SidecarAttachmentsComponentConstructorParams) {
    super();
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.attachmentSaver = params.attachmentSaver;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
  Pairs a name with its base among `names`, using the configured sidecar extensions.
  @returns `undefined` for a non-sidecar, `null` for an orphan or ambiguous sidecar.
  */
  public findBase(name: string, names: readonly string[]): null | SidecarBase | undefined {
    return findSidecarBase({ extensions: this.pluginSettingsComponent.settings.sidecarExtensions, name, names });
  }

  public override onload(): void {
    const { app, attachmentPathManager, attachmentSaver } = this;
    this.registerMethodPatch({
      $object: attachmentSaver,
      methodName: 'saveAttachment',
      patchHandler: ({ originalArguments: [saveParams], originalMethodBound }) => {
        const entry = this.entries.get(saveParams.attachmentFileContent);
        if (entry?.saved) {
          return entry.saved;
        }
        const save = async (): Promise<TFile> => {
          const name = makeFileName({ fileBaseName: saveParams.attachmentFileBaseName, fileExtension: saveParams.attachmentFileExtension });
          const siblings = entry?.batch.filter((candidate) => dirname(candidate.attachment.filepath ?? '') === dirname(entry.attachment.filepath ?? '')) ?? [];
          const pairing = this.findBase(name, siblings.map((candidate) => candidate.name));
          if (pairing === undefined) {
            const shouldPreserveContent = siblings.some((candidate) => this.findBase(candidate.name, siblings.map((sibling) => sibling.name))?.baseName === name);
            return await originalMethodBound({ ...saveParams, shouldPreserveContent });
          }
          const existing = pairing === null && siblings.length <= 1 ? await this.findExistingBase(name) : undefined;
          const resolvedPairing = existing?.pairing ?? pairing;
          let base: TFile | undefined = existing?.base;
          if (pairing) {
            const baseEntry = ensureNonNullable(siblings.find((candidate) => candidate.name === pairing.baseName));
            base = await attachmentSaver.saveAttachment({
              attachmentFileBaseName: baseEntry.attachment.name,
              attachmentFileContent: baseEntry.content,
              attachmentFileExtension: baseEntry.attachment.extension
            });
          }
          if (!base || !resolvedPairing) {
            this.reportUnpaired(name);
            return await originalMethodBound({ ...saveParams, shouldKeepName: true, shouldPreserveContent: true });
          }
          const destinationPath = getSidecarPath(base.path, resolvedPairing);
          if (await app.vault.exists(destinationPath)) {
            // A suffix on the companion alone would break the pairing. Leave existing bytes untouched.
            throw new Error(t(($) => $.notice.sidecarDestinationExists, { path: destinationPath }));
          }
          selfWriteRegistry.register(destinationPath);
          return await originalMethodBound({ ...saveParams, destinationPath, shouldKeepName: true, shouldPreserveContent: true });
        };
        const saved = save().then((file) => {
          if (entry?.attachment.filepath) {
            this.attachmentPathManager.originalAttachmentNamesComponent.setOriginalPath(file.path, entry.attachment.filepath);
          }
          return file;
        });
        if (entry) {
          entry.saved = saved;
        }
        return saved;
      }
    });
    this.registerMethodPatch({
      $object: app,
      methodName: 'importAttachments',
      patchHandler: async ({ fallback, originalArguments: [attachments] }) => await this.runImportBatch(attachments, fallback)
    });
    this.registerMethodPatch({
      $object: attachmentPathManager,
      methodName: 'getAvailablePathForAttachments',
      patchHandler: ({ fallback, originalArguments: [pathParams] }) => {
        if (pathParams.context === AttachmentPathContext.RenameNote) {
          const file = typeof pathParams.oldAttachmentPathOrFile === 'string'
            ? app.vault.getFileByPath(pathParams.oldAttachmentPathOrFile)
            : pathParams.oldAttachmentPathOrFile;
          if (file && this.findBase(file.name, []) !== undefined) {
            // The dependency may plan linked files in either order. Only the base plans a move; its awaited
            // vault rename carries the companion, so no later plan can give it an independent random name.
            return Promise.resolve(file.path);
          }
        }
        return fallback();
      }
    });
    this.registerMethodPatch({
      $object: attachmentPathManager,
      methodName: 'getProperAttachmentPath',
      patchHandler: ({ fallback, originalArguments: [pathParams] }) => {
        const file = pathParams.attachmentFile;
        if (this.findBase(file.name, []) === undefined) {
          return fallback();
        }
        const pairing = this.findBase(file.name, file.parent?.children.filter((child) => child instanceof ObsidianFile).map((child) => child.name) ?? []);
        // A base's move carries its companions; a companion never gets an independent random name.
        if (!pairing && !isNonInteractiveActionContext(pathParams.actionContext)) {
          this.reportUnpaired(file.path);
        }
        return Promise.resolve(null);
      }
    });
    this.registerMethodPatch({
      $object: app.vault,
      methodName: 'rename',
      patchHandler: async ({ fallback, originalArguments: [file, newPath], originalMethodBound }) => {
        if (!(file instanceof ObsidianFile) || this.moving.has(file)) {
          await fallback();
          return;
        }
        const oldPath = file.path;
        const companions = this.getCompanionMoves(file, newPath);
        for (const move of companions) {
          if (await app.vault.exists(move.newPath) && move.file.path !== move.newPath) {
            throw new Error(t(($) => $.notice.sidecarDestinationExists, { path: move.newPath }));
          }
        }
        await fallback();
        const moved: typeof companions = [];
        try {
          for (const move of companions) {
            this.moving.add(move.file);
            try {
              await app.fileManager.renameFile(move.file, move.newPath);
              moved.push(move);
            } finally {
              this.moving.delete(move.file);
            }
          }
        } catch (error) {
          // Restore the base and companions already moved, so a failed move does not strand a partial group.
          await originalMethodBound(file, oldPath);
          for (const move of moved.reverse()) {
            this.moving.add(move.file);
            try {
              await app.fileManager.renameFile(move.file, move.oldPath);
            } finally {
              this.moving.delete(move.file);
            }
          }
          throw error;
        }
      }
    });
  }

  /**
  Tells the user a sidecar kept its own name because no single base was found.
  */
  public reportUnpaired(path: string): void {
    this.pluginNoticeComponent.showNotice(t(($) => $.notice.sidecarBaseMissing, { path }));
  }

  /**
  Keeps the batch alive until the editor or app finishes saving its files.
  @typeParam T - The import sink's result.
  */
  public async runImportBatch<T>(attachments: readonly ImportedAttachment[], run: () => Promise<T>): Promise<T> {
    const batch: ImportEntry[] = [];
    try {
      for (const attachment of attachments) {
        const content = await attachment.data;
        if (!content || this.entries.has(content)) {
          continue;
        }
        const entry: ImportEntry = {
          attachment,
          batch,
          content,
          name: makeFileName({ fileBaseName: attachment.name, fileExtension: attachment.extension })
        };
        batch.push(entry);
        this.entries.set(content, entry);
      }
      return await run();
    } finally {
      for (const entry of batch) {
        this.entries.delete(entry.content);
      }
    }
  }

  private async findExistingBase(name: string): Promise<ExistingSidecarBase | undefined> {
    const note = this.app.workspace.getActiveFile();
    if (!note) {
      return undefined;
    }
    const candidates: ExistingSidecarBase[] = [];
    for (const base of this.app.vault.getFiles()) {
      const originalName = this.attachmentPathManager.originalAttachmentNamesComponent.get(base.path) ?? base.name;
      const candidatePairing = this.findBase(name, [originalName]);
      if (!candidatePairing) {
        continue;
      }
      const folder = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.ReadApi,
        attachmentFileName: base.name,
        attachmentFileStats: base.stat,
        notePath: note.path,
        originalAttachmentFileNameParams: { originalAttachmentFileName: originalName }
      });
      if (dirname(base.path) !== folder) {
        continue;
      }
      candidates.push({ base, pairing: candidatePairing });
    }
    const pairing = this.findBase(name, candidates.map((candidate) => candidate.pairing.baseName));
    if (!pairing) {
      return undefined;
    }
    const candidate = ensureNonNullable(candidates.find((entry) => entry.pairing.baseName === pairing.baseName));
    return { base: candidate.base, pairing };
  }

  private getCompanionMoves(file: TFile, newPath: string): CompanionMove[] {
    const siblings = file.parent?.children.filter((child): child is TFile => child instanceof ObsidianFile) ?? [];
    const names = siblings.map((candidate) => candidate.name);
    const moves: CompanionMove[] = [{ file, newPath, oldPath: file.path }];
    const queued = new Set([file]);
    let index = 0;
    // Follow chains such as document.html.p7s.asc without renaming any companion twice.
    while (index < moves.length) {
      const current = ensureNonNullable(moves[index++]);
      for (const sibling of siblings) {
        if (queued.has(sibling)) {
          continue;
        }
        const pairing = this.findBase(sibling.name, names);

        if (pairing?.baseName !== current.file.name) {
          continue;
        }
        const destination = getSidecarPath(current.newPath, pairing);
        queued.add(sibling);
        moves.push({ file: sibling, newPath: destination, oldPath: sibling.path });
      }
    }
    return moves.slice(1);
  }
}
