import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  afterAll,
  beforeAll,
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * `Commit bulk operations to git` end to end, against a vault that is a git repository: one run of `Move attachment
 * to proper folder` lands as `chore: before OP<n>` (everything that was pending) plus `OP<n>: <summary>` (the move
 * alone), and reverting that one commit puts the vault back.
 *
 * The suite makes the shared temporary vault a repository for its own lifetime and removes `.git` again afterwards.
 * The configuration folder is ignored, as it is in most real vault repositories, so the workspace file Obsidian
 * rewrites on its own schedule cannot land in the operation's commit and conflict with the revert.
 *
 * The revert is run with the system `git` here rather than through `Undo a bulk operation...`, whose picker would
 * need a pointer-driven suggester; the command is checked to be offered, and it runs the same `git revert --no-edit`
 * after committing whatever is pending, which this suite does too.
 *
 * Every git call from inside Obsidian is asynchronous, as the library's are. A blocking `execFileSync` stalls the
 * renderer while git rewrites `.git`, and on Windows Obsidian's file watcher then drops the events for the files a
 * revert puts back, so the vault never sees them.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const MOVE_COMMAND_ID = `${PLUGIN_ID}:move-attachment-to-proper-folder`;
const UNDO_COMMAND_ID = `${PLUGIN_ID}:undo-bulk-operation`;
// The run's closure waits twice, and every closure stays under the transport's 30s cap.
const RUN_WAIT_TIMEOUT_IN_MILLISECONDS = 10_000;
// The commit waits for a 2s quiet vault after the move, so this is generous.
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface CommitsResult {
  readonly movedPaths: readonly string[];
  readonly operationChangedPaths: readonly string[];
  readonly operationSha: string;
  readonly subjects: readonly string[];
}

interface RevertResult {
  readonly isAttachmentBack: boolean;
  readonly isMovedCopyGone: boolean;
  readonly noteContent: string;
  readonly revertSubject: string;
  readonly status: string;
}

interface RunResult {
  readonly attachmentPath: string;
  readonly isUndoCommandOffered: boolean;
  readonly noteContentBefore: string;
  readonly notePath: string;
  readonly settingsFound: boolean;
}

/**
 * Builds, inside Obsidian, an asynchronous `git` runner for the vault folder. Serialized by its source text through
 * `evalInObsidian`'s `input`, so it reaches nothing outside its own body.
 *
 * @param adapter - The vault adapter, which on desktop knows the vault's folder.
 * @returns The runner, which resolves to git's trimmed output.
 */
function createGitRunner(adapter: unknown): (...gitArguments: string[]) => Promise<string> {
  interface ChildProcessExecFileOptions {
    readonly cwd: string;
    readonly encoding: 'utf-8';
  }

  interface ChildProcess {
    readonly execFile: (
      file: string,
      gitArguments: readonly string[],
      options: ChildProcessExecFileOptions,
      callback: (error: Error | null, stdout: string) => void
    ) => void;
  }

  interface BasePathAdapter {
    readonly getBasePath: () => string;
  }

  interface NodeRequireHost {
    readonly require: (id: string) => unknown;
  }

  function isBasePathAdapter(value: unknown): value is BasePathAdapter {
    return typeof (value as Partial<BasePathAdapter>).getBasePath === 'function';
  }

  function isChildProcess(value: unknown): value is ChildProcess {
    return typeof (value as Partial<ChildProcess>).execFile === 'function';
  }

  function isNodeRequireHost(value: unknown): value is NodeRequireHost {
    return typeof (value as Partial<NodeRequireHost>).require === 'function';
  }

  // Desktop Obsidian runs its renderer with Node integration, so `require` is the renderer's own.
  const requireHost: unknown = window;
  const childProcess = isNodeRequireHost(requireHost) ? requireHost.require('node:child_process') : null;
  if (!isChildProcess(childProcess) || !isBasePathAdapter(adapter)) {
    throw new Error('git can only be run from desktop Obsidian with a file system vault');
  }
  const cwd = adapter.getBasePath();

  return (...gitArguments: string[]): Promise<string> =>
    new Promise((resolve, reject) => {
      childProcess.execFile('git', gitArguments, { cwd, encoding: 'utf-8' }, (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(stdout.trim());
      });
    });
}

describe('Commit bulk operations to git', () => {
  beforeAll(async () => {
    await evalInObsidian({
      async callback({ app, createGitRunner: createGit }): Promise<void> {
        const git = createGit(app.vault.adapter);
        await git('init', '--quiet');
        await git('config', 'user.name', 'Integration Test');
        await git('config', 'user.email', 'integration-test@example.com');
        // A machine-wide signing setting would make every commit wait for a key nobody can unlock here.
        // cspell:ignore gpgsign
        await git('config', 'commit.gpgsign', 'false');
        // A machine-wide `core.autocrlf` would rewrite line endings when the revert checks the note out again.
        await git('config', 'core.autocrlf', 'false');
        await app.vault.adapter.write('.gitignore', `${app.vault.configDir}/\n`);
      },
      input: { createGitRunner },
      vaultPath: getTemporaryVault().path
    });
  }, 60_000);

  afterAll(async () => {
    await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, pluginId }): Promise<void> {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldCommitBulkOperations: boolean;
        }

        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && typeof (value as Partial<Settings>).shouldCommitBulkOperations === 'boolean';
        }

        await findSettingsComponent(app.plugins.getPlugin(pluginId), isSettings)?.editAndSave((settings) => {
          settings.shouldCommitBulkOperations = false;
        });
        await app.vault.adapter.rmdir('.git', true);
        await app.vault.adapter.remove('.gitignore');
      },
      input: { findPluginSettingsComponent, pluginId: PLUGIN_ID },
      vaultPath: getTemporaryVault().path
    });
  }, 60_000);

  it('records one run as its own commit, and reverting that commit puts the vault back', async () => {
    const run = await evalInObsidian({
      async callback({
        app,
        findPluginSettingsComponent: findSettingsComponent,
        lib: { waitUntil },
        moveCommandId,
        pluginId,
        undoCommandId,
        waitTimeoutInMilliseconds
      }): Promise<RunResult> {
        interface AvailabilityCheckableCommand {
          readonly checkCallback?: (isChecking: boolean) => boolean | undefined;
        }

        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldCommitBulkOperations: boolean;
        }

        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && typeof (value as Partial<Settings>).shouldCommitBulkOperations === 'boolean';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isSettings);
        if (!settingsComponent) {
          return { attachmentPath: '', isUndoCommandOffered: false, noteContentBefore: '', notePath: '', settingsFound: false };
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const attachmentPath = `stray-${stamp}/pic-${stamp}.png`;
        const notePath = `bulk-op-note-${stamp}.md`;
        const noteContentBefore = `![[${attachmentPath}]]\n`;

        await app.vault.createFolder(`stray-${stamp}`);
        const attachmentFile = await app.vault.createBinary(attachmentPath, new ArrayBuffer(4));
        await app.vault.create(notePath, noteContentBefore);
        await waitUntil({
          message: 'the staged embed was not indexed',
          predicate: () => app.metadataCache.getBacklinksForFile(attachmentFile).keys().length > 0,
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });

        await settingsComponent.editAndSave((settings) => {
          settings.shouldCommitBulkOperations = true;
        });

        const undoCommandUnknown: unknown = app.commands.commands[undoCommandId];
        const isUndoCommandOffered = (undoCommandUnknown as AvailabilityCheckableCommand | undefined)?.checkCallback?.(true) === true;

        // The palette command acts on the ACTIVE file, and `openFile` resolves before the switch lands.
        await app.workspace.getLeaf(false).openFile(attachmentFile);
        await waitUntil({
          message: 'the attachment did not become the active file',
          predicate: () => app.workspace.getActiveFile()?.path === attachmentPath,
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });
        app.commands.executeCommandById(moveCommandId);

        return { attachmentPath, isUndoCommandOffered, noteContentBefore, notePath, settingsFound: true };
      },
      input: {
        findPluginSettingsComponent,
        moveCommandId: MOVE_COMMAND_ID,
        pluginId: PLUGIN_ID,
        undoCommandId: UNDO_COMMAND_ID,
        waitTimeoutInMilliseconds: RUN_WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(run.settingsFound).toBe(true);
    expect(run.isUndoCommandOffered).toBe(true);

    const commits = await evalInObsidian({
      async callback({ app, attachmentPath, createGitRunner: createGit, lib: { waitUntil }, notePath, waitTimeoutInMilliseconds }): Promise<CommitsResult> {
        const git = createGit(app.vault.adapter);
        let subjects: string[] = [];

        await waitUntil({
          message: 'no OP commit was made for the move',
          predicate: async () => {
            try {
              const log = await git('log', '--format=%s');
              subjects = log.split('\n');
            } catch {
              // `git log` fails until the first commit exists.
              subjects = [];
            }
            return subjects.some((subject) => /^OP\d+: /.test(subject));
          },
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });

        const operationSha = await git('log', '--format=%H', '--grep=^OP[0-9]*: ', '-n', '1');
        const noteBaseName = notePath.replace(/\.md$/, '');
        const movedFolderPrefix = `assets/${noteBaseName}/`;
        // Without `--no-renames`, git reports the move's copy and delete as one rename and lists only the new path.
        const changedPathsOutput = await git('show', '--name-only', '--no-renames', '--format=', operationSha);
        const changedPaths = changedPathsOutput.split('\n');
        return {
          movedPaths: app.vault.getFiles().map((file) => file.path).filter((path) => path.startsWith(movedFolderPrefix)),
          operationChangedPaths: changedPaths.filter((path) => path === notePath || path === attachmentPath || path.startsWith(movedFolderPrefix)),
          operationSha,
          subjects
        };
      },
      input: { attachmentPath: run.attachmentPath, createGitRunner, notePath: run.notePath, waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS },
      vaultPath: getTemporaryVault().path
    });

    // Two commits: what was pending, then the move alone, named after the command and its scope.
    const operationSubject = commits.subjects[0] ?? '';
    const operationId = /^(?<operationId>OP\d+): /.exec(operationSubject)?.groups?.['operationId'] ?? '';
    expect(operationSubject).toBe(`${operationId}: Move attachments to proper folder in ${run.attachmentPath}`);
    expect(operationId).not.toBe('');
    expect(commits.subjects[1]).toBe(`chore: before ${operationId}`);
    expect(commits.movedPaths).toHaveLength(1);
    // The operation's commit holds the original's removal, the note's edit and the moved copy.
    expect([...commits.operationChangedPaths].sort()).toEqual([run.attachmentPath, ...commits.movedPaths, run.notePath].sort());

    const reverted = await evalInObsidian({
      async callback({
        app,
        attachmentPath,
        createGitRunner: createGit,
        lib: { waitUntil },
        movedPath,
        notePath,
        operationSha,
        waitTimeoutInMilliseconds
      }): Promise<RevertResult> {
        const git = createGit(app.vault.adapter);

        // What `Undo a bulk operation...` does: commit what is pending, so the revert never meets local changes.
        if (await git('status', '--porcelain') !== '') {
          await git('add', '-A');
          await git('commit', '--quiet', '-m', 'chore: before revert');
        }
        await git('revert', '--no-edit', operationSha);

        await waitUntil({
          message: 'Obsidian did not pick up the reverted files',
          predicate: () => app.vault.getFileByPath(attachmentPath) !== null && app.vault.getFileByPath(movedPath) === null,
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });

        return {
          isAttachmentBack: app.vault.getFileByPath(attachmentPath) !== null,
          isMovedCopyGone: app.vault.getFileByPath(movedPath) === null,
          noteContent: await app.vault.adapter.read(notePath),
          revertSubject: await git('log', '--format=%s', '-n', '1'),
          status: await git('status', '--porcelain', '--', attachmentPath, notePath, movedPath)
        };
      },
      input: {
        attachmentPath: run.attachmentPath,
        createGitRunner,
        movedPath: commits.movedPaths[0] ?? '',
        notePath: run.notePath,
        operationSha: commits.operationSha,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(reverted.revertSubject).toBe(`Revert "${operationSubject}"`);
    expect(reverted.isAttachmentBack).toBe(true);
    expect(reverted.isMovedCopyGone).toBe(true);
    expect(reverted.noteContent).toBe(run.noteContentBefore);
    expect(reverted.status).toBe('');
  }, 120_000);
});
