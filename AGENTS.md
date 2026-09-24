# AGENTS.md

## Advanced Rename and Delete Handler is a declared dependency, so every test vault carries it

`src/plugin.ts` declares Advanced Rename and Delete Handler through `getPluginDependencies()`. Until its API is published at contract `^1.1.0`, this plugin's `onloadImpl` does not run: no commands, no patches, no settings tab of its own — the library shows a blocked tab and a notice that install it in one click.

Consequences for anyone touching the tests:

- **Every integration vault seeds it.** `scripts/helpers/advanced-rename-and-delete-handler-seed.ts` downloads the pinned RELEASE (cached under `.cache/`) and writes it into the vault with a `data.json` that leaves renames, attachment-folder moves and deletions off, and sets the read-back values to this plugin's historic defaults (`DeleteWithEmptyParents` and so on). The desktop and Android projects get it from `scripts/vitest-global-setup.ts`, wired in `scripts/vitest-config.ts`; the demo-vault and performance projects compose it into their own setups. A new project that opens a vault needs the same, or every suite in it meets this plugin blocked.
- **No suite may disable or remove it.** It outlives each file, and taking it away closes this plugin's gate for every later file in the run. A suite that needs its settings changed proposes them through its `migrateSettings` API and hands the previous values back — see `src/attachment-unit-folder-rescue-cross-plugin.desktop.integration.test.ts`.
- **Find its dialogs by TITLE, never with a bare `.modal-container` lookup.** `migrateSettings` opens a dialog on the way in *and* on the way out, and the behavior under test may have its own dialog open at the same time — anything that fails while the handler is asking something leaves two boxes on screen. A bare `document.querySelector('.modal-container')` then takes whichever is first in the DOM, and the teardown's throw (`the handler's settings dialog has no OK button`) **replaces the assertion that actually failed**, so the run reports the wrong defect entirely. `src/shared-attachment-tie-cross-plugin.desktop.integration.test.ts` matches on the `.modal-title` prefix for exactly this reason.
- **Unit tests publish a stand-in API.** `src/plugin.test.ts` publishes an empty API for the dependency in `beforeEach`; without it the gate never opens and nothing past the base loads. `unpublishProviderApi()` withdraws it, which is how the blocked path and the surface teardown are tested.
- **`onloadImpl` runs again each time the gate reopens.** Anything it stores outside its children has to be reset when the surface unloads — `attachmentCollector` and `pluginApi` both are, because `collectAttachmentsInAbstractFiles` and the published API are reachable from outside and would otherwise drive torn-down components.

## A command gate belongs on `canExecuteAbstractFile`; `canExecuteAbstractFiles` answers one surface out of three

`AbstractFileCommandHandler` exposes two overridable gates, and they are not interchangeable:

- `canExecuteAbstractFile(abstractFile)` is the per-file predicate. The **command palette** reaches it through `canExecute()` (`shouldAddToCommandPalette() && !!activeFile && this.canExecuteAbstractFile(activeFile)`), the **single-file menu** calls it directly, and the base's `canExecuteAbstractFiles` composes it over every entry.
- `canExecuteAbstractFiles(abstractFiles)` is reached by the **multi-select menu alone**.

So a handler that overrides only the second, leaving the first at its base `return true`, gates one surface out of three — and the other two offer a command that then walks its own filter and does nothing. All three of this repo's gated handlers were that shape, and it was caught only because `excalidraw-source-note-skip.desktop.integration.test.ts` asks `checkCallback(true)` — the same availability question Obsidian asks before listing a command. Every unit test passed while the palette was still offering it, because the unit tests called the override.

Two consequences for anyone adding or changing one:

- **Put the predicate on `canExecuteAbstractFile` and let the base compose it.** All three gated handlers are worked examples: `collect-attachments-in-file-command-handler.ts` (plain `isNote`, so a drawing is still collected from), `delete-unused-attachments-in-file-command-handler.ts` and `move-attachment-to-proper-folder-command-handler.ts` (both `isNoteEx`).
- **Do not open such an override with `super.canExecute()`.** The three handlers used to, and it tests the ACTIVE file — a condition with nothing to do with a menu built from the files the user clicked, and one that turns into a real false negative the moment `canExecuteAbstractFile` is implemented, hiding the multi-select item whenever an unrelated file is open.

## The published reads are non-interactive, and a new interactive token must say so

`src/plugin-api-impl.ts` answers a consumer's questions by driving the same `AttachmentPathManager` the commands drive, under `ActionContext.ReadApi`. That context exists for one reason: **a read has no user to ask.** A consumer auditing a whole vault calls `getAttachmentFolderPath` once per note, and a folder template holding `{{prompt}}` would raise one dialog per note.

- **A token that would open anything must gate on `isNonInteractiveActionContext`** (`src/token-evaluator-context.ts`), not on `ActionContext.ValidateTokens` by name. `prompt-token.ts` is the only such token today and is the worked example; naming the context directly is how the next one silently starts prompting an audit.
- **`migrateSettings` asks through its OWN dialog, never through a token.** It receives the collect settings Consistent Attachments and Links hands over, and the user approves them in `src/modals/collect-settings-migration-modal.ts`. It never evaluates a template, so it gives `{{prompt}}` no way in. Keep it that way: the non-interactive rule above is about the READS.
- **`collectAttachments` is an ACTION and asks exactly what the `Collect attachments` commands ask** — it drives the same queued collector, under the command's own contexts, not `ReadApi`. Two things keep that honest: it resolves to nothing and never reaches the collector when no named path exists (an empty list is what the collector confirms with the user), and it awaits the collect through `addToQueueAndWait` so a consumer can sequence on it. The plugin instance's `collectAttachmentsInAbstractFiles` is its superseded predecessor (a JSDoc note, not `@deprecated`: the fleet config forbids disabling `no-deprecated`, and its own tests must keep calling it) and still delegates to the same collector.
- **`ActionContext.ReadApi` falls into every `default:` branch** in `attachment-path-manager.ts`, so a read answers about the NEW-attachment destination (`attachmentFolderPath`) and the ordinary generated file name. That is deliberate and is what `api.d.ts` promises. The collect destination (`collectedAttachmentFolderPath`) is a different question and is not published yet.

## `api.d.ts` at the repo root is the whole published surface, and it imports `obsidian` alone

The convention: a consumer copies that one file, or references it where it sits, with no build-time dependency on this repository. `src/plugin-api.ts` holds only the runtime half (`PLUGIN_API_CONTRACT`, `PLUGIN_API_VERSION`) and RE-EXPORTS the types from it, so each type is declared once. Adding a member means editing `api.d.ts`, the contract, the impl, and the version — a minor bump for an addition, which is what lets a consumer keep asking for `'^1'`.

## An integration suite edits settings through `editAndSave`, never onto the settings object

A `data.json` reload replaces the settings object, so an assignment onto it reverts to the file's values mid-suite, silently. Every desktop suite therefore gets the settings component from `scripts/helpers/plugin-settings-component-finder.ts`, passed into the closure through `evalInObsidian`'s `input` (functions there are serialized by source text, so the finder stays self-contained), and both edits and the final restore go through `editAndSave`. Read values through `settingsComponent.settings` each time rather than holding the object. A saved edit outlives the suite in `data.json`, so a suite that changes settings restores them in a `finally`.

## A fresh install follows Obsidian's attachment location, so every test vault seeds pattern mode

Since 13.0.0 `shouldFollowObsidianAttachmentLocation` defaults to on. While it is on, `attachmentFolderPath` is not consulted at all, so an integration vault with no `data.json` of ours quietly turns every pattern suite into a test of Obsidian's own setting. `scripts/helpers/plugin-settings-seed.ts` seeds `{ shouldFollowObsidianAttachmentLocation: false }`. The desktop/Android, demo-vault and performance setups all compose it, and a new project that opens a vault needs it too. The demo vault commits a full `data.json` in pattern mode for the same reason: notes 01 and 08 demonstrate patterns and hard-code `assets/<note>`.

`PluginSettingsComponent.loadFromFile` writes `data.json` when none exists, because the obsidian-dev-utils base never does. Without that write, nothing on disk tells a fresh install apart from a user who never saved a setting, and a default change moves both.
