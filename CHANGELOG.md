# CHANGELOG

## 16.0.0

- feat(settings)!: merge taking obsidian-lib 5.0.0 path settings with globs and case-insensitive matching (re #98 - Exclude file extensions (e.g. .mdenc) from Collect attachments)
- docs: mark plugin names as code
- fix(tokens): merge registering custom tokens whenever the settings are validated

Migration: every entry in a path list (attachment unit folders, the two exclude lists, the orphan-scan paths) now matches case-insensitively. An unescaped `*`, `?` or `[` makes an entry a glob (`*.pdf`, `Archive/**/*.png`, `*_files/`), so a plain path that holds one of those characters literally must escape it (`Notes \[old\]`). An entry shaped `/pattern/flags` is a regular expression whose flags are honoured; an unknown flag is reported as invalid.

## 15.1.1

- docs(api): merge naming the validation debug switch in the contract
- fix(paste): merge renaming every pasted image file again under Only pasted images (re #97 - [BUG] The newly uploaded attachment was not renamed.)
- chore(deps): merge bumping obsidian-test-mocks to ^7.2.3
- refactor(api): merge refreshing the `Advanced Rename and Delete Handler` contract copy
- chore(github): merge linking Discussions from the issue chooser
- refactor(paste): merge using the nullable ImportedAttachment typings
- docs(agents): merge saying how a demo-vault Try it promise is asserted
- docs(demo-vault): merge giving every Try it a button for its setup and steps
- docs(tokens): merge a custom-token example that renames only images
- fix(attachments): merge replacing special characters in a name a new attachment keeps
- docs(settings): say the Markdown URL format applies only when an attachment is added
- fix(collect): merge collecting after a note is moved outside Obsidian
- test(network-images): merge pinning the automatic collect downloading a network image
- test(excalidraw): merge pinning a paste into a folder that does not exist yet
- test(api-contract): verify the contract with verifyApiContract from typescript-lib 1.5.0
- fix(paste): merge no longer force-loading a deferred markdown tab at startup
- refactor(api-contract): merge building the contract guards from typescript-lib and obsidian-lib

## 15.1.0

- feat(paste): merge telling screenshot files apart from real files in Only pasted images
- feat(collect): merge an opt-in setting that merges byte-identical attachments
- build(deps): merge taking obsidian-dev-toolkit 3.1.0 without the obsidian-lib override
- ci: merge attesting release assets through the toolkit's reusable workflow
- feat(dependency): merge requiring `Advanced Rename and Delete Handler` 2.2.0 or later

## 15.0.0

- feat(api)!: merge removing the vault graft; use the API's getAvailablePathForAttachments and isAttachmentUnitFolder
  - BREAKING: `app.vault.getAvailablePathForAttachments.extended` is removed. Use the plugin API's `getAvailablePathForAttachments` (contract `1.3.0`).
  - BREAKING: `app.vault.getAvailablePathForAttachments.checkIsAttachmentUnitFolder` is removed. Use the plugin API's `isAttachmentUnitFolder` (contract `1.3.0`).
  - `obsidian-dev-utils` 107.4.1 and older read these members; `@mnaoumov/obsidian-lib` 2.0.0 and later read the plugin API.
  - `Advanced Rename and Delete Handler` needs 2.2.0 or later to keep an attachment unit folder whole when it rescues attachments out of a deleted folder.
- test: merge seeding `Advanced Rename and Delete Handler` 2.2.1, which reads the designation through the API
- build(demo-vault): merge requiring `CodeScript Toolkit` 13.8.0 for the obsidian-lib demo script
- fix(ui): merge marking the plugin names in the dependency reason as code
- refactor(demo-vault): merge importing the community-plugin helpers from @mnaoumov/obsidian-lib

## 14.2.0

- refactor: merge moving off obsidian-dev-utils onto the @mnaoumov packages
- refactor(api): merge building the API contract on @mnaoumov/typescript-lib/api-contract
- feat(api): merge taking `Advanced Rename and Delete Handler`'s own contract, with full schemas
- feat(api): merge the copyable api-contract.ts with full schemas
- feat(ui): merge marking plugin names as code in UI, markdown and comments

## 14.1.0

- test: merge using the obsidian-typings declarations of Obsidian internals
- test(api): read the migrate suite's expected contract version from the source
- feat(api): merge publishing the attachment-path resolver and the unit-folder check

## 14.0.3

- fix: merge updating obsidian-dev-utils to 107.4.1 (re #95 - [BUG] Global CSS leak via `body button:not(.clickable-icon)` breaks button text and icons in other plugins)

## 14.0.2

- chore: merge updating libs onto obsidian-dev-utils 107.3.1

## 14.0.1

- revert: leave no special case for a note's auto-export (#92)
- fix(external-attachments): merge leaving a note's auto-export where it is written (#92)
- test(external-attachments): merge pinning that an `Excalidraw` paste is renamed only once `Excalidraw` is listed
- docs(external-attachments): merge saying an image pasted into a drawing is `Excalidraw`'s write
- test(screenshots): merge setting the desktop capture theme with applyObsidianTheme
- test(android): merge verifying the overlap stub writes
- fix(release-notes): merge naming the plugin in the release notes popup
- chore(test): merge dropping the perf transport raise obsidian-dev-utils now provides

## 14.0.0

**Breaking: the token syntax moved from `${...}` to `{{...}}`.** Tokens are now written `{{noteFileName}}`, and a token with a format takes `{{token:format}}`, for example `{{date:YYYY-MM-DD}}`. The `${token}` and `${token:{...}}` forms no longer parse.

Upgrading from `${...}`: your saved patterns are rewritten to `{{...}}` automatically the first time 14.0.0 loads. Your custom tokens code is JavaScript you wrote, so it is left as it is: a `ctx.fillTemplate('${noteFileName}')` in it fails with an error naming the `{{noteFileName}}` that replaces it, rather than silently producing a wrong name. The demo vault's `03 Tokens and patterns` note has the full token reference.

- refactor(settings): merge stating that the legacy file-name pattern is never absent
- docs(settings): merge spelling behavior the US way so the spellcheck gate passes
- refactor(settings): merge dropping the loadFromFile override the obsidian-dev-utils base now covers
- test(integration): merge naming the empty-folder cleanup race behind Failed to parse path
- feat(settings): merge recognizing a drawing by its excalidraw-plugin property through the handler (#90)
- test(screenshots): merge capturing the desktop frames without the editor caret
- test(screenshots): merge pinning the clock the store captures read
- refactor(settings): merge dropping the anchored placeholder override
- docs(agents): merge noting the capture suites as the one writer of the handler record
- chore(deps): merge the dependency sweep onto obsidian-integration-testing 17 and the re-shot store frames
- refactor(settings): merge dropping the private-field onSavingRecord override on obsidian-dev-utils 107
- refactor(styles): merge dropping the local multiple-dropdown rule on obsidian-dev-utils 107 (#86)
- feat(external-attachments): merge renaming an image pasted into an `Excalidraw` drawing (#65)
- test(coverage): merge covering the branches the obsidian-test-mocks 7 float left uncovered
- test(delete-unused): merge pinning that the images a drawing shows are backlinks
- refactor(tokens): merge keeping parseFormatObject file-local
- test(integration): merge editing settings through editAndSave in every desktop suite
- fix(tokens): merge registering the stored custom tokens when enabled after layout-ready
- chore(deps): merge floating obsidian-test-mocks to ^7.0.0
- docs(demo-vault): merge stating what skipping a drawing costs the delete-unused sweep
- docs(readme): merge linking both cross-plugin API guides
- fix: merge moving an attachment used by a single note to its proper folder
- style(comments): merge lowercasing the wrapped-comment continuation lines
- test(api): merge the per-note suite's editAndSave settings seam
- refactor(settings): merge showing the overlap banner row through a visible predicate
- feat!: merge the move to the {{token:format}} syntax
- build(lint): merge turning on no-soft-break-in-paragraph
- refactor: merge dropping the local command disposal the base now makes redundant
- chore(deps): merge raising obsidian-dev-utils to 106 and obsidian-integration-testing to 16
- test(demo-vault): merge installing `CodeScript Toolkit` headlessly when it is missing
- chore: merge adopting the npm run gate branch gate
- fix(settings): merge stopping every settings load from rewriting data.json
- fix(deps): merge restoring the lockfile's missing resolved and integrity fields
- fix: merge never sweeping a drawing as a note for unused attachments
- fix: merge giving a drawing treated as an attachment its base name as link text

## 13.0.0

- docs(demo-vault): merge showing the Collect attachments automatically setting
- refactor(patches): merge keeping the core Files tab id file-local
- test: merge covering the per-note read API branches
- fix: merge no longer offering Move attachment to proper folder on a note
- docs(contributing): merge basing PRs on main, the repo default branch
- fix(screenshots): merge importing sharp by its default export in both capture suites
- test(integration): merge the bounded vault cleanup and the dead-instance report
- fix(delete-unused): merge keeping an attachment the note text links to, re #89
- fix(rename-by-plugin): merge leaving an unlinked foreign file in place, re #88
- feat(delete-unused): merge the linked, minimizable confirmation, re #87
- fix(settings): merge the expanded Plugins picker, re #86
- test: merge the desktop closure wait sizing
- feat(api): merge the published collectAttachments member
- test: merge the wait-ceiling sizing for the rescue and dependency suites
- test(delete): merge the reporter's second #70 vault layout suite
- fix(delete-unused): an empty note no longer keeps an attachment unit folder alive (re #83 - [BUG] `Delete unused attachments in entire vault` still doesn't delete `attachment unit folders`)
- fix: re #82
- docs: say why every test vault seeds pattern mode now that a fresh install follows Obsidian
- feat(location)!: follow Obsidian by default; switch it off to get ./assets/${noteFileName} back
- feat(collect): receive the collect settings `Consistent Attachments and Links` hands over
- feat(location): follow Obsidian's own attachment location on request
- feat(collect): say when a collect moved nothing, and name the setting that pinned it (re #81 - [BUG] "Collect attachments in current note" function seems to do nothing - v11.11.0)
- docs: replace two labels a reader of this repo cannot resolve
- feat: publish a per-note attachment-folder read API for other plugins
- refactor: read the attachment-unit-folder designation through the library
- feat: exempt chosen attachment file types from the multiple notes check (re #80 - [FR] Allow excluding specific attachment extensions from the multiple-notes check)
- feat: give Collect attachments a destination of its own (re #78 - [FR] Allow Collect attachments to use a separate destination from new attachments)
- docs(agents): find the handler's dialogs by title, not by a bare modal lookup
- test(rescue): accept issue #71's tie dialog with both real plugins on one vault
- fix(deps): float devalue to 5.9.4, clearing GHSA-9rgm-9g3h-6x36
- chore(deps): drop the dead markdown-it override
- chore(deps): drop the dead js-yaml override
- fix(deps): override smol-toml to clear a denial-of-service advisory
- docs: replace the private rule-id citations with what they assert
- test: run the mobile file-drawer retry from Node, so its own diagnostic can fire
- docs: name the library and the sibling plugins so a reader can resolve them
- docs: replace the private tracker references with what they pointed at
- test: bring eight in-closure wait ceilings under the transport's per-eval cap
- feat!: require `Advanced Rename and Delete Handler` instead of suggesting it (re #84 - [FR] Stop notification for `Advanced rename and delete handler` from appearing)
- feat: warn about the `Consistent Attachments and Links` collecting overlap

## 12.0.1

- test: cover the three unused-attachments-remover paths the gate was short on
- chore: bring the lockfile up to the obsidian-dev-utils floor it now declares
- refactor: replace the hand-rolled settings-migration copy with the shared component
- docs: say where the debug command is run
- refactor(modals): take the input-spellcheck rule from obsidian-dev-utils
- docs: name the unversioned demo-vault asset and the folder it unzips into
- chore: make the LICENSE copyright line lintable and guard it against the year roll-over
- test(test-mocks): stop replacing the plugin registry, and sweep the dependencies
- test(unit-folder-rescue): prove issue #70 fixed with both real plugins on one vault
- feat(ownerless-attachments): reach attachment folders whose owning note is gone
- chore(deps): move to obsidian-dev-utils 101 and obsidian-test-mocks 5
- refactor(move-to-proper-folder): drop the `this` alias the directory review flags
- feat(rename-by-plugin): scope the foreign-attachment rename to named plugins (re #77 - [FR] Setting to only `include` defined plugins for renames)

## 12.0.0

- feat(rename-delete)!: hand rename and delete over to `Advanced Rename and Delete Handler`
- feat(collect): name the higher-priority notes when collecting from an outranked note (re #75 - [FR] Show a higher priority notification when `collect attachments in current note` is triggered on a note of lower priority)
- feat(note-priority): report only the notes tying for the highest rank (re #74 - [FR] A lower priority item should not appear on the notification box, when there is ambiguity in collection)
- feat(collect): stay quiet when the priority winner already holds the attachment (re #73 - [FR] `Multiple notes` notification box should not appear when triggering `collect attachments in current file`, when all notes have different priorities)
- feat: re #72
- feat(attachment-unit-folder): publish the unit folder designation on the vault (re #70 - [BUG] Delete Interception doesn't work with `Attachment Unit Folders`)
- fix: re #69
- fix(build): wire build:compile to buildCompile and drop the duplicate leaf script

## 11.11.0

- style: satisfy capitalized-comments in the new tests
- test(navigation): cover the three gaps blocking the coverage gate
- style: exempt an aliased import from perfectionist sorting
- style: reformat after the dprint bump
- chore(deps): sweep caret-ranged dependencies to latest
- fix(deps): move to obsidian-integration-testing 11 and obsidian-dev-utils 96.5.2
- fix(deps): drop the brace-expansion file: override that breaks a clean install
- feat(navigation): add commands to jump between a note and its attachments
- test(plugin): cover the Notebook Navigator layout-ready path

## 11.10.0

- style(test): fix comment indentation in the attachment-rescue suite
- fix(test): make the desktop integration suite deterministic
- docs(test): repoint the bottleneck suite's header comment, which named a file this repo does not have
- fix(vitest): restore the performance project's global setup and CDP timeout
- fix: re mnaoumov/obsidian-advanced-note-composer#259
- fix(settings): point plugin-directory links at community.obsidian.md
- feat: re #68

## 11.9.0

- fix(test): reword a comment cspell rejects
- fix(test): wait for the relocation to settle, not merely to start (#65)
- fix(delete-unused-attachments): stop showing a progress bar for a single note
- feat(commands): delete unused attachments across the entire vault (#64)
- docs(demo-vault): explain why an image pasted into a drawing is left alone (#65)
- feat(tokens): add title case and whitespace collapsing to the string format (#59)
- docs(demo-vault): show what deleting a note or its folder does to a shared attachment (#67)
- feat(collect): say why the priority list left a shared attachment behind (#66)
- docs(demo-vault): unwrap the notes so Obsidian stops rendering a break per line
- chore(cspell): teach the dictionary Obsidian's `offref`
- docs(readme): render the same in Obsidian's plugin page as on GitHub
- fix(rename): stop a concurrent edit orphaning a moved note's embeds (re #60 - The image link is not updated)
- chore: lint

## 11.8.0

- style: format the locale files
- feat(prompt): focus the input, name the heading, and catch foreign attachments (#59)

## 11.7.0

- chore: update libs
- feat(attachment-rescue): rescue a still-referenced attachment from a deletion (#57)
- chore: update libs
- refactor(attachment-unit-folder): take the rule from obsidian-dev-utils
- feat(jpeg): keep the image's metadata across the conversion, behind a setting (#55)
- chore: update obsidian-dev-utils to 94.6.1
- chore: update obsidian-dev-utils to 94.6.0
- fix: override deepmerge-ts to clear GHSA-ggr8-5vv4-36mx
- feat(plugin): expose collecting a specific note's attachments to other plugins
- feat(collect): let a priority list decide which note owns a shared attachment (#57)
- feat(collect): treat designated folders as one attachment so the whole tree travels (#56)
- test: gate the demo vault by clicking every code button
- chore: teach cspell the advisory wording
- chore: update libs
- docs(demo-vault): make the token patterns inspectable
- docs: add store screenshots and surface them in the README

## 11.6.5

- docs(demo-vault): use NATO placeholders instead of foo, bar and baz

## 11.6.4

- docs: make the demo vault the documentation, in the standard layout
- feat(demo-vault): migrate to obsidian-dev-utils 93.3.1 and adopt the authoring convention

## 11.6.3

- chore: update libs and adopt obsidian-integration-testing 10

## 11.6.2

- fix: re #50
- fix: re #50

## 11.6.1

- chore: update libs
- test: un-skip the #47 and #49 reproductions, now green on obsidian-dev-utils 89 (re #47, re #49)
- test: re #49
- test: re #47
- chore: update libs
- refactor(prism): register the tokenized-string language through obsidian-dev-utils' SyntaxHighlightingComponent
- chore(vitest): consume the shared vitest configuration and collapse the desktop-only suites

## 11.6.0

- test(settings): exercise the custom-tokens row teardown
- refactor: replace the deprecated setWarning with setDestructive
- refactor(settings): move the settings tab onto the declarative settings API
- chore: update libs and clear the npm audit
- docs: fix the demo vault download instructions

## 11.5.0

- feat: show a progress notice while a rename updates backlinks (re #25)
- chore: update libs
- feat: add opt-in raw-path safety scan for collecting attachments (re #46)
- feat: add Delete unused attachments" command and menu item (re #23)

## 11.4.0

- docs: demo link-display-text setting (re #24)
- test: behavioral integration tests for obsidian-dev-utils 88.2.0 canvas/alias fixes + clipboard/link-display
- chore: update libs
- fix: re #16
- fix: re #26
- feat: re #24
- fix: re #31
- fix: re #29

## 11.3.0

- test: add desktop integration test for issue #33 collect exclusion
- feat: re #33

## 11.2.6

- fix: re #34

## 11.2.5

- fix: re #35

## 11.2.4

- chore: update libs
- chore: update libs

## 11.2.3

- chore: update libs

## 11.2.2

- chore: update libs
- chore(demo-vault): drop committed Invocables placeholder
- fix(demo-vault): export invoke() from startup script; add Invocables folder

## 11.2.1

- docs: standardize demo-vault README
- docs: drop per-plugin demo-vault setup notes (bootstrap covered by the obsidian-dev-utils harness)
- docs: unnumber demo-vault setup notes
- docs(demo-vault): create the `Custom Attachment Location` demo vault

## 11.2.0

- feat: re #28
- perf: single-pass cursor-line + sequence-number resolution
- fix: re #38

## 11.1.1

- chore: update libs
- chore: update obsidian-dev-utils to 85.0.0
- refactor: pass params objects to attachment path, maps and modal helpers
- build: lock typescript to 6.0.3

## 11.1.0

- feat: re #42
- test: wire integration-testing vitest-setup into integration projects
- chore: update libs
- chore: sort tsconfig types

## 11.0.0

- perf!: read attachment content lazily during path resolution

## 10.3.8

- refactor: new template

## 10.3.7

- chore: update version script
- fix: $(noteFileCreationDate) re <https://github.com/mnaoumov/obsidian-custom-attachment-location/issues/21>
- chore: update libs

## 10.3.6

- chore: update libs

## 10.3.5

- chore: update template

## 10.3.4

- chore: update template

## 10.3.3

- feat: safer trashing

## 10.3.2

- chore: lint
- chore: update libs re #19

## 10.3.1

- fix: sequenceNumber re #13

## 10.3.0

- feat: extract localizations
- feat: reorder settings re #10

## 10.2.1

- chore: update libs re #11

## 10.2.0

- refactor: path settings re #12

## 10.1.0

- fix: rename emptyFolderBehavior

## 10.0.4

- chore: update libs

## 10.0.3

- fix: comparison with unset version re <https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/261>

## 10.0.2

- fix: hyphens token re #8

## 10.0.1

- fix: update links to the new repo re #5

## 10.0.0

- docs: cleanup
- chore: update libs
- docs: simplify default
- feat: defaultValueTemplate re #1
- fix: prism
- fix: parser
- fix: replace legacy format strings
- feat: add release notes
- feat: update sample tokens
- feat: rewrite prism
- feat: add parser
- feat: don't check for prompt token
- feat: refactor token formats
- docs: update formats
- docs: replace with (no format)
- docs: add attributions

## 9.26.4

- chore: republish

## 9.26.3

- chore: republish

## 9.26.2

- docs: change attribution

## 9.26.1

- fix: add reference to `Backlink Cache` re #235
- chore: update libs

## 9.26.0

- feat: convert images to jpeg re #258

## 9.25.0

- feat: visualize whitespace in replacement setting re #232
- chore: update libs

## 9.24.0

- feat: increase JPEG quality choices re #236

## 9.23.3

- docs: improve description re #238

## 9.23.2

- fix: handle . and .. templates re #239

## 9.23.1

- feat: improve description re <https://github.com/dy-sh/obsidian-consistent-attachments-and-links/issues/144>

## 9.23.0

- feat: add links to attachment/notes re #256
- chore: update libs

## 9.22.0

- feat: add modal for MoveAttachmentToProperFolder
- feat: check for duplicates even if attachment is already in place re #257

## 9.21.0

- feat: add shouldHandleRenames re #251

## 9.20.0

- chore: lint
- fix: hide notice on cancel re #252
- feat: add cancel mode re #234
- chore: update libs

## 9.19.0

- feat: move attachment to proper folder re #253
- feat: allow select multiple notes/folder to collect
- fix: missed localization

## 9.18.5

- chore: update libs re #254
- chore: fix electron version, same as in typings

## 9.18.4

- chore: update libs

## 9.18.3

- fix: don't interrupt on timeout re #243

## 9.18.2

- fix: attachment paths for excalidraw re #249

## 9.18.1

- fix: change link on copied collected attachment re #250
- chore: update libs

## 9.18.0

- feat: add individual rename/collect name settings
- feat: add ${sequenceNumber} token re #247

## 9.17.17

- fix: show version mismatch alert only once. re #246

## 9.17.16

- chore: update libs

## 9.17.15

- chore: update libs

## 9.17.14

- fix: handling include/exclude paths not ending with /

## 9.17.13

- chore: update libs

## 9.17.12

- fix: compilation
- chore: update libs

## 9.17.11

- chore: update libs

## 9.17.10

- chore: update libs
  - fix #231

## 9.17.9

- chore: update libs

## 9.17.8

- fix: preserve settings cursor position

## 9.17.7

- fix: proper space replacement

## 9.17.6

- fix: properly handle unicode chars
  - fix #229

## 9.17.5

- fix: properly resolve empty folders

## 9.17.4

- fix: init cursor line to extract headings
  - fix: #228
- chore: update libs
- chore: enable markdownlint

## 9.17.3

- chore: update libs

## 9.17.2

- fix: build
- chore: update libs

## 9.17.1

- chore: enable conventional commits

## 9.17.0

- Add default image size (#224)

## 9.16.5

- Update libs (#223)

## 9.16.4

- Update libs (#222)

## 9.16.3

- Simplify AttachmentCollector as links already handled by Rename handler (#221)
- Ensure MetadataDeleted processed before queue (#220)

## 9.16.2

- Don't hide Notice until done
- Collect each attachment once (#219)

## 9.16.1

- Update libs (#217)
- Improve default placeholders

## 9.16.0

- Add all translations
- Validate plugin version
- Warn about special characters change
- Add missing i18n
- Replace special characters in headings
- Don't mix empty and default setting UI

## 9.15.8

- Ensure frontmatter links headings are not used

## 9.15.7

- Substitute headings on collect (#214)

## 9.15.6

- Clarify term `pasted image` (#215)

## 9.15.5

- Fix enum binding (#213)

## 9.15.4

- Minor changes

## 9.15.3

- Fix infinite rename (#211)

## 9.15.2

- Additional check for dummy path (#210)

## 9.15.1

- Fix root folder

## 9.15.0

- Add oldNoteFile* tokens

## 9.14.0

- Pass ActionContext

## 9.13.5

- Minor changes

## 9.13.4

- Minor changes

## 9.13.3

- Reuse base i18n

## 9.13.2

- Rename back

## 9.13.1

- Localize unhandledError

## 9.13.0

- Add Chinese translation (#201)

## 9.12.0

- Fix paths with trailing spaces and dots (#204)

## 9.11.1

- #206

## 9.11.0

- Add timeout setting (#203)

## 9.10.6

- Minor changes

## 9.10.5

- Fix uninitialized stats on rename
- Fix #202

## 9.10.4

- More accurate file changes

## 9.10.3

- Minor changes

## 9.10.2

- Register patch without using temp files (#199)

## 9.10.1

- Fix closing active note on load
  - fix: <https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/199#issuecomment-3241586013>

## 9.10.0

- Add default=empty, default=now

## 9.9.1

- Truncate time

## 9.9.0

- Don't add extra new lines (#196)
- Improve description
- Pass content and stats to every substitutions
- Copy original times when creating attachments

## 9.8.1

- Minor changes

## 9.8.0

- originalAttachmentFileCreationDate / originalAttachmentFileModificationDate

## 9.7.1

- Prevent double prompt (#196)

## 9.7.0

- Allow generated file names with slash (#195)

## 9.6.0

- Insert shared text into cursor position (#196)

## 9.5.1

- Minor changes

## 9.5.0

- Restore shouldRenameAttachmentFiles

## 9.4.0

- Add shouldSkipDuplicateCheck

## 9.3.0

- Generate name in getAvailablePathForAttachments
- Move shouldRenameAttachments

## 9.2.2

- Minor changes

## 9.2.1

- Rephrase
- Add link to use cases

## 9.2.0

- Add warning with link
- Add warning to README

## 9.1.0

- Add obsidian to context

## 9.0.8

- getOsUnsafePathCharsRegExp

## 9.0.7

- Use platform-specific getInvalidFileNamePathCharsRegExp (#189)
- More abort signals

## 9.0.6

- Minor changes

## 9.0.5

- removeUndefinedProperties (#186, #188)
- Refactor abortSignal  (#186, #188)

## 9.0.4

- Revalidate tokens after debouncing

## 9.0.3

- Prevent infinite update loop
- Revalidate settings after registering tokens

## 9.0.2

- Register custom tokens on startup (#187)

## 9.0.1

- Don't timeout on collecting in prompt mode
- Prevent image/video overflow

## 9.0.0

- Highlight token
- Improve validation message
- Add formats for prompt
- Deprecate shouldRenameAttachmentsToLowerCase
- Add preview (#184)

## 8.8.2

- Don't use new API (#181)

## 8.8.1

- Prevent infinite loop in prompt

## 8.8.0

- Custom token from heading where the attachment is (#183)
- Trim end whitespaces
- Clean validation
- Improve validation
- Add heading variables

## 8.7.0

- Rename share files (#181)

## 8.6.0

- Validate formats
- Allow multi-format for syntax highlighting
- Add indexFromStart/indexFromEnd

## 8.5.2

- Minor changes

## 8.5.1

- Minor changes

## 8.5.0

- Add choice for CollectAttachmentUsedByMultipleNotesMode
- Reformat settings tab

## 8.4.2

- Add base examples
- Add more logging

## 8.4.1

- Minor changes

## 8.4.0

- generatedAttachmentFileName/generatedAttachmentFilePath
- Fix outdated descriptions

## 8.3.1

- Properly exclude paths (Fixes #175)

## 8.3.0

- Add left/right formatting (fixes #174)

## 8.2.2

- Update libs (#170)

## 8.2.1

- Replace legacy tokens in markdownUrlFormat

## 8.2.0

- Round size to decimal points

## 8.1.0

- \[FR\] Slugify as an option (#167)
- Refactor random
- Upper, lower, slugify file/folder names

## 8.0.2

- Update renamed token

## 8.0.1

- Fix warning condition

## 8.0.0

- \[FR\] File Size (#168)
- Add attachmentFileSize
- Rename tokens

## 7.11.0

- Fix the lib version
- Update libs (Fixes #169)

## 7.10.0

- Add toggle for avoiding attachment duplication during collection. #166 (by @Accelsnow)

## 7.9.0

- Exclude paths from attachment collecting

## 7.8.2

- Ensure attachment folder is updated on rename

## 7.8.1

- Fix build

## 7.8.0

- Update attachmentFolderPath on opening file

## 7.7.6

- Minor changes

## 7.7.5

- Minor changes

## 7.7.4

- Minor changes

## 7.7.3

- Properly handle sequential special characters

## 7.7.2

- Minor changes

## 7.7.1

- Reset default url format

## 7.7.0

- Modify url generation not faking the file instances
- Add markdown URL format customization #152 (thanks to @Kamesuta)

## 7.6.1

- Minor changes

## 7.6.0

- Fix size
- Add placeholder
- Fix compilation

## 7.5.0

- Switch to EmptyAttachmentFolderBehavior

## 7.4.3

- Minor changes

## 7.4.2

- Improve performance

## 7.4.1

- Minor changes

## 7.4.0

- Add Treat as attachment extensions.
- Support .md Attachments (#147)

## 7.3.0

- Add settings code highlighting

## 7.2.6

- Minor changes

## 7.2.5

- Pass original file name with extension

## 7.2.4

- Minor changes

## 7.2.3

- Minor changes

## 7.2.2

- Minor changes

## 7.2.1

- New template

## 7.2.0

- Show progress bar

## 7.1.0

- Replace special characters

## 7.0.5

- Minor changes

## 7.0.4

- Minor changes

## 7.0.3

- Minor changes

## 7.0.2

- Minor changes

## 7.0.1

- Minor changes

## 7.0.0

- Allow call fillTemplate() from custom token
- Add include/exclude settings

## 6.0.2

- Minor changes

## 6.0.1

- Update template

## 6.0.0

- Refactor to support insert attachment
- Rename settings

## 5.1.7

- Paste in input/textarea

## 5.1.6

- Lint

## 5.1.5

- Format

## 5.1.4

- Minor changes

## 5.1.3

- Minor changes

## 5.1.2

- Minor changes

## 5.1.1

- Minor changes

## 5.1.0

- Show visible whitespace

## 5.0.2

- Validate separator

## 5.0.1

- Pass attachment filename

## 5.0.0

- Add custom tokens
- Add frontmatter formatter
- Validate path after applying tokens
- Add fileCreationDate/fileModificationDate
- Handle ../ paths
- Add randoms and uuid
- Add originalCopiedFileExtension
- Don't allow tokens in prompt
- Allow root path
- Allow leading and trailing /
- Allow . and ..

## 4.31.1

- Respect renameOnlyImages when collecting

## 4.31.0

- Enable custom whitespace replacement
- Handle raw link

## 4.30.6

- Minor changes

## 4.30.5

- Minor changes

## 4.30.4

- Minor changes

## 4.30.3

- Minor changes

## 4.30.2

- Minor changes

## 4.30.1

- Refactor loop

## 4.30.0

- Remove date selector
- Refactor templating

## 4.29.1

- Minor changes

## 4.29.0

- Use image-override to be compatible with `Paste Mode` plugin
- Fix check for pasted image

## 4.28.5

- Minor changes

## 4.28.4

- Update libs - fixes mobile build

## 4.28.3

- Avoid default exports

## 4.28.2

- Minor changes

## 4.28.1

- Check for missing webUtils (Electron < 29)

## 4.28.0

- Fix passing path in new Electron

## 4.27.6

- Minor changes

## 4.27.5

- Minor changes

## 4.27.4

- Minor changes

## 4.27.3

- Minor changes

## 4.27.2

- Minor changes

## 4.27.1

- Refactor

## 4.27.0

- Allow paste in link editing textbox

## 4.26.0

- Don't fail on broken canvas

## 4.25.0

- Add support for frontmatter links

## 4.24.0

- Support multi-window

## 4.23.2

- Minor changes

## 4.23.1

- Minor changes

## 4.23.0

- Refactor

## 4.22.1

- Refactor

## 4.22.0

- Replace whitespace on drop
- Fix relative path resolution
- Handle duplicates
- Fix stat for mobile

## 4.21.0

- Fix race condition

## 4.20.0

- Init all settings

## 4.19.0

- Don't remove folders with hidden files

## 4.18.0

- Add `Delete orphan attachments` setting

## 4.17.0

- Remove to trash

## 4.16.0

- Preserve angle brackets and leading dot

## 4.15.0

- Reuse `RenameDeleteHandler`
- Add optional `skipFolderCreation` to `getAvailablePathForAttachments`

## 4.14.0

- Proper integration with `Better Markdown Links`

## 4.13.0

- Handle special renames

## 4.12.2

- Fix jpegQuality dropdown binding

## 4.12.1

- Add extension

## 4.12.0

- Add `Rename attachments on collecting` setting

## 4.11.0

- Show warning
- Fix build

## 4.10.0

- Fix settings saving
- Allow dot-folders
- Fix mobile loading
- Fix backlinks race condition
- Process attachments before note

## 4.9.4

- Handle removed parent folder case
- Rename attachments before changing links

## 4.9.3

- Fix backlink check
- Check for race conditions

## 4.9.2

- Fix options merging

## 4.9.1

- Fix related attachments notice

## 4.9.0

- Don't create fake file.

## 4.8.0

- Don't create duplicates when dragging vault files

## 4.7.0

- Skip paste handler in metadata editor

## 4.6.0

- Fix race condition

## 4.5.0

- Ensure `getAvailablePathForAttachments` creates missing folder

## 4.4.0

- Fix race conditions

## 4.3.3

- Bugfixes

## 4.3.2

- Fix double paste

## 4.3.1

- Create attachment folders on paste/drop

## 4.3.0

- Create attachment folder only when it is needed

## 4.2.1

- Fix build

## 4.2.0

- Add `Rename only images` setting

## 4.1.0

- Generate links exactly as Obsidian does

## 4.0.0

- Disable Obsidian's built-in way to update links
- Add commands and buttons to collect attachments

## 3.8.0

- Improve checks for target type

## 3.7.0

- Add `Rename pasted files with known names` setting

## 3.6.0

- Handle move, not only rename
- Add `Keep empty attachment folders` setting

## 3.5.0

- Preserve draggable on redrop

## 3.4.0

- Handle rename/delete for canvas

## 3.3.0

- Add `${foldername}` and `${folderPath}`

## 3.2.0

- Configure `Duplicate name separator`

## 3.1.0

- Add canvas support

## 3.0.0

- Don't modify `attachmentFolderPath` setting

## 2.1.0

- Configure drag&drop as paste behavior
- Remove extra dot before jpg
- Add support for `${prompt}`

## 2.0.0

- Make universal paste/drop

## 1.3.1

- Bugfixes

## 1.3.0

- Substitute `${originalCopiedFilename}`

## 1.2.0

- Bugfixes

## 1.1.0

- Bugfixes

## 1.0.3

- Remove unused attachment folder

## 1.0.2

- Forbid backslashes

## 1.0.1

- Add settings validation

## 1.0.0

- Fix README.md template example to prevent inappropriate latex rendering by @kaiiiz in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/28>
- Handle pasting multiple images by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/58>
- Support date var template(moment.js) in folder path & image name by @Harrd in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/56>
- Add mobile support by @mengbo in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/44>
- Add name sanitization when creating folder. by @EricWiener in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/35>
- Feature: Compress images from png to jpeg while pasting from the clipboard by @kaiiiz in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/29>

## 0.0.9

- Update attachment folder config when note renamed by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/26>

## 0.0.8

- Move attachments when note is moved by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/21>
- Make attachment folder setting modified every time file opens by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/23>

## 0.0.7

- Fixed minor typo in the settings by @astrodad in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/10>
- Temporarily fix Drag-n-Drop file from explorer doesn't copy file to obsidian vault.

## 0.0.6

- Add support for absolute path and relative path.
- Add options for auto renaming.

## 0.0.5

- Add support for drop event
- Fix typos & grammar by @TypicalHog in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/2>

## 0.0.4

- Optimize code

## 0.0.3

- Add setting tabs and fix bugs.

## 0.0.2

- Add support for custom pasted image filename.

## 0.0.1

- Initial release
