# CHANGELOG

## 17.4.0

- docs(original-attachment-names): say a folder move keeps the original, and how to remove it
- feat(settings): templates by operation, one page per operation
- fix(settings): render tokens in setting descriptions as code
- fix(original-attachment-names): follow a moved history folder instead of recreating it
- test(original-attachment-names): drop the synthetic link menu on Android now that the long press retries
- docs(changelog): regroup the published release notes for readers

## 17.3.0

This release has 3 new features, 4 fixes and 1 documentation change. 6 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **attachments:** per-operation folder and file name templates for new attachments
- **rename-attachments:** rename a note's attachments in place with a template of their own
- \[FR\] Make the hardcoded `Plugin data/` folder location configurable (#99)

### Fixed

- **deps:** load at Obsidian startup again, on @mnaoumov/obsidian-lib 10.11.0
- **settings:** let a cleared sidecar extension list disable pairing
- \[BUG\] When using your plugin and syncthing between 2 vaults used by 2 different person, many sync warnings (#102)
- \[FR\] Make the hardcoded `Plugin data/` folder location configurable (#99)

### Documentation

- **original-names:** apply a folder move once, and keep the original anchor

## 17.2.0

This release has 3 new features, 1 fix and 3 documentation changes. 8 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- \[FR\] Make the hardcoded `Plugin data/` folder location configurable (#99)
- store only original attachment names, and drop Copy original path
- fold the link display text toggle into Inserted link text

### Fixed

- clear glob cancellation advisory

### Documentation

- point the sync data folder README at its mnaoumov.dev page
- **demo-vault:** document pluginDataFolder and shouldAllowHiddenPluginDataFolder
- link to the Obsidian resources page

## 17.1.0

This release has 7 new features, 6 fixes, 1 improvement and 6 documentation changes. 14 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- add a Report a bug command
- record bulk commands as `git` commits, so one revert undoes a run
- **sidecars:** pair sidecars in mobile share imports
- synchronize original attachment metadata between devices
- copy original attachment metadata from context menus
- **sidecars:** keep companion names with their base attachments
- add original-name templates for inserted attachment links

### Fixed

- **attachment-saving:** keep the folder on the note a save started from
- patch the clipboard manager when a note opens into the active tab
- **share:** leave a shared Markdown note to core so it keeps its name
- **sidecars:** retire the original sidecar group together after a move
- **sidecars:** keep companions in deletion scans and copies
- **dependency:** ask for an update, not an install, while `Advanced Rename and Delete Handler` 3.0.0 is enabled

### Improved

- answer a burst of attachment-path queries with one walk of the note

### Documentation

- **readme:** point bug reports at the Report a bug command
- add issue-filing instructions for AI agents
- **readme:** combine related resources and plugin comparisons
- **demo-vault:** point the token context link at its new path
- **readme:** cut the README to a landing page and move the plugin API guide to docs
- **readme:** list similar plugins from a prior-art search

## 17.0.0

This release has 1 breaking change, 3 new features, 2 fixes and 8 documentation changes. 6 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### Breaking changes

- **deps:** move to `obsidian-lib` 6 and off the dropped `obsidian-dev-utils` names

### New

- offer every Total Commander checksum in {{attachmentFileHash}}
- add {{attachmentFileHash}} token naming attachments by a content hash
- **tokens:** merge remembering each attachment's arrival name for {{originalAttachmentFileName}}

### Fixed

- show the CSV copied notice with the plugin header
- drop the plugin name from notice text

### Documentation

- **demo-vault:** split the token reference into one note per token
- name `obsidian-lib` where comments said dev-utils
- point a leftover `obsidian-dev-utils` pin reason at the packages in the tree now
- shorten the debugging section
- **changelog:** escape the issue-title tags so `markdownlint` and `cspell` pass
- **changelog:** name the issue each released entry resolved
- **readme:** lead the Debugging section with `Advanced Debug Mode`
- **changelog:** merge adding the 16.0.0 path-settings migration note

## 16.0.0

- feat(settings)!: merge taking `obsidian-lib` 5.0.0 path settings with globs and case-insensitive matching (re #98 - Exclude file extensions (e.g. .mdenc) from Collect attachments)
- docs: mark plugin names as code
- fix(tokens): merge registering custom tokens whenever the settings are validated

Migration: every entry in a path list (attachment unit folders, the two exclude lists, the orphan-scan paths) now matches case-insensitively. An unescaped `*`, `?` or `[` makes an entry a glob (`*.pdf`, `Archive/**/*.png`, `*_files/`), so a plain path that holds one of those characters literally must escape it (`Notes \[old\]`). An entry shaped `/pattern/flags` is a regular expression whose flags are honoured; an unknown flag is reported as invalid.

## 15.1.1

This release has 4 fixes and 5 documentation changes. 8 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### Fixed

- **paste:** merge renaming every pasted image file again under Only pasted images (re #97 - \[BUG\] The newly uploaded attachment was not renamed.)
- **attachments:** merge replacing special characters in a name a new attachment keeps
- **collect:** merge collecting after a note is moved outside Obsidian
- **paste:** merge no longer force-loading a deferred markdown tab at startup

### Documentation

- **api:** merge naming the validation debug switch in the contract
- **agents:** merge saying how a demo-vault Try it promise is asserted
- **demo-vault:** merge giving every Try it a button for its setup and steps
- **tokens:** merge a custom-token example that renames only images (<https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/226>)
- **settings:** say the Markdown URL format applies only when an attachment is added (#182)

## 15.1.0

This release has 3 new features. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **paste:** merge telling screenshot files apart from real files in Only pasted images
- **collect:** merge an opt-in setting that merges byte-identical attachments
- **dependency:** merge requiring `Advanced Rename and Delete Handler` 2.2.0 or later

## 15.0.0

- feat(api)!: merge removing the vault graft; use the API's getAvailablePathForAttachments and isAttachmentUnitFolder
  - BREAKING: `app.vault.getAvailablePathForAttachments.extended` is removed. Use the plugin API's `getAvailablePathForAttachments` (contract `1.3.0`).
  - BREAKING: `app.vault.getAvailablePathForAttachments.checkIsAttachmentUnitFolder` is removed. Use the plugin API's `isAttachmentUnitFolder` (contract `1.3.0`).
  - `obsidian-dev-utils` 107.4.1 and older read these members; `@mnaoumov/obsidian-lib` 2.0.0 and later read the plugin API.
  - `Advanced Rename and Delete Handler` needs 2.2.0 or later to keep an attachment unit folder whole when it rescues attachments out of a deleted folder.
- test: merge seeding `Advanced Rename and Delete Handler` 2.2.1, which reads the designation through the API
- build(demo-vault): merge requiring `CodeScript Toolkit` 13.8.0 for the `obsidian-lib` demo script
- fix(ui): merge marking the plugin names in the dependency reason as code
- refactor(demo-vault): merge importing the community-plugin helpers from @mnaoumov/obsidian-lib

## 14.2.0

This release has 3 new features. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **api:** merge taking `Advanced Rename and Delete Handler`'s own contract, with full schemas
- **api:** merge the copyable api-contract.ts with full schemas
- **ui:** merge marking plugin names as code in UI, markdown and comments

## 14.1.0

This release has 1 new feature. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **api:** merge publishing the attachment-path resolver and the unit-folder check

## 14.0.3

This release has 1 fix.

### Fixed

- merge updating `obsidian-dev-utils` to 107.4.1 (re #95 - \[BUG\] Global CSS leak via `body button:not(.clickable-icon)` breaks button text and icons in other plugins)

## 14.0.2

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 14.0.1

This release has 2 fixes, 1 documentation change and 1 other change. 4 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### Fixed

- **external-attachments:** merge leaving a note's auto-export where it is written (#92)
- **release-notes:** merge naming the plugin in the release notes popup

### Documentation

- **external-attachments:** merge saying an image pasted into a drawing is `Excalidraw`'s write

### Other changes

- leave no special case for a note's auto-export (#92)

## 14.0.0

**Breaking: the token syntax moved from `${...}` to `{{...}}`.** Tokens are now written `{{noteFileName}}`, and a token with a format takes `{{token:format}}`, for example `{{date:YYYY-MM-DD}}`. The `${token}` and `${token:{...}}` forms no longer parse.

Upgrading from `${...}`: your saved patterns are rewritten to `{{...}}` automatically the first time 14.0.0 loads. Your custom tokens code is JavaScript you wrote, so it is left as it is: a `ctx.fillTemplate('${noteFileName}')` in it fails with an error naming the `{{noteFileName}}` that replaces it, rather than silently producing a wrong name. The demo vault's `03 Tokens and patterns` note has the full token reference.

- refactor(settings): merge stating that the legacy file-name pattern is never absent
- docs(settings): merge spelling behavior the US way so the spellcheck gate passes
- refactor(settings): merge dropping the loadFromFile override the `obsidian-dev-utils` base now covers
- test(integration): merge naming the empty-folder cleanup race behind Failed to parse path
- feat(settings): merge recognizing a drawing by its excalidraw-plugin property through the handler (#90)
- test(screenshots): merge capturing the desktop frames without the editor caret
- test(screenshots): merge pinning the clock the store captures read
- refactor(settings): merge dropping the anchored placeholder override
- docs(agents): merge noting the capture suites as the one writer of the handler record
- chore(deps): merge the dependency sweep onto `obsidian-integration-testing` 17 and the re-shot store frames
- refactor(settings): merge dropping the private-field onSavingRecord override on `obsidian-dev-utils` 107
- refactor(styles): merge dropping the local multiple-dropdown rule on `obsidian-dev-utils` 107 (#86)
- feat(external-attachments): merge renaming an image pasted into an `Excalidraw` drawing (#65)
- test(coverage): merge covering the branches the `obsidian-test-mocks` 7 float left uncovered
- test(delete-unused): merge pinning that the images a drawing shows are backlinks
- refactor(tokens): merge keeping parseFormatObject file-local
- test(integration): merge editing settings through editAndSave in every desktop suite
- fix(tokens): merge registering the stored custom tokens when enabled after layout-ready
- chore(deps): merge floating `obsidian-test-mocks` to ^7.0.0
- docs(demo-vault): merge stating what skipping a drawing costs the delete-unused sweep
- docs(readme): merge linking both cross-plugin API guides
- fix: merge moving an attachment used by a single note to its proper folder
- style(comments): merge lowercasing the wrapped-comment continuation lines
- test(api): merge the per-note suite's editAndSave settings seam
- refactor(settings): merge showing the overlap banner row through a visible predicate
- feat!: merge the move to the {{token:format}} syntax
- build(lint): merge turning on no-soft-break-in-paragraph
- refactor: merge dropping the local command disposal the base now makes redundant
- chore(deps): merge raising `obsidian-dev-utils` to 106 and `obsidian-integration-testing` to 16
- test(demo-vault): merge installing `CodeScript Toolkit` headlessly when it is missing
- chore: merge adopting the `npm` run gate branch gate
- fix(settings): merge stopping every settings load from rewriting data.json
- fix(deps): merge restoring the lockfile's missing resolved and integrity fields
- fix: merge never sweeping a drawing as a note for unused attachments
- fix: merge giving a drawing treated as an attachment its base name as link text

## 13.0.0

This release has 2 breaking changes, 9 new features, 9 fixes and 8 documentation changes. 12 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### Breaking changes

- **location:** follow Obsidian by default; switch it off to get ./assets/${noteFileName} back
- require `Advanced Rename and Delete Handler` instead of suggesting it (re #84 - \[FR\] Stop notification for `Advanced rename and delete handler` from appearing)

### New

- **delete-unused:** merge the linked, minimizable confirmation, re #87
- **api:** merge the published collectAttachments member
- **collect:** receive the collect settings `Consistent Attachments and Links` hands over
- **location:** follow Obsidian's own attachment location on request
- **collect:** say when a collect moved nothing, and name the setting that pinned it (re #81 - \[BUG\] "Collect attachments in current note" function seems to do nothing - v11.11.0)
- publish a per-note attachment-folder read API for other plugins
- exempt chosen attachment file types from the multiple notes check (re #80 - \[FR\] Allow excluding specific attachment extensions from the multiple-notes check)
- give Collect attachments a destination of its own (re #78 - \[FR\] Allow Collect attachments to use a separate destination from new attachments)
- warn about the `Consistent Attachments and Links` collecting overlap

### Fixed

- merge no longer offering Move attachment to proper folder on a note
- **screenshots:** merge importing sharp by its default export in both capture suites
- **delete-unused:** merge keeping an attachment the note text links to, re #89
- **rename-by-plugin:** merge leaving an unlinked foreign file in place, re #88
- **settings:** merge the expanded Plugins picker, re #86
- **delete-unused:** an empty note no longer keeps an attachment unit folder alive (re #83 - \[BUG\] `Delete unused attachments in entire vault` still doesn't delete `attachment unit folders`)
- \[BUG\] Enabling renaming of attachments created by other plugins duplicates the Markdown (#82)
- **deps:** float devalue to 5.9.4, clearing GHSA-9rgm-9g3h-6x36
- **deps:** override smol-toml to clear a denial-of-service advisory

### Documentation

- **demo-vault:** merge showing the Collect attachments automatically setting
- **contributing:** merge basing PRs on main, the repo default branch
- say why every test vault seeds pattern mode now that a fresh install follows Obsidian
- replace two labels a reader of this repo cannot resolve
- **agents:** find the handler's dialogs by title, not by a bare modal lookup
- replace the private rule-id citations with what they assert
- name the library and the sibling plugins so a reader can resolve them
- replace the private tracker references with what they pointed at

## 12.0.1

This release has 2 new features and 2 documentation changes. 9 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **ownerless-attachments:** reach attachment folders whose owning note is gone
- **rename-by-plugin:** scope the foreign-attachment rename to named plugins (re #77 - \[FR\] Setting to only `include` defined plugins for renames)

### Documentation

- say where the debug command is run
- name the unversioned demo-vault asset and the folder it unzips into

## 12.0.0

This release has 1 breaking change, 5 new features and 2 fixes.

### Breaking changes

- **rename-delete:** hand rename and delete over to `Advanced Rename and Delete Handler`

### New

- **collect:** name the higher-priority notes when collecting from an outranked note (re #75 - \[FR\] Show a higher priority notification when `collect attachments in current note` is triggered on a note of lower priority)
- **note-priority:** report only the notes tying for the highest rank (re #74 - \[FR\] A lower priority item should not appear on the notification box, when there is ambiguity in collection)
- **collect:** stay quiet when the priority winner already holds the attachment (re #73 - \[FR\] `Multiple notes` notification box should not appear when triggering `collect attachments in current file`, when all notes have different priorities)
- \[FR\] Include `Attachment Unit Folders` In `Delete unused attachments in entire vault` (#72)
- **attachment-unit-folder:** publish the unit folder designation on the vault (re #70 - \[BUG\] Delete Interception doesn't work with `Attachment Unit Folders`)

### Fixed

- \[BUG\] Empty attachment folder persists, when an `attachment unit folder` is the last item to be moved (#69)
- **build:** wire build:compile to buildCompile and drop the duplicate leaf script

## 11.11.0

This release has 1 new feature and 2 fixes. 6 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **navigation:** add commands to jump between a note and its attachments

### Fixed

- **deps:** move to `obsidian-integration-testing` 11 and `obsidian-dev-utils` 96.5.2
- **deps:** drop the brace-expansion file: override that breaks a clean install

## 11.10.0

This release has 1 new feature, 4 fixes and 1 documentation change. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### New

- \[FR\] Add clickable headers in settings (#68)

### Fixed

- **test:** make the desktop integration suite deterministic
- **`vitest`:** restore the performance project's global setup and CDP timeout
- re mnaoumov/obsidian-advanced-note-composer#259
- **settings:** point plugin-directory links at community.obsidian.md

### Documentation

- **test:** repoint the bottleneck suite's header comment, which named a file this repo does not have

## 11.9.0

This release has 3 new features, 4 fixes and 4 documentation changes. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **commands:** delete unused attachments across the entire vault (#64)
- **tokens:** add title case and whitespace collapsing to the string format (#59)
- **collect:** say why the priority list left a shared attachment behind (#66)

### Fixed

- **test:** reword a comment `cspell` rejects
- **test:** wait for the relocation to settle, not merely to start (#65)
- **delete-unused-attachments:** stop showing a progress bar for a single note
- **rename:** stop a concurrent edit orphaning a moved note's embeds (re #60 - The image link is not updated)

### Documentation

- **demo-vault:** explain why an image pasted into a drawing is left alone (#65)
- **demo-vault:** show what deleting a note or its folder does to a shared attachment (#67)
- **demo-vault:** unwrap the notes so Obsidian stops rendering a break per line
- **readme:** render the same in Obsidian's plugin page as on `GitHub`

## 11.8.0

This release has 1 new feature. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### New

- **prompt:** focus the input, name the heading, and catch foreign attachments (#59)

## 11.7.0

This release has 5 new features, 1 fix and 2 documentation changes. 8 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- **attachment-rescue:** rescue a still-referenced attachment from a deletion (#57)
- **jpeg:** keep the image's metadata across the conversion, behind a setting (#55)
- **plugin:** expose collecting a specific note's attachments to other plugins
- **collect:** let a priority list decide which note owns a shared attachment (#57)
- **collect:** treat designated folders as one attachment so the whole tree travels (#56)

### Fixed

- override deepmerge-ts to clear GHSA-ggr8-5vv4-36mx

### Documentation

- **demo-vault:** make the token patterns inspectable
- add store screenshots and surface them in the README

## 11.6.5

This release has 1 documentation change.

### Documentation

- **demo-vault:** use NATO placeholders instead of foo, bar and baz

## 11.6.4

This release has 1 new feature and 1 documentation change.

### New

- **demo-vault:** migrate to `obsidian-dev-utils` 93.3.1 and adopt the authoring convention

### Documentation

- make the demo vault the documentation, in the standard layout

## 11.6.3

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 11.6.2

This release has 2 fixes.

### Fixed

- Adopt the two refinements from PR #51 (@lingkai5wu): per-occurrence replacement (#50)
- \[BUG\] Downloaded network images bypass Obsidian's relative link generation (#50)

## 11.6.1

This release has maintenance changes only. 7 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

## 11.6.0

This release has 1 documentation change. 4 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### Documentation

- fix the demo vault download instructions

## 11.5.0

This release has 3 new features. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### New

- show a progress notice while a rename updates backlinks (re #25)
- add opt-in raw-path safety scan for collecting attachments (re #46)
- add Delete unused attachments" command and menu item (re #23)

## 11.4.0

This release has 1 new feature, 4 fixes and 1 documentation change. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- \[FR\] Attachment file name as link description text (#24)

### Fixed

- \[BUG\] iCloud Sync Loop (#16)
- \[BUG\] Empty attachments folder is created automatically (#26)
- \[BUG\] Renaming attachments only works if "Attachment Rename mode" is set to "All" (#31)
- \[BUG\] Cannot write literal string "at" in Generated attachment file name (#29)

### Documentation

- demo link-display-text setting (re #24)

## 11.3.0

This release has 1 new feature. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### New

- Add the `excludePathsFromMultipleNotesCheck` setting. Backlink source (#33)

## 11.2.6

This release has 1 fix.

### Fixed

- collect canvas text-node embed attachments (#34)

## 11.2.5

This release has 1 fix.

### Fixed

- reuse `obsidian-dev-utils` cleanupEmptyFolders after (#35)

## 11.2.4

This release has maintenance changes only. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

## 11.2.3

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 11.2.2

This release has 1 fix. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### Fixed

- **demo-vault:** export invoke() from startup script; add Invocables folder

## 11.2.1

This release has 4 documentation changes.

### Documentation

- standardize demo-vault README
- drop per-plugin demo-vault setup notes (bootstrap covered by the `obsidian-dev-utils` harness)
- unnumber demo-vault setup notes
- **demo-vault:** create the `Custom Attachment Location` demo vault

## 11.2.0

This release has 1 new feature, 1 fix and 1 improvement.

### New

- \[FR\] Let Obsidian handle aspect ratio for (#28)

### Fixed

- \[BUG\] sequenceNumber should ignore (#38)

### Improved

- single-pass cursor-line + sequence-number resolution

## 11.1.1

This release has maintenance changes only. 4 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

## 11.1.0

This release has 1 new feature. 3 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- Download Network Images During Collect Attachments (#42)

## 11.0.0

This release has 1 breaking change.

### Breaking changes

- read attachment content lazily during path resolution

## 10.3.8

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 10.3.7

This release has 1 fix. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### Fixed

- $(noteFileCreationDate) re <https://github.com/mnaoumov/obsidian-custom-attachment-location/issues/21>

## 10.3.6

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 10.3.5

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 10.3.4

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 10.3.3

This release has 1 new feature.

### New

- safer trashing

## 10.3.2

This release has maintenance changes only. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

## 10.3.1

This release has 1 fix.

### Fixed

- sequenceNumber re #13

## 10.3.0

This release has 2 new features.

### New

- extract localizations
- reorder settings re #10

## 10.2.1

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 10.2.0

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 10.1.0

This release has 1 fix.

### Fixed

- rename emptyFolderBehavior

## 10.0.4

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 10.0.3

This release has 1 fix.

### Fixed

- comparison with unset version re <https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/261>

## 10.0.2

This release has 1 fix.

### Fixed

- hyphens token re #8

## 10.0.1

This release has 1 fix.

### Fixed

- update links to the new repo re #5

## 10.0.0

This release has 7 new features, 3 fixes and 5 documentation changes. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### New

- defaultValueTemplate re #1
- add release notes
- update sample tokens
- rewrite prism
- add parser
- don't check for prompt token
- refactor token formats

### Fixed

- prism
- parser
- replace legacy format strings

### Documentation

- cleanup
- simplify default
- update formats
- replace with (no format)
- add attributions

## 9.26.4

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.26.3

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.26.2

This release has 1 documentation change.

### Documentation

- change attribution

## 9.26.1

This release has 1 fix. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### Fixed

- add reference to `Backlink Cache` re #235

## 9.26.0

This release has 1 new feature.

### New

- convert images to jpeg re #258

## 9.25.0

This release has 1 new feature. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### New

- visualize whitespace in replacement setting re #232

## 9.24.0

This release has 1 new feature.

### New

- increase JPEG quality choices re #236

## 9.23.3

This release has 1 documentation change.

### Documentation

- improve description re #238

## 9.23.2

This release has 1 fix.

### Fixed

- handle . and .. templates re #239

## 9.23.1

This release has 1 new feature.

### New

- improve description re <https://github.com/dy-sh/obsidian-consistent-attachments-and-links/issues/144>

## 9.23.0

This release has 1 new feature. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### New

- add links to attachment/notes re #256

## 9.22.0

This release has 2 new features.

### New

- add modal for MoveAttachmentToProperFolder
- check for duplicates even if attachment is already in place re #257

## 9.21.0

This release has 1 new feature.

### New

- add shouldHandleRenames re #251

## 9.20.0

This release has 1 new feature and 1 fix. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

### New

- add cancel mode re #234

### Fixed

- hide notice on cancel re #252

## 9.19.0

This release has 2 new features and 1 fix.

### New

- move attachment to proper folder re #253
- allow select multiple notes/folder to collect

### Fixed

- missed localization

## 9.18.5

This release has maintenance changes only. 2 maintenance commits (tests, build, CI, refactoring, dependencies) are not listed.

## 9.18.4

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.18.3

This release has 1 fix.

### Fixed

- don't interrupt on timeout re #243

## 9.18.2

This release has 1 fix.

### Fixed

- attachment paths for excalidraw re #249

## 9.18.1

This release has 1 fix. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### Fixed

- change link on copied collected attachment re #250

## 9.18.0

This release has 2 new features.

### New

- add individual rename/collect name settings
- add ${sequenceNumber} token re #247

## 9.17.17

This release has 1 fix.

### Fixed

- show version mismatch alert only once. re #246

## 9.17.16

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.17.15

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.17.14

This release has 1 fix.

### Fixed

- handling include/exclude paths not ending with /

## 9.17.13

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.17.12

This release has 1 fix. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### Fixed

- compilation

## 9.17.11

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.17.10

- chore: update libs
  - fix #231

## 9.17.9

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.17.8

This release has 1 fix.

### Fixed

- preserve settings cursor position

## 9.17.7

This release has 1 fix.

### Fixed

- proper space replacement

## 9.17.6

- fix: properly handle unicode chars
  - fix #229

## 9.17.5

This release has 1 fix.

### Fixed

- properly resolve empty folders

## 9.17.4

- fix: init cursor line to extract headings
  - fix: #228
- chore: update libs
- chore: enable `markdownlint`

## 9.17.3

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.17.2

This release has 1 fix. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

### Fixed

- build

## 9.17.1

This release has maintenance changes only. 1 maintenance commit (tests, build, CI, refactoring, dependencies) is not listed.

## 9.17.0

This release has 1 other change.

### Other changes

- Add default image size (#224)

## 9.16.5

This release has 1 other change.

### Other changes

- Update libs (#223)

## 9.16.4

This release has 1 other change.

### Other changes

- Update libs (#222)

## 9.16.3

This release has 2 other changes.

### Other changes

- Simplify AttachmentCollector as links already handled by Rename handler (#221)
- Ensure MetadataDeleted processed before queue (#220)

## 9.16.2

This release has 2 other changes.

### Other changes

- Don't hide Notice until done
- Collect each attachment once (#219)

## 9.16.1

This release has 2 other changes.

### Other changes

- Update libs (#217)
- Improve default placeholders

## 9.16.0

This release has 6 other changes.

### Other changes

- Add all translations
- Validate plugin version
- Warn about special characters change
- Add missing i18n
- Replace special characters in headings
- Don't mix empty and default setting UI

## 9.15.8

This release has 1 other change.

### Other changes

- Ensure frontmatter links headings are not used

## 9.15.7

This release has 1 other change.

### Other changes

- Substitute headings on collect (#214)

## 9.15.6

This release has 1 other change.

### Other changes

- Clarify term `pasted image` (#215)

## 9.15.5

This release has 1 other change.

### Other changes

- Fix enum binding (#213)

## 9.15.4

This release has 1 other change.

### Other changes

- Minor changes

## 9.15.3

This release has 1 other change.

### Other changes

- Fix infinite rename (#211)

## 9.15.2

This release has 1 other change.

### Other changes

- Additional check for dummy path (#210)

## 9.15.1

This release has 1 other change.

### Other changes

- Fix root folder

## 9.15.0

This release has 1 other change.

### Other changes

- Add oldNoteFile* tokens

## 9.14.0

This release has 1 other change.

### Other changes

- Pass ActionContext

## 9.13.5

This release has 1 other change.

### Other changes

- Minor changes

## 9.13.4

This release has 1 other change.

### Other changes

- Minor changes

## 9.13.3

This release has 1 other change.

### Other changes

- Reuse base i18n

## 9.13.2

This release has 1 other change.

### Other changes

- Rename back

## 9.13.1

This release has 1 other change.

### Other changes

- Localize unhandledError

## 9.13.0

This release has 1 other change.

### Other changes

- Add Chinese translation (#201)

## 9.12.0

This release has 1 other change.

### Other changes

- Fix paths with trailing spaces and dots (#204)

## 9.11.1

This release has 1 other change.

### Other changes

- #206

## 9.11.0

This release has 1 other change.

### Other changes

- Add timeout setting (#203)

## 9.10.6

This release has 1 other change.

### Other changes

- Minor changes

## 9.10.5

This release has 2 other changes.

### Other changes

- Fix uninitialized stats on rename
- Fix #202

## 9.10.4

This release has 1 other change.

### Other changes

- More accurate file changes

## 9.10.3

This release has 1 other change.

### Other changes

- Minor changes

## 9.10.2

This release has 1 other change.

### Other changes

- Register patch without using temp files (#199)

## 9.10.1

- Fix closing active note on load
  - fix: <https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/199#issuecomment-3241586013>

## 9.10.0

This release has 1 other change.

### Other changes

- Add default=empty, default=now

## 9.9.1

This release has 1 other change.

### Other changes

- Truncate time

## 9.9.0

This release has 4 other changes.

### Other changes

- Don't add extra new lines (#196)
- Improve description
- Pass content and stats to every substitutions
- Copy original times when creating attachments

## 9.8.1

This release has 1 other change.

### Other changes

- Minor changes

## 9.8.0

This release has 1 other change.

### Other changes

- originalAttachmentFileCreationDate / originalAttachmentFileModificationDate

## 9.7.1

This release has 1 other change.

### Other changes

- Prevent double prompt (#196)

## 9.7.0

This release has 1 other change.

### Other changes

- Allow generated file names with slash (#195)

## 9.6.0

This release has 1 other change.

### Other changes

- Insert shared text into cursor position (#196)

## 9.5.1

This release has 1 other change.

### Other changes

- Minor changes

## 9.5.0

This release has 1 other change.

### Other changes

- Restore shouldRenameAttachmentFiles

## 9.4.0

This release has 1 other change.

### Other changes

- Add shouldSkipDuplicateCheck

## 9.3.0

This release has 2 other changes.

### Other changes

- Generate name in getAvailablePathForAttachments
- Move shouldRenameAttachments

## 9.2.2

This release has 1 other change.

### Other changes

- Minor changes

## 9.2.1

This release has 2 other changes.

### Other changes

- Rephrase
- Add link to use cases

## 9.2.0

This release has 2 other changes.

### Other changes

- Add warning with link
- Add warning to README

## 9.1.0

This release has 1 other change.

### Other changes

- Add obsidian to context

## 9.0.8

This release has 1 other change.

### Other changes

- getOsUnsafePathCharsRegExp

## 9.0.7

This release has 2 other changes.

### Other changes

- Use platform-specific getInvalidFileNamePathCharsRegExp (#189)
- More abort signals

## 9.0.6

This release has 1 other change.

### Other changes

- Minor changes

## 9.0.5

This release has 2 other changes.

### Other changes

- removeUndefinedProperties (#186, #188)
- Refactor abortSignal  (#186, #188)

## 9.0.4

This release has 1 other change.

### Other changes

- Revalidate tokens after debouncing

## 9.0.3

This release has 2 other changes.

### Other changes

- Prevent infinite update loop
- Revalidate settings after registering tokens

## 9.0.2

This release has 1 other change.

### Other changes

- Register custom tokens on startup (#187)

## 9.0.1

This release has 2 other changes.

### Other changes

- Don't timeout on collecting in prompt mode
- Prevent image/video overflow

## 9.0.0

This release has 5 other changes.

### Other changes

- Highlight token
- Improve validation message
- Add formats for prompt
- Deprecate shouldRenameAttachmentsToLowerCase
- Add preview (#184)

## 8.8.2

This release has 1 other change.

### Other changes

- Don't use new API (#181)

## 8.8.1

This release has 1 other change.

### Other changes

- Prevent infinite loop in prompt

## 8.8.0

This release has 5 other changes.

### Other changes

- Custom token from heading where the attachment is (#183)
- Trim end whitespaces
- Clean validation
- Improve validation
- Add heading variables

## 8.7.0

This release has 1 other change.

### Other changes

- Rename share files (#181)

## 8.6.0

This release has 3 other changes.

### Other changes

- Validate formats
- Allow multi-format for syntax highlighting
- Add indexFromStart/indexFromEnd

## 8.5.2

This release has 1 other change.

### Other changes

- Minor changes

## 8.5.1

This release has 1 other change.

### Other changes

- Minor changes

## 8.5.0

This release has 2 other changes.

### Other changes

- Add choice for CollectAttachmentUsedByMultipleNotesMode
- Reformat settings tab

## 8.4.2

This release has 2 other changes.

### Other changes

- Add base examples
- Add more logging

## 8.4.1

This release has 1 other change.

### Other changes

- Minor changes

## 8.4.0

This release has 2 other changes.

### Other changes

- generatedAttachmentFileName/generatedAttachmentFilePath
- Fix outdated descriptions

## 8.3.1

This release has 1 other change.

### Other changes

- Properly exclude paths (Fixes #175)

## 8.3.0

This release has 1 other change.

### Other changes

- Add left/right formatting (fixes #174)

## 8.2.2

This release has 1 other change.

### Other changes

- Update libs (#170)

## 8.2.1

This release has 1 other change.

### Other changes

- Replace legacy tokens in markdownUrlFormat

## 8.2.0

This release has 1 other change.

### Other changes

- Round size to decimal points

## 8.1.0

This release has 3 other changes.

### Other changes

- \[FR\] Slugify as an option (#167)
- Refactor random
- Upper, lower, slugify file/folder names

## 8.0.2

This release has 1 other change.

### Other changes

- Update renamed token

## 8.0.1

This release has 1 other change.

### Other changes

- Fix warning condition

## 8.0.0

This release has 3 other changes.

### Other changes

- \[FR\] File Size (#168)
- Add attachmentFileSize
- Rename tokens

## 7.11.0

This release has 2 other changes.

### Other changes

- Fix the lib version
- Update libs (Fixes #169)

## 7.10.0

This release has 1 other change.

### Other changes

- Add toggle for avoiding attachment duplication during collection. #166 (by @Accelsnow)

## 7.9.0

This release has 1 other change.

### Other changes

- Exclude paths from attachment collecting

## 7.8.2

This release has 1 other change.

### Other changes

- Ensure attachment folder is updated on rename

## 7.8.1

This release has 1 other change.

### Other changes

- Fix build

## 7.8.0

This release has 1 other change.

### Other changes

- Update attachmentFolderPath on opening file

## 7.7.6

This release has 1 other change.

### Other changes

- Minor changes

## 7.7.5

This release has 1 other change.

### Other changes

- Minor changes

## 7.7.4

This release has 1 other change.

### Other changes

- Minor changes

## 7.7.3

This release has 1 other change.

### Other changes

- Properly handle sequential special characters

## 7.7.2

This release has 1 other change.

### Other changes

- Minor changes

## 7.7.1

This release has 1 other change.

### Other changes

- Reset default url format

## 7.7.0

This release has 2 other changes.

### Other changes

- Modify url generation not faking the file instances
- Add markdown URL format customization #152 (thanks to @Kamesuta)

## 7.6.1

This release has 1 other change.

### Other changes

- Minor changes

## 7.6.0

This release has 3 other changes.

### Other changes

- Fix size
- Add placeholder
- Fix compilation

## 7.5.0

This release has 1 other change.

### Other changes

- Switch to EmptyAttachmentFolderBehavior

## 7.4.3

This release has 1 other change.

### Other changes

- Minor changes

## 7.4.2

This release has 1 other change.

### Other changes

- Improve performance

## 7.4.1

This release has 1 other change.

### Other changes

- Minor changes

## 7.4.0

This release has 2 other changes.

### Other changes

- Add Treat as attachment extensions.
- Support .md Attachments (#147)

## 7.3.0

This release has 1 other change.

### Other changes

- Add settings code highlighting

## 7.2.6

This release has 1 other change.

### Other changes

- Minor changes

## 7.2.5

This release has 1 other change.

### Other changes

- Pass original file name with extension

## 7.2.4

This release has 1 other change.

### Other changes

- Minor changes

## 7.2.3

This release has 1 other change.

### Other changes

- Minor changes

## 7.2.2

This release has 1 other change.

### Other changes

- Minor changes

## 7.2.1

This release has 1 other change.

### Other changes

- New template

## 7.2.0

This release has 1 other change.

### Other changes

- Show progress bar

## 7.1.0

This release has 1 other change.

### Other changes

- Replace special characters

## 7.0.5

This release has 1 other change.

### Other changes

- Minor changes

## 7.0.4

This release has 1 other change.

### Other changes

- Minor changes

## 7.0.3

This release has 1 other change.

### Other changes

- Minor changes

## 7.0.2

This release has 1 other change.

### Other changes

- Minor changes

## 7.0.1

This release has 1 other change.

### Other changes

- Minor changes

## 7.0.0

This release has 2 other changes.

### Other changes

- Allow call fillTemplate() from custom token
- Add include/exclude settings

## 6.0.2

This release has 1 other change.

### Other changes

- Minor changes

## 6.0.1

This release has 1 other change.

### Other changes

- Update template

## 6.0.0

This release has 2 other changes.

### Other changes

- Refactor to support insert attachment
- Rename settings

## 5.1.7

This release has 1 other change.

### Other changes

- Paste in input/textarea

## 5.1.6

This release has 1 other change.

### Other changes

- Lint

## 5.1.5

This release has 1 other change.

### Other changes

- Format

## 5.1.4

This release has 1 other change.

### Other changes

- Minor changes

## 5.1.3

This release has 1 other change.

### Other changes

- Minor changes

## 5.1.2

This release has 1 other change.

### Other changes

- Minor changes

## 5.1.1

This release has 1 other change.

### Other changes

- Minor changes

## 5.1.0

This release has 1 other change.

### Other changes

- Show visible whitespace

## 5.0.2

This release has 1 other change.

### Other changes

- Validate separator

## 5.0.1

This release has 1 other change.

### Other changes

- Pass attachment filename

## 5.0.0

This release has 11 other changes.

### Other changes

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

This release has 1 other change.

### Other changes

- Respect renameOnlyImages when collecting

## 4.31.0

This release has 2 other changes.

### Other changes

- Enable custom whitespace replacement
- Handle raw link

## 4.30.6

This release has 1 other change.

### Other changes

- Minor changes

## 4.30.5

This release has 1 other change.

### Other changes

- Minor changes

## 4.30.4

This release has 1 other change.

### Other changes

- Minor changes

## 4.30.3

This release has 1 other change.

### Other changes

- Minor changes

## 4.30.2

This release has 1 other change.

### Other changes

- Minor changes

## 4.30.1

This release has 1 other change.

### Other changes

- Refactor loop

## 4.30.0

This release has 2 other changes.

### Other changes

- Remove date selector
- Refactor templating

## 4.29.1

This release has 1 other change.

### Other changes

- Minor changes

## 4.29.0

This release has 2 other changes.

### Other changes

- Use image-override to be compatible with `Paste Mode` plugin
- Fix check for pasted image

## 4.28.5

This release has 1 other change.

### Other changes

- Minor changes

## 4.28.4

This release has 1 other change.

### Other changes

- Update libs - fixes mobile build

## 4.28.3

This release has 1 other change.

### Other changes

- Avoid default exports

## 4.28.2

This release has 1 other change.

### Other changes

- Minor changes

## 4.28.1

This release has 1 other change.

### Other changes

- Check for missing webUtils (Electron < 29)

## 4.28.0

This release has 1 other change.

### Other changes

- Fix passing path in new Electron

## 4.27.6

This release has 1 other change.

### Other changes

- Minor changes

## 4.27.5

This release has 1 other change.

### Other changes

- Minor changes

## 4.27.4

This release has 1 other change.

### Other changes

- Minor changes

## 4.27.3

This release has 1 other change.

### Other changes

- Minor changes

## 4.27.2

This release has 1 other change.

### Other changes

- Minor changes

## 4.27.1

This release has 1 other change.

### Other changes

- Refactor

## 4.27.0

This release has 1 other change.

### Other changes

- Allow paste in link editing textbox

## 4.26.0

This release has 1 other change.

### Other changes

- Don't fail on broken canvas

## 4.25.0

This release has 1 other change.

### Other changes

- Add support for frontmatter links

## 4.24.0

This release has 1 other change.

### Other changes

- Support multi-window

## 4.23.2

This release has 1 other change.

### Other changes

- Minor changes

## 4.23.1

This release has 1 other change.

### Other changes

- Minor changes

## 4.23.0

This release has 1 other change.

### Other changes

- Refactor

## 4.22.1

This release has 1 other change.

### Other changes

- Refactor

## 4.22.0

This release has 4 other changes.

### Other changes

- Replace whitespace on drop
- Fix relative path resolution
- Handle duplicates
- Fix stat for mobile

## 4.21.0

This release has 1 other change.

### Other changes

- Fix race condition

## 4.20.0

This release has 1 other change.

### Other changes

- Init all settings

## 4.19.0

This release has 1 other change.

### Other changes

- Don't remove folders with hidden files

## 4.18.0

This release has 1 other change.

### Other changes

- Add `Delete orphan attachments` setting

## 4.17.0

This release has 1 other change.

### Other changes

- Remove to trash

## 4.16.0

This release has 1 other change.

### Other changes

- Preserve angle brackets and leading dot

## 4.15.0

This release has 2 other changes.

### Other changes

- Reuse RenameDeleteHandler
- Add optional skipFolderCreation to getAvailablePathForAttachments

## 4.14.0

This release has 1 other change.

### Other changes

- Proper integration with `Better Markdown Links`

## 4.13.0

This release has 1 other change.

### Other changes

- Handle special renames

## 4.12.2

This release has 1 other change.

### Other changes

- Fix jpegQuality dropdown binding

## 4.12.1

This release has 1 other change.

### Other changes

- Add extension

## 4.12.0

This release has 1 other change.

### Other changes

- Add `Rename attachments on collecting` setting

## 4.11.0

This release has 2 other changes.

### Other changes

- Show warning
- Fix build

## 4.10.0

This release has 5 other changes.

### Other changes

- Fix settings saving
- Allow dot-folders
- Fix mobile loading
- Fix backlinks race condition
- Process attachments before note

## 4.9.4

This release has 2 other changes.

### Other changes

- Handle removed parent folder case
- Rename attachments before changing links

## 4.9.3

This release has 2 other changes.

### Other changes

- Fix backlink check
- Check for race conditions

## 4.9.2

This release has 1 other change.

### Other changes

- Fix options merging

## 4.9.1

This release has 1 other change.

### Other changes

- Fix related attachments notice

## 4.9.0

This release has 1 other change.

### Other changes

- Don't create fake file.

## 4.8.0

This release has 1 other change.

### Other changes

- Don't create duplicates when dragging vault files

## 4.7.0

This release has 1 other change.

### Other changes

- Skip paste handler in metadata editor

## 4.6.0

This release has 1 other change.

### Other changes

- Fix race condition

## 4.5.0

This release has 1 other change.

### Other changes

- Ensure `getAvailablePathForAttachments` creates missing folder

## 4.4.0

This release has 1 other change.

### Other changes

- Fix race conditions

## 4.3.3

This release has 1 other change.

### Other changes

- Bugfixes

## 4.3.2

This release has 1 other change.

### Other changes

- Fix double paste

## 4.3.1

This release has 1 other change.

### Other changes

- Create attachment folders on paste/drop

## 4.3.0

This release has 1 other change.

### Other changes

- Create attachment folder only when it is needed

## 4.2.1

This release has 1 other change.

### Other changes

- Fix build

## 4.2.0

This release has 1 other change.

### Other changes

- Add `Rename only images` setting

## 4.1.0

This release has 1 other change.

### Other changes

- Generate links exactly as Obsidian does

## 4.0.0

This release has 2 other changes.

### Other changes

- Disable Obsidian's built-in way to update links
- Add commands and buttons to collect attachments

## 3.8.0

This release has 1 other change.

### Other changes

- Improve checks for target type

## 3.7.0

This release has 1 other change.

### Other changes

- Add `Rename pasted files with known names` setting

## 3.6.0

This release has 2 other changes.

### Other changes

- Handle move, not only rename
- Add `Keep empty attachment folders` setting

## 3.5.0

This release has 1 other change.

### Other changes

- Preserve draggable on redrop

## 3.4.0

This release has 1 other change.

### Other changes

- Handle rename/delete for canvas

## 3.3.0

This release has 1 other change.

### Other changes

- Add ${foldername} and ${folderPath}

## 3.2.0

This release has 1 other change.

### Other changes

- Configure `Duplicate name separator`

## 3.1.0

This release has 1 other change.

### Other changes

- Add canvas support

## 3.0.0

This release has 1 other change.

### Other changes

- Don't modify attachmentFolderPath setting

## 2.1.0

This release has 3 other changes.

### Other changes

- Configure drag&drop as paste behavior
- Remove extra dot before jpg
- Add support for `${prompt}`

## 2.0.0

This release has 1 other change.

### Other changes

- Make universal paste/drop

## 1.3.1

This release has 1 other change.

### Other changes

- Bugfixes

## 1.3.0

This release has 1 other change.

### Other changes

- Substitute ${originalCopiedFilename}

## 1.2.0

This release has 1 other change.

### Other changes

- Bugfixes

## 1.1.0

This release has 1 other change.

### Other changes

- Bugfixes

## 1.0.3

This release has 1 other change.

### Other changes

- Remove unused attachment folder

## 1.0.2

This release has 1 other change.

### Other changes

- Forbid backslashes

## 1.0.1

This release has 1 other change.

### Other changes

- Add settings validation

## 1.0.0

This release has 6 other changes.

### Other changes

- Fix README.md template example to prevent inappropriate latex rendering by @kaiiiz in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/28>
- Handle pasting multiple images by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/58>
- Support date var template(moment.js) in folder path & image name by @Harrd in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/56>
- Add mobile support by @mengbo in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/44>
- Add name sanitization when creating folder. by @EricWiener in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/35>
- Compress images from png to jpeg while pasting from the clipboard by @kaiiiz in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/29>

## 0.0.9

This release has 1 other change.

### Other changes

- Update attachment folder config when note renamed by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/26>

## 0.0.8

This release has 2 other changes.

### Other changes

- Move attachments when note is moved by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/21>
- Make attachment folder setting modified every time file opens by @mnaoumov in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/23>

## 0.0.7

This release has 2 other changes.

### Other changes

- Fixed minor typo in the settings by @astrodad in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/10>
- Temporarily fix Drag-n-Drop file from explorer doesn't copy file to obsidian vault.

## 0.0.6

This release has 2 other changes.

### Other changes

- Add support for absolute path and relative path.
- Add options for auto renaming.

## 0.0.5

This release has 2 other changes.

### Other changes

- Add support for drop event
- Fix typos & grammar by @TypicalHog in <https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/2>

## 0.0.4

This release has 1 other change.

### Other changes

- Optimize code

## 0.0.3

This release has 1 other change.

### Other changes

- Add setting tabs and fix bugs.

## 0.0.2

This release has 1 other change.

### Other changes

- Add support for custom pasted image filename.

## 0.0.1

This release has 1 other change.

### Other changes

- Initial release
