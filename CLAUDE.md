# CLAUDE.md

## Known Issues

- **Unit coverage far below the 100% gate.** As of 2026-06-20, `npm run test:coverage`
  (which requires 100% over `src/**/*.ts` from the `unit-tests` project) reports ~29% — e.g.
  `src/patches` at 0%, large component/substitution files largely uncovered. All unit tests pass
  (`npm test`), and compile/lint/format/spellcheck are green; only the coverage threshold fails.
  This is a pre-existing WIP gap left by the in-progress refactor series (`extract
  AttachmentCollector`, `extract AttachmentPathManager`, `break circular dependencies`, etc.), not
  a regression from any single change. Closing it requires writing unit tests for the uncovered
  modules.
