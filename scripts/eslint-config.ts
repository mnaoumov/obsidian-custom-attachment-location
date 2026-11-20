import type { Linter } from 'eslint';

import { defineEslintConfigs } from '@mnaoumov/obsidian-dev-toolkit/linters/eslint-config';
import { ObsidianPluginRepoPaths } from '@mnaoumov/obsidian-dev-toolkit/obsidian-plugin-repo-paths';
import {
  defineConfig,
  globalIgnores
} from 'eslint/config';

export const configs: Linter.Config[] = defineEslintConfigs({
  customConfigs(context) {
    return defineConfig([
      // A verbatim copy of the provider's hand-written `api.d.ts`, refreshed from its repository rather than edited,
      // so its style is the provider's to keep.
      globalIgnores(['src/advanced-rename-and-delete-handler/api/api.d.ts']),
      {
        rules: {
          'obsidianmd/ui/sentence-case': [
            'error',
            {
              brands: [
                'Backlink Cache',
                'Show Hidden Files'
              ]
            }
          ]
        }
      },
      {
        /**
         * The toolkit registers the `typescript-dev-toolkit` plugin for the context's TypeScript files alone, so a rule
         * of that plugin turned on without `files` reaches `package.json`, `LICENSE` and the root `.mjs` configs too,
         * and ESLint aborts the whole run on the missing plugin.
         */
        files: context.allFiles(),
        rules: {
          'typescript-dev-toolkit/no-undefined-return-type': 'error'
        }
      },
      {
        files: [
          'src/externally-created-attachments/write-attribution-patch-component.test.ts',
          'src/externally-created-attachments/externally-created-attachment-plugin-list.desktop.integration.test.ts'
        ],
        rules: {
          /**
           * These two suites test how the plugin identifies WHICH other plugin wrote a file, and the only
           * answer Obsidian offers is the `plugin:<id>` source URL it stamps on a community plugin's code:
           * `window.eval('(function anonymous(...){...})\n//# sourceURL=plugin:' + id)`. Reproducing that
           * compilation is the only way to produce the stack frames a real plugin produces, so it is the
           * one thing these tests cannot mock away without testing nothing.
           *
           * Waived at file scope rather than inline because `no-eval` and `obsidianmd/rule-custom-message`
           * are on the no-inline-disable list. The risk the rules guard against is absent here: the
           * compiled source is a literal in these files, and neither file ships — no `*.test.ts` is
           * bundled into `main.js`. Production code never compiles a string; it only READS the frames.
           */
          '@typescript-eslint/no-implied-eval': 'off',
          'no-new-func': 'off',
          'obsidianmd/rule-custom-message': 'off'
        }
      },
      {
        files: ['src/**/*.integration.test.ts'],
        rules: {
          /**
           * An integration suite's `evalInObsidian` closures run inside the Obsidian renderer, where
           * `window` and `document` always exist. The rule reads the file's Node test environment,
           * which declares neither, so it reports every `window.x?.` and `document.x?.` in those
           * closures although none of them can throw.
           */
          'unicorn/no-optional-chaining-on-undeclared-variable': 'off'
        }
      },
      {
        files: [ObsidianPluginRepoPaths.ManifestJson],
        rules: {
          /**
           * The community directory forbids `obsidian` inside a plugin `id`, and this one carries it.
           * A published `id` is permanent — changing it orphans every existing installation and the
           * listing itself — so this repo can never satisfy the rule. The other three manifest rules
           * stay on, which is why the checks are separate rules rather than one. `validate-manifest`
           * keeps every other check: only its id check drops the one word the id carries forever.
           */
          'obsidian-dev-toolkit/manifest-id': 'off',
          'obsidianmd/validate-manifest': ['error', { allowedWords: { id: ['obsidian'] }, checkId: true }]
        }
      }
    ]);
  }
});
