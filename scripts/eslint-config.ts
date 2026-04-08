import type { Linter } from 'eslint';

import { defineConfig } from 'eslint/config';
import { defineEslintConfigs } from 'obsidian-dev-utils/script-utils/linters/eslint-config';

export const configs: Linter.Config[] = defineEslintConfigs({
  customConfigs() {
    return defineConfig({
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
    });
  }
});
