/**
 * @file
 *
 * Normalizes a human-typed name: collapses its whitespace and title-cases it while leaving acronyms
 * alone.
 *
 * Requested against `${prompt}` (issue #59), where the value is typed by hand and therefore arrives
 * with whatever spacing and casing the typing produced. Invalid characters are NOT handled here — the
 * plugin already replaces those through the `specialCharacters` / `specialCharactersReplacement`
 * settings, and a second, differently-configured idea of a valid character is exactly the kind of
 * duplication that drifts.
 *
 * The rules match Advanced Note Composer's `normalizeTypedFolderName`, which is where the reporter met
 * them. Worth lifting into `obsidian-dev-utils` once both plugins can be released together.
 */

/**
 * The shortest word that can be an acronym. Below it the acronym rule is indistinguishable from
 * ordinary title-casing anyway — a lone `A` is already its own upper-case — so the length test only
 * ever decides real words.
 */
const MIN_ACRONYM_LENGTH = 2;

const TITLE_CASE_SEPARATOR_REG_EXP = /^(?:\s+|-)$/;

/**
 * Splits a name into title-casing units: the words AND the separators between them. The separator is a
 * capture group, so it survives the split and `join('')` puts it back exactly where it was — which is
 * what keeps `Foo - Bar` and `Foo-Bar` distinguishable.
 */
const TITLE_CASE_UNIT_REG_EXP = /(?<Separator>\s+|-)/;

const WHITESPACE_RUN_REG_EXP = /\s+/g;

/**
 * Collapses every run of whitespace to a single space and removes leading and trailing whitespace.
 *
 * @param value - The value to collapse.
 * @returns The collapsed value.
 */
export function collapseWhitespace(value: string): string {
  return value.replaceAll(WHITESPACE_RUN_REG_EXP, ' ').trim();
}

/**
 * Capitalizes the first letter of each word and lower-cases the rest, EXCEPT a word that is already
 * entirely upper-case, which is left alone so an acronym survives (`api TEST` becomes `Api TEST`).
 *
 * Words are separated by whitespace or a hyphen, and the separators are preserved exactly, so
 * `Foo - Bar` and `Foo-Bar` stay distinguishable.
 *
 * @param value - The value to title-case.
 * @returns The title-cased value.
 */
export function toTitleCase(value: string): string {
  return value
    .split(TITLE_CASE_UNIT_REG_EXP)
    .map((unit) => {
      if (!unit || TITLE_CASE_SEPARATOR_REG_EXP.test(unit)) {
        return unit;
      }

      if (unit.length >= MIN_ACRONYM_LENGTH && unit === unit.toUpperCase()) {
        return unit;
      }

      return unit.charAt(0).toUpperCase() + unit.slice(1).toLowerCase();
    })
    .join('');
}
