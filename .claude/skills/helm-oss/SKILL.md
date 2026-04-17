```markdown
# helm-oss Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns, coding conventions, and workflows used in the `helm-oss` TypeScript monorepo. It covers file naming, import/export styles, commit conventions, and the process for upgrading dependencies across multiple packages. This guide is intended for contributors and maintainers to ensure consistency and efficiency in the codebase.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `myModule.ts`, `userService.test.ts`

### Import Style
- Use **relative imports** for internal modules.
  - Example:
    ```typescript
    import { doSomething } from './utils';
    ```

### Export Style
- Use **named exports**.
  - Example:
    ```typescript
    // utils.ts
    export function doSomething() { ... }
    ```

    ```typescript
    // consumer.ts
    import { doSomething } from './utils';
    ```

### Commit Messages
- Follow **conventional commit** style.
- Common prefix: `chore`
- Example:
  ```
  chore: update dependencies in user and auth packages
  ```

## Workflows

### Multi-Package Dependency Upgrade
**Trigger:** When you need to upgrade one or more npm dependencies across multiple packages in the monorepo (e.g., via Dependabot or manually).  
**Command:** `/upgrade-dependencies`

1. **Identify outdated dependencies** across all packages and sub-packages.
2. **Update** each affected `package.json` and `package-lock.json` file.
3. **Regenerate lockfiles** as needed to ensure consistency.
4. **Commit all updated files together** with a detailed changelog in the commit message.
   - Example commit message:
     ```
     chore: upgrade lodash and typescript in all packages

     - lodash upgraded to 4.17.21 in packages/core and packages/api
     - typescript upgraded to 4.9.5 in all packages
     - Regenerated lockfiles
     ```

**Files involved:**
- `*/package.json`
- `*/package-lock.json`
- `*/**/package.json`
- `*/**/package-lock.json`

**Frequency:** ~2-4 times per month

## Testing Patterns

- Test files follow the pattern: `*.test.*`
  - Example: `userService.test.ts`
- Testing framework is **unknown** (not detected), but tests are colocated with source files or in test directories.
- To add a test:
  ```typescript
  // userService.test.ts
  import { getUser } from './userService';

  describe('getUser', () => {
    it('returns user data', () => {
      // test implementation
    });
  });
  ```

## Commands

| Command               | Purpose                                                        |
|-----------------------|----------------------------------------------------------------|
| /upgrade-dependencies | Batch upgrade npm dependencies across all packages and lockfiles|
```
