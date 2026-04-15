```markdown
# helm-oss Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `helm-oss` TypeScript codebase. It covers file naming, import/export styles, commit message conventions, and testing patterns. The guide is designed to help contributors write consistent, maintainable code and follow best practices when working with this repository.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `myUtility.ts`, `userService.ts`

### Imports
- Use **relative import paths** for all imports.
  - Example:
    ```typescript
    import { fetchData } from './apiClient';
    ```

### Exports
- Use **named exports**.
  - Example:
    ```typescript
    // Good
    export function calculateSum(a: number, b: number): number {
      return a + b;
    }

    // Bad (default export)
    // export default function calculateSum(...) { ... }
    ```

### Commit Messages
- Follow **Conventional Commits**.
- Common prefix: `chore`
- Example:
  ```
  chore: update dependencies to latest versions
  ```

## Workflows

### Commit Changes
**Trigger:** When making any code or documentation changes.
**Command:** `/commit-changes`

1. Make your code changes following the coding conventions.
2. Stage your changes: `git add .`
3. Write a commit message using the conventional format:
   ```
   chore: <short description>
   ```
4. Commit your changes: `git commit -m "chore: <short description>"`

### Add a Test
**Trigger:** When adding new features or fixing bugs.
**Command:** `/add-test`

1. Create a test file using the pattern: `*.test.*` (e.g., `myFunction.test.ts`).
2. Write tests for your code (testing framework is not specified; use standard TypeScript test patterns).
3. Ensure your test covers all relevant cases.

### Run Tests
**Trigger:** Before pushing changes or opening a pull request.
**Command:** `/run-tests`

1. Run the test suite using the project's test runner (framework is unspecified; use the appropriate command, e.g., `npm test` or `yarn test`).
2. Ensure all tests pass before proceeding.

## Testing Patterns

- **Test files** use the `*.test.*` naming convention (e.g., `example.test.ts`).
- Place test files alongside the code they test or in a dedicated test directory.
- Use standard TypeScript testing practices.
- Example test file:
  ```typescript
  // mathUtils.test.ts
  import { calculateSum } from './mathUtils';

  describe('calculateSum', () => {
    it('adds two numbers', () => {
      expect(calculateSum(2, 3)).toBe(5);
    });
  });
  ```

## Commands
| Command          | Purpose                                 |
|------------------|-----------------------------------------|
| /commit-changes  | Guide for making and committing changes |
| /add-test        | Steps for adding a new test             |
| /run-tests       | Steps for running the test suite        |
```