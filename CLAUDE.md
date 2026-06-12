# CLAUDE.md

## Protocol version

The Ably protocol version is **6** (integer). This is sent as:
- `x-ably-version: 6` header on all REST requests (RSC7e)
- `v=6` query param on WebSocket connections (RTN2f)

These are the same value. The versioning scheme changed from decimal (e.g. "1.2") to integer at v2 (CSV2a). Old docs and code may still reference "1.2" — that's wrong for current SDKs.

## Test baseline

1287 pass / 0 fail / 61 ignored (post stage 5.8, 2026-06-12). THE SUITE IS FULLY
GREEN — any failure after a change is a regression. Every ignore carries an
explicit recorded-deferral reason. Integration: 62 pass / 15 ignored against the live nonprod
sandbox; proxy: 8/8 via uts-proxy. Run integration/proxy with --test-threads=1
(shared sandbox app; flaky in parallel). If any tests_rest_*/tests_proxy test fails
after a change, something regressed.

Run tests: `cargo test 2>&1 | tail -5`

## Test organization

Tests mirror the UTS (Universal Test Specification) directory structure:
- `tests_rest_unit_*.rs` — REST unit tests (mocked HTTP)
- `tests_rest_integration.rs` — REST integration tests (nonprod sandbox)
- `tests_realtime_unit_*.rs` — Realtime unit tests (mocked WebSocket)
- `tests_realtime_integration.rs` — Realtime integration tests [planned]
- `tests_proxy.rs` — proxy integration tests (uts-proxy, auto-downloaded)

Filter by category: `cargo test tests_rest_unit` or `cargo test tests_realtime_unit`.

UTS specs are at `../specification/uts/`. Each test function should reference its spec ID in the name (e.g. `rsc7e_x_ably_version_header`).

## Mock injection pattern

Tests use `ClientOptions::rest_with_mock(mock)` which:
1. Clones the `MockHttpClient` (Arc-based) to get a handle
2. Boxes the original as `Box<dyn HttpClient>`
3. Stores the cloned handle on `RestInner.mock_handle` (behind `#[cfg(test)]`)

This avoids `as_any()` downcasting on the `HttpClient` trait. The handle is retrieved in tests via `client.inner.mock_handle.as_ref().unwrap()`.

## Spec items that are easy to get wrong

- **RSC15f**: Cached fallback host. When a fallback succeeds, cache it and try it *first* on the next request. On failure, clear cache and include the primary host in the retry list.
- **RSC1b**: Empty token string must be rejected at client construction time.
- **RSC18**: Basic auth (API key without token auth) over non-TLS must be rejected.

## Phased implementation

See `DESIGN.md` for the API surface and the plan in `.claude/plans/noble-strolling-marble.md` for phase tracking. `PROGRESS.md` tracks what's done per phase (all phases COMPLETE as of 2026-06-12).

## Work management (Backlog.md)

Subsequent work is managed with the Backlog.md CLI (tasks live in `backlog/tasks/`;
full agent guide appended at the bottom of this file). The deferred-work backlog
(JWT tests, RTN16 recovery, RTN17j, delta/vcdiff, push LocalDevice, RTN20, upstream
issue filing, housekeeping) is loaded as TASK-1..TASK-10 — start there, not from
PROGRESS.md prose. `backlog` resolves via the repo `.tool-versions`
(`nodejs 22.11.0 .npm`); use `backlog task list --plain` / `backlog board`.
When completing a task that un-ignores tests, also convert the corresponding
`uts_coverage.txt` exclusions (see tools/uts_coverage_generate.py).

## Conventions

- `pub(crate)` for all internal constructors, wire types, and protocol details
- One `ErrorInfo` type (no separate `Error` vs `ErrorInfo`)
- One `Message` type shared by REST and Realtime
- Builder pattern for publish (both REST and Realtime)
- MessagePack is the default format; JSON is opt-in via `use_binary_protocol(false)`

## Realtime design contract (BINDING — see DESIGN.md "Realtime State & Concurrency")

These are requirements, not guidance. They apply to ALL realtime work (Phase 5+):

1. **One connection loop owns ALL mutable protocol state** (connection state
   machine, channels, presence, ACKs, queues, timers) as plain owned data.
   **No locks on protocol state, ever.** Handles interact with the loop only via
   the LoopInput mpsc, oneshot replies, watch snapshots, and broadcast events.
2. **Complete allowed lock inventory**: the `Channels` handle registry Mutex,
   plus the two REST locks (auth_state, fallback_state). Nothing else.
   `tests_design_conformance.rs` enforces this on every `cargo test` — if it
   fails, STOP and read its message; never weaken or bypass it. (The two
   temporary stub presence mutexes were deleted in 5.7 as planned;
   channel.rs allowance is now exactly 1.)
3. **The loop never awaits I/O.** Blocking work (transport connect, token
   acquisition, writes) happens in spawned tasks posting LoopInput back,
   generation-tagged.
4. **Realtime tests are derived from the UTS specs** (`uts/realtime/unit/*.md`),
   never from old implementations. The 440 ported tests are a coverage
   cross-check and quarry only (adopt verbatim only when they match the UTS
   pseudo-code); each Phase 5 stage records adopted/superseded counts.
   **Per-ID traceability is enforced**: `uts_coverage.txt` maps every UTS
   Test ID (rest + realtime) to the Rust test(s) covering it, or excludes it
   with a stage/deferral reason; `tests_uts_coverage.rs` fails the build on
   any unaccounted ID, dangling test reference, or reasonless exclusion.
   Closing a stage means converting its exclusions into mappings (regenerate
   with `tools/uts_coverage_generate.py`, then review the diff).
5. **Design-change-before-code**: if an implementation step seems to need a new
   sync primitive, shared state outside the loop, or a loop bypass, STOP. Propose
   the change as a DESIGN.md edit and get explicit human approval BEFORE writing
   the code. This includes anything that would dodge the conformance test.

<!-- BACKLOG.MD GUIDELINES START -->
# Instructions for the usage of Backlog.md CLI Tool

## Backlog.md: Comprehensive Project Management Tool via CLI

### Assistant Objective

Efficiently manage all project tasks, status, and documentation using the Backlog.md CLI, ensuring all project metadata
remains fully synchronized and up-to-date.

### Core Capabilities

- ✅ **Task Management**: Create, edit, assign, prioritize, and track tasks with full metadata
- ✅ **Search**: Fuzzy search across tasks, documents, and decisions with `backlog search`
- ✅ **Acceptance Criteria**: Granular control with add/remove/check/uncheck by index
- ✅ **Definition of Done checklists**: Per-task DoD items with add/remove/check/uncheck
- ✅ **Board Visualization**: Terminal-based Kanban board (`backlog board`) and web UI (`backlog browser`)
- ✅ **Git Integration**: Automatic tracking of task states across branches
- ✅ **Dependencies**: Task relationships and subtask hierarchies
- ✅ **Documentation & Decisions**: Structured docs and architectural decision records
- ✅ **Export & Reporting**: Generate markdown reports and board snapshots
- ✅ **AI-Optimized**: `--plain` flag provides clean text output for AI processing

### Why This Matters to You (AI Agent)

1. **Comprehensive system** - Full project management capabilities through CLI
2. **The CLI is the interface** - All operations go through `backlog` commands
3. **Unified interaction model** - You can use CLI for both reading (`backlog task 1 --plain`) and writing (
   `backlog task edit 1`)
4. **Metadata stays synchronized** - The CLI handles all the complex relationships

### Key Understanding

- **Tasks** live in `backlog/tasks/` as `task-<id> - <title>.md` files
- **You interact via CLI only**: `backlog task create`, `backlog task edit`, etc.
- **Use `--plain` flag** for AI-friendly output when viewing/listing
- **Never bypass the CLI** - It handles Git, metadata, file naming, and relationships

---

# ⚠️ CRITICAL: NEVER EDIT TASK FILES DIRECTLY. Edit Only via CLI

**ALL task operations MUST use the Backlog.md CLI commands**

- ✅ **DO**: Use `backlog task edit` and other CLI commands
- ✅ **DO**: Use `backlog task create` to create new tasks
- ✅ **DO**: Use `backlog task edit <id> --check-ac <index>` to mark acceptance criteria
- ❌ **DON'T**: Edit markdown files directly
- ❌ **DON'T**: Manually change checkboxes in files
- ❌ **DON'T**: Add or modify text in task files without using CLI

**Why?** Direct file editing breaks metadata synchronization, Git tracking, and task relationships.

---

## 1. Source of Truth & File Structure

### 📖 **UNDERSTANDING** (What you'll see when reading)

- Markdown task files live under **`backlog/tasks/`** (drafts under **`backlog/drafts/`**)
- Files are named: `task-<id> - <title>.md` (e.g., `task-42 - Add GraphQL resolver.md`)
- Project documentation is in **`backlog/docs/`**
- Project decisions are in **`backlog/decisions/`**

### 🔧 **ACTING** (How to change things)

- **All task operations MUST use the Backlog.md CLI tool**
- This ensures metadata is correctly updated and the project stays in sync
- **Always use `--plain` flag** when listing or viewing tasks for AI-friendly text output
- Create and update project docs through Backlog.md APIs so frontmatter and paths stay valid. For CLI users, run `backlog doc create "Title" -p guides/setup` or `backlog doc update doc-1 --content "Updated markdown"`; MCP users should use `document_create` / `document_update`.
- Document paths are relative to `backlog/docs/`; absolute paths and `..` traversal are rejected.

---

## 2. Common Mistakes to Avoid

### ❌ **WRONG: Direct File Editing**

```markdown
# DON'T DO THIS:

1. Open backlog/tasks/task-7 - Feature.md in editor
2. Change "- [ ]" to "- [x]" manually
3. Add notes, comments, or final summary directly to the file
4. Save the file
```

### ✅ **CORRECT: Using CLI Commands**

```bash
# DO THIS INSTEAD:
backlog task edit 7 --check-ac 1  # Mark AC #1 as complete
backlog task edit 7 --notes "Implementation complete"  # Add notes
backlog task edit 7 --comment "Review question" --comment-author @agent-k  # Add comment
backlog task edit 7 --final-summary "PR-style summary"  # Add final summary
backlog task edit 7 -s "In Progress" -a @agent-k  # Multiple commands: change status and assign the task when you start working on the task
```

---

## 3. Understanding Task Format (Read-Only Reference)

⚠️ **FORMAT REFERENCE ONLY** - The following sections show what you'll SEE in task files.
**Never edit these directly! Use CLI commands to make changes.**

### Task Structure You'll See

```markdown
---
id: task-42
title: Add GraphQL resolver
status: To Do
assignee: [@sara]
labels: [backend, api]
modified_files:
  - src/server/api.ts
  - src/web/components/TaskList.tsx
---

## Description

Brief explanation of the task purpose.

## Acceptance Criteria

<!-- AC:BEGIN -->

- [ ] #1 First criterion
- [x] #2 Second criterion (completed)
- [ ] #3 Third criterion

<!-- AC:END -->

## Definition of Done

<!-- DOD:BEGIN -->

- [ ] #1 Tests pass
- [ ] #2 Docs updated

<!-- DOD:END -->

## Implementation Plan

1. Research approach
2. Implement solution

## Implementation Notes

Progress notes captured during implementation.

## Comments

Task discussion, review questions, and collaboration notes.

## Final Summary

PR-style summary of what was implemented.
```

### How to Modify Each Section

| What You Want to Change | CLI Command to Use                                       |
|-------------------------|----------------------------------------------------------|
| Title                   | `backlog task edit 42 -t "New Title"`                    |
| Status                  | `backlog task edit 42 -s "In Progress"`                  |
| Assignee                | `backlog task edit 42 -a @sara`                          |
| Labels                  | `backlog task edit 42 -l backend,api`                    |
| Description             | `backlog task edit 42 -d "New description"`              |
| Add AC                  | `backlog task edit 42 --ac "New criterion"`              |
| Add DoD                 | `backlog task edit 42 --dod "Ship notes"`                |
| Check AC #1             | `backlog task edit 42 --check-ac 1`                      |
| Check DoD #1            | `backlog task edit 42 --check-dod 1`                     |
| Uncheck AC #2           | `backlog task edit 42 --uncheck-ac 2`                    |
| Uncheck DoD #2          | `backlog task edit 42 --uncheck-dod 2`                   |
| Remove AC #3            | `backlog task edit 42 --remove-ac 3`                     |
| Remove DoD #3           | `backlog task edit 42 --remove-dod 3`                    |
| Add Plan                | `backlog task edit 42 --plan "1. Step one\n2. Step two"` |
| Add Notes (replace)     | `backlog task edit 42 --notes "What I did"`              |
| Append Notes            | `backlog task edit 42 --append-notes "Another note"` |
| Add Comment             | `backlog task edit 42 --comment "Review question" --comment-author @agent` |
| Add Final Summary       | `backlog task edit 42 --final-summary "PR-style summary"` |
| Append Final Summary    | `backlog task edit 42 --append-final-summary "Another detail"` |
| Clear Final Summary     | `backlog task edit 42 --clear-final-summary` |

---

## 4. Defining Tasks

### Creating New Tasks

**Always use CLI to create tasks:**

```bash
# Example
backlog task create "Task title" -d "Description" --ac "First criterion" --ac "Second criterion"
```

### Title (one liner)

Use a clear brief title that summarizes the task.

### Description (The "why")

Provide a concise summary of the task purpose and its goal. Explains the context without implementation details.

### Acceptance Criteria (The "what")

**Understanding the Format:**

- Acceptance criteria appear as numbered checkboxes in the markdown files
- Format: `- [ ] #1 Criterion text` (unchecked) or `- [x] #1 Criterion text` (checked)

**Managing Acceptance Criteria via CLI:**

⚠️ **IMPORTANT: How AC Commands Work**

- **Adding criteria (`--ac`)** accepts multiple flags: `--ac "First" --ac "Second"` ✅
- **Checking/unchecking/removing** accept multiple flags too: `--check-ac 1 --check-ac 2` ✅
- **Mixed operations** work in a single command: `--check-ac 1 --uncheck-ac 2 --remove-ac 3` ✅

```bash
# Examples

# Add new criteria (MULTIPLE values allowed)
backlog task edit 42 --ac "User can login" --ac "Session persists"

# Check specific criteria by index (MULTIPLE values supported)
backlog task edit 42 --check-ac 1 --check-ac 2 --check-ac 3  # Check multiple ACs
# Or check them individually if you prefer:
backlog task edit 42 --check-ac 1    # Mark #1 as complete
backlog task edit 42 --check-ac 2    # Mark #2 as complete

# Mixed operations in single command
backlog task edit 42 --check-ac 1 --uncheck-ac 2 --remove-ac 3

# ❌ STILL WRONG - These formats don't work:
# backlog task edit 42 --check-ac 1,2,3  # No comma-separated values
# backlog task edit 42 --check-ac 1-3    # No ranges
# backlog task edit 42 --check 1         # Wrong flag name

# Multiple operations of same type
backlog task edit 42 --uncheck-ac 1 --uncheck-ac 2  # Uncheck multiple ACs
backlog task edit 42 --remove-ac 2 --remove-ac 4    # Remove multiple ACs (processed high-to-low)
```

### Definition of Done checklist (per-task)

Definition of Done items are a second checklist in each task. Defaults come from `definition_of_done` in the project config file (`backlog/config.yml`, `.backlog/config.yml`, or `backlog.config.yml`) or from Web UI Settings, and can be disabled per task.

**Managing Definition of Done via CLI:**

```bash
# Add DoD items (MULTIPLE values allowed)
backlog task edit 42 --dod "Run tests" --dod "Update docs"

# Check/uncheck DoD items by index (MULTIPLE values supported)
backlog task edit 42 --check-dod 1 --check-dod 2
backlog task edit 42 --uncheck-dod 1

# Remove DoD items by index
backlog task edit 42 --remove-dod 2

# Create without defaults
backlog task create "Feature" --no-dod-defaults
```

**Key Principles for Good ACs:**

- **Outcome-Oriented:** Focus on the result, not the method.
- **Testable/Verifiable:** Each criterion should be objectively testable
- **Clear and Concise:** Unambiguous language
- **Complete:** Collectively cover the task scope
- **User-Focused:** Frame from end-user or system behavior perspective

Good Examples:

- "User can successfully log in with valid credentials"
- "System processes 1000 requests per second without errors"
- "CLI preserves literal newlines in description/plan/notes/comments/final summary; `\\n` sequences are not auto-converted"

Bad Example (Implementation Step):

- "Add a new function handleLogin() in auth.ts"
- "Define expected behavior and document supported input patterns"

### Task Breakdown Strategy

1. Identify foundational components first
2. Create tasks in dependency order (foundations before features)
3. Ensure each task delivers value independently
4. Avoid creating tasks that block each other

### Task Requirements

- Tasks must be **atomic** and **testable** or **verifiable**
- Each task should represent a single unit of work for one PR
- **Never** reference future tasks (only tasks with id < current task id)
- Ensure tasks are **independent** and don't depend on future work

---

## 5. Implementing Tasks

### 5.1. First step when implementing a task

The very first things you must do when you take over a task are:

* set the task in progress
* assign it to yourself

```bash
# Example
backlog task edit 42 -s "In Progress" -a @{myself}
```

### 5.2. Review Task References and Documentation

Before planning, check if the task has any attached `references` or `documentation`:
- **References**: Related code files, GitHub issues, or URLs relevant to the implementation
- **Documentation**: Design docs, API specs, or other materials for understanding context

These are visible in the task view output. Review them to understand the full context before drafting your plan.

### 5.3. Create an Implementation Plan (The "how")

Previously created tasks contain the why and the what. Once you are familiar with that part you should think about a
plan on **HOW** to tackle the task and all its acceptance criteria. This is your **Implementation Plan**.
First do a quick check to see if all the tools that you are planning to use are available in the environment you are
working in.
When you are ready, write it down in the task so that you can refer to it later.

```bash
# Example
backlog task edit 42 --plan "1. Research codebase for references\n2Research on internet for similar cases\n3. Implement\n4. Test"
```

## 5.4. Implementation

Once you have a plan, you can start implementing the task. This is where you write code, run tests, and make sure
everything works as expected. Follow the acceptance criteria one by one and MARK THEM AS COMPLETE as soon as you
finish them.

### 5.5 Implementation Notes (Progress log)

Use Implementation Notes to log progress, decisions, and blockers as you work.
Append notes progressively during implementation using `--append-notes`:

```
backlog task edit 42 --append-notes "Investigated root cause" --append-notes "Added tests for edge case"
```

```bash
# Example
backlog task edit 42 --notes "Initial implementation done; pending integration tests"
```

### 5.6 Final Summary (PR description)

When you are done implementing a task you need to prepare a PR description for it.
Because you cannot create PRs directly, write the PR as a clean summary in the Final Summary field.

**Quality bar:** Write it like a reviewer will see it. A one‑liner is rarely enough unless the change is truly trivial.
Include the key scope so someone can understand the impact without reading the whole diff.

```bash
# Example
backlog task edit 42 --final-summary "Implemented pattern X because Reason Y; updated files Z and W; added tests"
```

**IMPORTANT**: Do NOT include an Implementation Plan when creating a task. The plan is added only after you start the
implementation.

- Creation phase: provide Title, Description, Acceptance Criteria, and optionally labels/priority/assignee.
- When you begin work, switch to edit, set the task in progress and assign to yourself
  `backlog task edit <id> -s "In Progress" -a "..."`.
- Think about how you would solve the task and add the plan: `backlog task edit <id> --plan "..."`.
- After updating the plan, share it with the user and ask for confirmation. Do not begin coding until the user approves the plan or explicitly tells you to skip the review.
- Append Implementation Notes during implementation using `--append-notes` as progress is made.
- Add Final Summary only after completing the work: `backlog task edit <id> --final-summary "..."` (replace) or append using `--append-final-summary`.

## Phase discipline: What goes where

- Creation: Title, Description, Acceptance Criteria, labels/priority/assignee.
- Implementation: Implementation Plan (after moving to In Progress and assigning to yourself) + Implementation Notes (progress log, appended as you work).
- Wrap-up: Final Summary (PR description), verify AC and Definition of Done checks.

**IMPORTANT**: Only implement what's in the Acceptance Criteria. If you need to do more, either:

1. Update the AC first: `backlog task edit 42 --ac "New requirement"`
2. Or create a new follow up task: `backlog task create "Additional feature"`

---

## 6. Typical Workflow

```bash
# 1. Identify work
backlog task list -s "To Do" --plain

# 2. Read task details
backlog task 42 --plain

# 3. Start work: assign yourself & change status
backlog task edit 42 -s "In Progress" -a @myself

# 4. Add implementation plan
backlog task edit 42 --plan "1. Analyze\n2. Refactor\n3. Test"

# 5. Share the plan with the user and wait for approval (do not write code yet)

# 6. Work on the task (write code, test, etc.)

# 7. Mark acceptance criteria as complete (supports multiple in one command)
backlog task edit 42 --check-ac 1 --check-ac 2 --check-ac 3  # Check all at once
# Or check them individually if preferred:
# backlog task edit 42 --check-ac 1
# backlog task edit 42 --check-ac 2
# backlog task edit 42 --check-ac 3

# 8. Add Final Summary (PR Description)
backlog task edit 42 --final-summary "Refactored using strategy pattern, updated tests"

# 9. Mark task as done
backlog task edit 42 -s Done
```

---

## 7. Definition of Done (DoD)

A task is **Done** only when **ALL** of the following are complete:

### ✅ Via CLI Commands:

1. **All acceptance criteria checked**: Use `backlog task edit <id> --check-ac <index>` for each
2. **All Definition of Done items checked**: Use `backlog task edit <id> --check-dod <index>` for each
3. **Final Summary added**: Use `backlog task edit <id> --final-summary "..."`
4. **Status set to Done**: Use `backlog task edit <id> -s Done`

### ✅ Via Code/Testing:

5. **Tests pass**: Run test suite and linting
6. **Documentation updated**: Update relevant docs if needed
7. **Code reviewed**: Self-review your changes
8. **No regressions**: Performance, security checks pass

⚠️ **NEVER mark a task as Done without completing ALL items above**

---

## 8. Finding Tasks and Content with Search

When users ask you to find tasks related to a topic, use the `backlog search` command with `--plain` flag:

```bash
# Search for tasks about authentication
backlog search "auth" --plain

# Search only in tasks (not docs/decisions)
backlog search "login" --type task --plain

# Search with filters
backlog search "api" --status "In Progress" --plain
backlog search "bug" --priority high --plain

# Find tasks that modified a project file path
backlog search --modified-file src/server/api.ts --plain
```

**Key points:**
- Uses fuzzy matching - finds "authentication" when searching "auth"
- Searches task titles, descriptions, and content
- Also searches `modified_files`; `--modified-file` applies a case-insensitive path substring filter
- Also searches documents and decisions unless filtered with `--type task`
- Always use `--plain` flag for AI-readable output

---

## 9. Quick Reference: DO vs DON'T

### Viewing and Finding Tasks

| Task         | ✅ DO                        | ❌ DON'T                         |
|--------------|-----------------------------|---------------------------------|
| View task    | `backlog task 42 --plain`   | Open and read .md file directly |
| List tasks   | `backlog task list --plain` | Browse backlog/tasks folder     |
| Check status | `backlog task 42 --plain`   | Look at file content            |
| Find by topic| `backlog search "auth" --plain` | Manually grep through files |

### Modifying Tasks

| Task          | ✅ DO                                 | ❌ DON'T                           |
|---------------|--------------------------------------|-----------------------------------|
| Check AC      | `backlog task edit 42 --check-ac 1`  | Change `- [ ]` to `- [x]` in file |
| Add notes     | `backlog task edit 42 --notes "..."` | Type notes into .md file          |
| Add comment   | `backlog task edit 42 --comment "..." --comment-author @agent` | Type comment into .md file |
| Add final summary | `backlog task edit 42 --final-summary "..."` | Type summary into .md file |
| Change status | `backlog task edit 42 -s Done`       | Edit status in frontmatter        |
| Add AC        | `backlog task edit 42 --ac "New"`    | Add `- [ ] New` to file           |

---

## 10. Complete CLI Command Reference

### Task Creation

| Action           | Command                                                                             |
|------------------|-------------------------------------------------------------------------------------|
| Create task      | `backlog task create "Title"`                                                       |
| With description | `backlog task create "Title" -d "Description"`                                      |
| With AC          | `backlog task create "Title" --ac "Criterion 1" --ac "Criterion 2"`                 |
| With final summary | `backlog task create "Title" --final-summary "PR-style summary"`                 |
| With references  | `backlog task create "Title" --ref src/api.ts --ref https://github.com/issue/123`   |
| With documentation | `backlog task create "Title" --doc https://design-docs.example.com`               |
| With modified files | `backlog task create "Title" --modified-file src/api.ts --modified-file src/ui.ts` |
| With all options | `backlog task create "Title" -d "Desc" -a @sara -s "To Do" -l auth --priority high --ref src/api.ts --doc docs/spec.md --modified-file src/api.ts` |
| Create draft     | `backlog task create "Title" --draft`                                               |
| Create subtask   | `backlog task create "Title" -p 42`                                                 |

### Task Modification

| Action           | Command                                     |
|------------------|---------------------------------------------|
| Edit title       | `backlog task edit 42 -t "New Title"`       |
| Edit description | `backlog task edit 42 -d "New description"` |
| Change status    | `backlog task edit 42 -s "In Progress"`     |
| Assign           | `backlog task edit 42 -a @sara`             |
| Add labels       | `backlog task edit 42 -l backend,api`       |
| Set priority     | `backlog task edit 42 --priority high`      |

### Acceptance Criteria Management

| Action              | Command                                                                     |
|---------------------|-----------------------------------------------------------------------------|
| Add AC              | `backlog task edit 42 --ac "New criterion" --ac "Another"`                  |
| Remove AC #2        | `backlog task edit 42 --remove-ac 2`                                        |
| Remove multiple ACs | `backlog task edit 42 --remove-ac 2 --remove-ac 4`                          |
| Check AC #1         | `backlog task edit 42 --check-ac 1`                                         |
| Check multiple ACs  | `backlog task edit 42 --check-ac 1 --check-ac 3`                            |
| Uncheck AC #3       | `backlog task edit 42 --uncheck-ac 3`                                       |
| Mixed operations    | `backlog task edit 42 --check-ac 1 --uncheck-ac 2 --remove-ac 3 --ac "New"` |

### Task Content

| Action           | Command                                                  |
|------------------|----------------------------------------------------------|
| Add plan         | `backlog task edit 42 --plan "1. Step one\n2. Step two"` |
| Add notes        | `backlog task edit 42 --notes "Implementation details"`  |
| Add comment      | `backlog task edit 42 --comment "Review question" --comment-author @agent` |
| Add final summary | `backlog task edit 42 --final-summary "PR-style summary"` |
| Append final summary | `backlog task edit 42 --append-final-summary "More details"` |
| Clear final summary | `backlog task edit 42 --clear-final-summary` |
| Add dependencies | `backlog task edit 42 --dep task-1 --dep task-2`         |
| Add references   | `backlog task edit 42 --ref src/api.ts --ref https://github.com/issue/123` |
| Add documentation | `backlog task edit 42 --doc https://design-docs.example.com --doc docs/spec.md` |
| Set modified files | `backlog task edit 42 --modified-file src/api.ts --modified-file src/ui.ts` |

### Multi‑line Input (Description/Plan/Notes/Comments/Final Summary)

The CLI preserves input literally — shells do not convert `\n` inside normal quotes. Use one of the following forms, listed in order of preference for AI agents:

**1. Repeat `--append-*` for each line (works in every shell, including sandboxes that block other forms):**

```bash
backlog task edit 42 --notes "First line"
backlog task edit 42 --append-notes "Second line"
backlog task edit 42 --append-notes "Third line"
```

**2. Real newlines inside double quotes (single command — pass an actual line break inside the string):**

```bash
backlog task edit 42 --notes "First line
Second line

Final paragraph"
```

The same shape works for `--desc`, `--plan`, `--comment`, `--final-summary`, and the `--append-*` variants.

**3. Shell-specific shorthand (interactive shells only — some AI agent sandboxes reject these):**

- Bash/Zsh (ANSI‑C quoting):

  ```bash
  backlog task edit 42 --notes $'Line1\nLine2'
  ```

- POSIX sh (command substitution + printf):

  ```bash
  backlog task edit 42 --notes "$(printf 'Line1\nLine2')"
  ```

- PowerShell (backtick‑n):

  ```powershell
  backlog task edit 42 --notes "Line1`nLine2"
  ```

Prefer forms **1** and **2** when running under Claude Code, Codex, or any agent harness that screens commands through a tree‑sitter AST walker — those harnesses reject ANSI‑C strings, command substitutions, and heredoc forms (see issue [#595](https://github.com/MrLesk/Backlog.md/issues/595)).

Do not expect the literal sequence `\n` inside double quotes to become a newline. The CLI stores the backslash and `n` as written.

### Implementation Notes Formatting

- Keep implementation notes concise and time-ordered; focus on progress, decisions, and blockers.
- Use short paragraphs or bullet lists instead of a single long line.
- Use Markdown bullets (`-` for unordered, `1.` for ordered) for readability.
- When using CLI flags like `--append-notes`, remember to include explicit
  newlines. Either repeat the flag once per line:

  ```bash
  backlog task edit 42 --append-notes "- Added new API endpoint" \
    --append-notes "- Updated tests" \
    --append-notes "- TODO: monitor staging deploy"
  ```

  Or pass real newlines inside the quoted argument:

  ```bash
  backlog task edit 42 --append-notes "- Added new API endpoint
  - Updated tests
  - TODO: monitor staging deploy"
  ```

### Comments Formatting

- Use comments for task discussion, review notes, questions, and handoff context that should remain visible to humans and agents.
- Comments are append-only via `backlog task edit <id> --comment "..."`; include `--comment-author @name` when attribution is useful.
- Comment bodies may contain Markdown, but standalone `---` lines are reserved as comment delimiters.
- Do not use comments as the primary execution log; use Implementation Notes for progress and Final Summary for the PR description.

### Final Summary Formatting

- Treat the Final Summary as a PR description: lead with the outcome, then add key changes and tests.
- Keep it clean and structured so it can be pasted directly into GitHub.
- Prefer short paragraphs or bullet lists and avoid raw progress logs.
- Aim to cover: **what changed**, **why**, **user impact**, **tests run**, and **risks/follow‑ups** when relevant.
- Avoid single‑line summaries unless the change is truly tiny.

**Example (good, not rigid):**
```
Added Final Summary support across CLI/MCP/Web/TUI to separate PR summaries from progress notes.

Changes:
- Added `finalSummary` to task types and markdown section parsing/serialization (ordered after notes).
- CLI/MCP/Web/TUI now render and edit Final Summary; plain output includes it.

Tests:
- bun test src/test/final-summary.test.ts
- bun test src/test/cli-final-summary.test.ts
```

### Task Images (Local Assets)

Tasks may include images for screenshots, diagrams, or visual references. Local images are served automatically when using `backlog browser`.

**Storage location:**
- Place image files under the `assets/` folder inside your backlog directory (e.g., `backlog/assets/images/screenshot.png`)

**Supported formats:**
- png, jpg, jpeg, gif, svg, webp, avif (served with correct Content-Type)

**Markdown syntax in tasks:**
```markdown
![example](assets/images/screenshot.png)
```

**Workflow when adding images to tasks:**
1. Move or copy the image file into the `assets/` folder inside your backlog directory (e.g., `backlog/assets/images/screenshot.png`)
2. Then add or edit the task content via CLI, referencing the image using the `assets/<relative-path>` path

**Key points:**
- The path in Markdown starts with `assets/` and maps to the backlog directory's `assets/` folder; do **not** include the backlog directory name itself
- When `backlog browser` is running, these files are automatically available at `assets/<relative-path>`
- You can add images to descriptions, implementation notes, or final summaries using the standard CLI commands

### Document Management

> Docs are used for long-term project reference information, such as development standards, configuration guides, architecture documentation, etc. They differ from `tasks/` (specific tasks), `decisions/` (decision records), and `drafts/` (drafts).

Use Backlog.md public interfaces for document creation and updates so IDs, frontmatter, paths, and search metadata stay consistent.

#### CLI Usage

The CLI supports creating, updating, listing, and viewing documents.

```bash
# Create a new doc (saved under backlog/docs/ by default)
backlog doc create "API Guidelines"

# Create in a subdirectory (nested paths supported)
backlog doc create "Setup Guide" -p guides/setup

# Specify type at creation time
backlog doc create "Architecture" -t guide

# Update content while preserving omitted metadata
backlog doc update doc-1 --content "Updated markdown"

# Update metadata or move a doc within backlog/docs/
backlog doc update doc-1 --title "Setup Handbook" -t guide --tags setup,runbook -p guides

# List all docs (searched globally across subdirectories)
backlog doc list

# View a specific doc
backlog doc view doc-1
```

#### MCP / API Usage

- Use `document_create` to create documents with title, content, optional type/tags, and optional docs-directory-relative path.
- Use `document_update` to update document content, title, type, tags, or path while preserving document metadata.
- Document responses include the persisted docs-relative file path so agents can reference the created file without scanning source internals.

#### Key Rules

- Document paths are relative to `backlog/docs/`; absolute paths and `..` traversal are rejected.
- Supported document types are `readme`, `guide`, `specification`, and `other`.
- Document IDs are global across the entire docs tree, including nested subfolders.
- Prefer CLI, MCP, or Web document APIs over ad-hoc file writes so frontmatter and metadata remain valid.

### Task Operations

| Action             | Command                                      |
|--------------------|----------------------------------------------|
| View task          | `backlog task 42 --plain`                    |
| List tasks         | `backlog task list --plain`                  |
| Search tasks       | `backlog search "topic" --plain`              |
| Search with filter | `backlog search "api" --status "To Do" --plain` |
| Search by modified file | `backlog search --modified-file src/api.ts --plain` |
| Filter by status   | `backlog task list -s "In Progress" --plain` |
| Filter by assignee | `backlog task list -a @sara --plain`         |
| Archive task       | `backlog task archive 42`                    |
| Demote to draft    | `backlog task demote 42`                     |

---

## Common Issues

| Problem              | Solution                                                           |
|----------------------|--------------------------------------------------------------------|
| Task not found       | Check task ID with `backlog task list --plain`                     |
| AC won't check       | Use correct index: `backlog task 42 --plain` to see AC numbers     |
| Changes not saving   | Ensure you're using CLI, not editing files                         |
| Metadata out of sync | Re-edit via CLI to fix: `backlog task edit 42 -s <current-status>` |

---

## Remember: The Golden Rule

**🎯 If you want to change ANYTHING in a task, use the `backlog task edit` command.**
**📖 Use CLI to read tasks, exceptionally READ task files directly, never WRITE to them.**

Full help available: `backlog --help`

<!-- BACKLOG.MD GUIDELINES END -->
