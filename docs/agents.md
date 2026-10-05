# Agents in this repository's GitHub workflow

This page is for the owner. It says what the agent workflows do, why they act
only on the owner's own triggers, how to turn them on, and what they do not
protect against. Merging them changes nothing: every workflow here does nothing
until the repository variable `AGENTS_ENABLED` is `true`.

| You do | Workflow | Result |
|---|---|---|
| Comment `@claude ...` (first thing in the comment) on your own issue or pull request, or on a diff line of your own pull request | `claude.yml`, job `mention` | Claude Code answers in one comment and may commit to a `claude/` branch or the pull request's branch |
| Add `ai:implement` to your own open issue | `claude.yml`, jobs `claim`, `implement`, `publish` | a draft pull request labelled `agent-created`, or `ai:blocked` and `needs-human` on the issue |
| Add `ai:review` to your own pull request from this repository | `codex-review.yml` | one Codex `COMMENT` review; the label comes off |
| Comment `@codex review` on a pull request | none: Codex cloud's own GitHub integration | a Codex review |
| Drag your issue's card to "AI To Do" | `ai-poll.yml` (untested, off unless `AGENTS_BOARD` is `true`) | the issue gets `ai:implement` within about 15 minutes |
| Anyone else adds an `ai:*` label | `agent-labels.yml` | the label comes off |

## How it works and why it is safe

The repository is public. Anyone can open issues, comment and open pull requests
from forks. `issues` and `issue_comment` workflows run on the default branch
with the repository's secrets, whoever wrote the text. An agent that holds
secrets or a write token and reads a stranger's text can be steered by it; the
2025 and 2026 incidents with agents in CI were all this pattern. So the agents
here act only on what the owner wrote, and only when the owner asks.

**Threat model.** What is protected: the model API keys, the write scopes of
the workflow token, the project token, the default branch, and the owner's
budget and attention. Who is kept out:

- **Other people.** Every agent job requires the event's sender to be the owner
  (`github.event.sender.login == github.repository_owner`, `sender.type ==
  'User'`) and the issue or pull request to be the owner's. A comment must also
  be the owner's and start with `@claude`. The mention job passes
  `include_comments_by_actor: <owner>`, so the action shows Claude only the
  owner's comments. The implement job is in agent mode, where the action does
  not filter comments, so it writes the owner's text to a file itself: the title
  and body from the label event, and the owner's comments from before the label
  was added. Its prompt says that only that text is instructions.
- **Bots and GitHub Apps.** `sender.type == 'User'` turns them away, and
  `allowed_bots` stays empty, never `'*'`. A fork's pull request is never
  reviewed or answered (`head.repo.full_name == github.repository`).
- **The owner's own agents.** Claude Code cloud sessions and routines act as
  the owner's GitHub identity: their comments, labels and pull requests have
  the owner's login and type `User`, and no owner gate can tell them apart. So
  agent output is marked and the workflows ignore it; see
  [Loop prevention](#loop-prevention).
- **A misled agent.** Each run is bounded by `--max-turns`, `--max-budget-usd`
  and `timeout-minutes`, and has no WebFetch or WebSearch. The implement agent
  gets a read-only token: it can only leave commits and a final message behind.
  A separate job, which never sees the model key and runs nothing the agent
  wrote, checks the commits, pushes them to `claude/issue-N-RUN`, opens a
  **draft** pull request and posts the agent's text sanitised (`<!--` broken,
  `@` mentions neutralised). It refuses commits that change `.github/`,
  `.claude/`, `.mcp.json`, `CLAUDE.md` or `AGENTS.md`. The implement agent can
  neither push, approve nor merge; what the mention agent could do is under
  [Remaining gaps](#remaining-gaps).

Other rules the workflows follow: no `pull_request_target`, no `workflow_run`;
every `${{ github.event.* }}` text reaches a script through `env:`, never inside
`run:`; `permissions: {}` at the top and the least each job needs; every
action is pinned by its full commit SHA; `persist-credentials: false`. The
model keys live in the `agent` environment, not in the repository's secrets.

The action gets the job's `GITHUB_TOKEN` (`github_token` input), not the Claude
GitHub App. GitHub starts no workflow for an event made with that token, so
nothing an agent writes (a comment, a label, a commit, a pull request) can
start another agent. The cost: CI does not run on an agent's draft or commits by
itself. Read the change, then run CI (close and reopen the draft, or run `ci`
from the Actions tab on its branch).

## How to enable it

1. **Labels.** The labels below must exist; another change adds them through
   `.github/labels.yml`.
2. **Environment `agent`** (Settings, Environments):
   - Secret `ANTHROPIC_API_KEY`: a key used for nothing else, with a spend
     limit in the Anthropic Console. Instead you can set
     `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`, billed to your
     subscription); the workflows pass both inputs and the action takes
     whichever is set. The Claude GitHub App is not needed: the workflows give
     the action `GITHUB_TOKEN`. Installing the App and dropping `github_token`
     would make the agents' pushes run CI, but App events do start workflows.
   - Secret `OPENAI_API_KEY`, only for `codex-review.yml`: also dedicated and
     spend-capped.
   - Optional second key: add yourself as a **required reviewer**. Every agent
     job then waits for your approval in the Actions page. An agent acting as
     you could approve through the API only if its credentials reach that
     endpoint, which is unverified for cloud sessions. Leave "Prevent
     self-review" off, since you are both the one who triggers and the
     reviewer.
   - Leave deployment branches unrestricted: review-comment and `ai:review` runs
     run on `refs/pull/N/merge`, not on `main`.
3. **Repository secrets** (Settings, Secrets and variables, Actions), only for
   the board:
   - `PROJECT_PAT`: a classic personal access token with only the `project`
     scope. A project owned by a user takes no fine-grained token, GitHub App
     token or `GITHUB_TOKEN`. Without it the board is left alone and everything
     else works.
   - `LABEL_PAT`, only for `ai-poll.yml`: a fine-grained token for this
     repository only, with Issues read and write. The poll adds `ai:implement`
     with it, because a label added with `GITHUB_TOKEN` starts no workflow.
4. **Repository variables**: `AGENTS_ENABLED` = `true` turns the workflows on;
   delete it or set anything else to stop them all. `AGENTS_BOARD` = `true`
   turns on the poll.
5. **Actions settings** (Settings, Actions, General): tick "Allow GitHub
   Actions to create and approve pull requests", or `publish` cannot open the
   draft. It then pushes the branch and says so on the issue, which ends up
   `ai:blocked`. The setting also lets any job with `pull-requests: write`
   approve a pull request: the implement agent has no such token, the mention
   agent has (see the gaps below). Also keep "Require approval for all
   external contributors" for fork pull requests.
6. **A ruleset for `main`**: require a pull request and block force pushes.
   `GITHUB_TOKEN` cannot get past it, so no agent can push to `main`.
7. **The project** (a Projects board owned by you): a single-select field
   `Status` with the options **AI To Do**, **In Progress**, **Review**,
   **Blocked** and **Done**. Keep the built-in workflow "Item closed" setting
   Done, and add issues to the board (by hand, or with the auto-add workflow).
   An issue on no board is skipped.
8. **Codex cloud**: turn its automatic reviews off for this repository, and
   type `@codex review` yourself when you want one.

## Labels

| Label | Kind | Who sets it | Meaning |
|---|---|---|---|
| `ai:implement` | trigger, issue | you | Claude implements the issue as a draft pull request; the workflow takes the label off at once |
| `ai:review` | trigger, pull request | you | one Codex review; the workflow takes it off |
| `ai:fix` | trigger, pull request | you | reserved for one fix round; no workflow acts on it yet |
| `ai:working` | state | the workflow, with `GITHUB_TOKEN` | a run holds the issue |
| `ai:done` | state | the workflow | the draft pull request is open |
| `ai:blocked` | state | the workflow | the run ended without a pull request; the reason is on the issue |
| `needs-human` | control | the workflow, with `ai:blocked` | agents stop; adding `ai:implement` again clears it |
| `agent-created` | provenance | agents, and the workflow on its drafts | agent output; workflows ignore anything that carries it |
| `no-agent` | veto | you | no workflow acts on the issue or pull request |

`agent-labels.yml` takes off any `ai:*` label put on by someone other than you,
and the `ai:*` labels an issue someone else opened came with (an issue template
can add labels whoever opens it). Never put `ai:*` labels in a template.

## The board

GitHub starts no workflow when a card moves on a project owned by a user, so
the label is the trigger and the board mirrors the state.
`.github/scripts/board-status.sh` moves the issue's card when the labels change:
In Progress when a run takes the issue, Review when the draft opens, Blocked
when it ends without one. Done comes from the project's own "Item closed"
workflow when the issue closes.

To start work from the board instead of a label, turn on `ai-poll.yml`
(`AGENTS_BOARD` = `true`, `PROJECT_PAT` and `LABEL_PAT`). Every 15 minutes
`.github/scripts/board-poll.sh` looks at your open issues and labels at most one
with `ai:implement`: one whose card is in "AI To Do", whose newest Status change
is to "AI To Do", made by you (`actor.login` is the owner) and not by a project
workflow (`wasAutomated == false`), and newer than the issue's last
`ai:implement` label event. It labels nothing while an issue has `ai:working`.
The workflows move cards with your token too, but never to "AI To Do", so their
moves never count. A scheduled run is noise in the Actions list while the poll
is off; disable the workflow there if you do not use the board.

## Loop prevention

- Agent output carries the `agent-created` label (issues and pull requests) and
  an `<!-- agent:<tool> -->` marker in its body. No workflow acts on a comment,
  issue or pull request that carries either. To hand an agent's issue or pull
  request to an agent, adopt it first: take off `agent-created` and delete the
  marker line.
- Triggers are consumed: `ai:implement` and `ai:review` come off when a run
  takes them, so one label is one run.
- State labels, comments, branches and drafts are written with `GITHUB_TOKEN`,
  whose events start no workflow.
- Comments trigger only when they start with `@claude`, so an agent quoting the
  phrase mid-sentence does not. Sanitised agent text has no live `@` mention.
- One run per issue at a time (`concurrency` per issue, not cancelling), with
  turn, budget and time limits. An `ai:implement` run holds the issue until its
  publish job has set the labels, so a label reapplied meanwhile starts only
  after it. A third request while one runs and one waits replaces the waiting
  one.
- `AGENTS_ENABLED` stops everything; `no-agent` stops one item.

## Remaining gaps

- **An agent acting as you can trigger an agent.** A cloud session or routine
  that adds `ai:implement`, comments `@claude` without the marker, or drags a
  card does so as you, and the gates let it through. Two mitigations:
  a PreToolUse hook in the agent's own settings (the repository's
  `.claude/settings.json`, or the routine's) that refuses `ai:*` and
  `no-agent`/`needs-human` label changes, project Status changes and comments
  that start with a trigger; and the `agent` environment with you as required
  reviewer, an optional second key, so every run also needs your approval in
  the Actions page. Rules in AGENTS.md alone are advice, not enforcement.
- **The mention agent holds a write token for its run.** Tag mode limits its
  tools to reading, editing and git, but a misled agent there could push to an
  unprotected branch or, with the Actions setting above, approve a pull
  request. The ruleset on `main` is what keeps it out of `main`.
- **The implement agent runs code.** `go test` runs whatever the agent wrote,
  with network access. It can read the model key (`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`
  removes it from commands' environments on a best-effort basis), so the key is
  dedicated and capped. Code it runs could also tamper with the later steps of
  its own job and write to the default branch's Actions cache, which CI
  restores; that job uses no Go cache itself, and release builds use none.
- **Sanitising is not a filter.** It stops hidden comments and mentions, not an
  agent that writes out something secret it has read.
- **Codex cloud is outside these workflows.** `@codex` is answered by OpenAI's
  GitHub App, which no workflow here can gate. Who besides you can invoke it on
  a public repository is not documented; keep its automatic reviews off and
  check once with another account.
- **Only your own pull requests get `ai:review` or `@claude` on a diff line.**
  A draft from `ai:implement` is opened by `github-actions[bot]`, so it fails
  the owner gate; ask for a Codex review with `@codex review`, or continue on
  the issue.
- **Repository secrets reach any workflow in the repository**, including one on
  a branch. `PROJECT_PAT` is limited to the `project` scope and `LABEL_PAT` to
  this repository's issues. A required reviewer on `agent` keeps the model keys
  from a workflow that a branch adds.
- **A fork's pull request keeps foreign labels**: on `pull_request` a fork gets
  a read-only token. No agent acts on a fork's pull request.

## Untested

No workflow here has run yet; they pass actionlint, and the scripts were run
against recorded API shapes only. Least certain, and worth one throwaway issue
each:

- the whole of `ai-poll.yml`: the Status change event on a board owned by a user,
  its `actor` and `wasAutomated` there, and whether the 100 most recently
  updated open issues include a card that just moved;
- `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` in the action's tag and agent modes on a
  hosted runner;
- `gh auth setup-git` with only `GH_TOKEN` set, used by `publish` to push;
- the `labeled` event for labels an issue template adds, and its sender.
