# Is airbag worth using? An evaluation plan

The niche is crowded: agents ship their own sandboxes, and nono, AgentFS,
Docker Sandboxes with Code Airlock, and agentsh cover parts of what airbag
does (see the [comparison](comparison.md)). Whether airbag earns a place is a
question for measurement on real work, before more features. This page is the
plan; results go below it.

## The claim to test

A developer starts a long agent task, goes to do something else, and comes back
to: the real files untouched, a review that shows what changed in code and
config, what reached the network and what waits to be pushed, and a way to take
the useful part onto a branch and drop the rest.

## Against what

The same tasks with each of:

1. **Built-in sandbox and a worktree.** `git worktree add`, the agent's own
   sandbox (`claude` with `sandbox.enabled`, `codex --sandbox workspace-write`),
   review with `git diff`.
2. **nono** with `--rollback`.
3. **Code Airlock** (Docker Sandboxes in clone mode).
4. **airbag**, `airbag run`, then `review` and `apply --branch`.

## Tasks

Five real tasks in two or three repositories you already work in, each long
enough to leave unattended (15 to 60 minutes):

- a refactor across many files;
- a dependency upgrade with a broken build to fix;
- a feature with tests and a database the project runs in docker compose;
- a task that reads `.env` to run the app;
- a task that ends with a push and a pull request (for airbag, `gh pr create` in
  `defer:`).

Run each task once per tool, in an order that varies so learning does not
favour the last one.

## What to record per run

| Measure | How |
|---|---|
| Time from install to the first successful session | wall clock, once per tool |
| Finished without repairing the environment | yes or no; what had to be fixed |
| Human interventions during the run | count of prompts answered or manual steps |
| Review time and noise | minutes to decide; lines in the review that did not matter |
| Correctness with a dirty repository | uncommitted and untracked files before the run, and edits made during it: were they kept, overwritten or flagged |
| After an interruption | kill the agent mid-run, then resume or apply: what state is left |
| Repeated apply | apply, change your mind, roll back or apply again |
| Secrets | did the task need `.env`; did the tool hide, track or leak it |
| Credentials for reading | did the task need a token just to read (a private registry, `gh pr list`), and what happened without it |

Keep the raw notes per run; the summary goes in a table here.

## A narrow release

After the comparison, give one build to about ten developers outside this
project, with a one-page quickstart and no other help. After two weeks ask:

- how many times a week they used it, unprompted;
- what they stopped doing because of it: watching the terminal, copying the
  project, restoring files, carrying results over by hand;
- what made them stop, if they stopped.

Continue past this point if at least half use it several times a week on their
own and a few choose it over what they did before. That threshold is a choice
for this experiment, not a forecast.

## Results

None yet.
