# Review and apply

`airbag review` shows what the agent changed, sent and queued, in one place:

```
Workspace  /home/me/api
  Files    +3 ~2 -1    (git internals: 14 files)
  + .git/hooks/pre-commit  persist
  + leak.txt  secret in diff
Home       1 changes outside the workspace
  ~ ~/.bashrc  persist
Network    31 allowed: api.anthropic.com ×30, proxy.golang.org ×1
           1 denied: paste.example.net:443 ×1
Outbox     1
  i-1  git push origin feature/retry               pending
```

`airbag review --attention` prints only what needs a decision: secret reads, flagged
changes, every change in `$HOME` that apply would carry over other than an agent
config change of benign keys only (with the file's mode unchanged), many
deletions, waiting pushes, blocked calls, refusals past the log's rate. Caches and
agent state are not carried over, so they need no decision; a repository's git
directory in `$HOME` is one line with its count of files. In `$HOME` a change is matched by where the write really landed,
so one made through a link (`~/.bashrc` pointing into `~/dotfiles`) shows as a change
to the link's target, which needs a decision even when review cannot tell what the
link stands for. `airbag review --json` prints
the whole review as data for editors and CI, with a versioned schema
(`airbag.review/v1`; fields are only added within a version).

It flags persistence (git hooks, shell rc files, CI config, agent settings), new
executables, changes outside the workspace and values from your `.env` files that
ended up in the diff. `apply` refuses to overwrite files you changed on the host
while the agent worked. `apply -i` goes through the changes one by one (git
internals and caches come as one piece each) and keeps the rejected ones in the
session; `apply --only PATH` takes just part of the branch.

## Apply and rollback

An apply is all or nothing: before a real file changes, what was there moves into
the session, so a step that fails puts back the ones before it. `airbag rollback`
undoes the last apply the same way, and the agent's changes go back into the session
to apply again or discard; a file you edited after the apply is left as it is, and
its version from before the apply stays in the session: `airbag discard` refuses
to delete it until a later rollback restores it, or you pass `--force`. A push that
already ran is not undone.

A session records the directories its workspace and `$HOME` were when it began.
If one is another directory now (moved away, with a link or a new directory at its
path), apply, rollback, resume and the outbox change nothing there and say so; put
the directory back first. A directory is told by its path, inode, device and, where
the filesystem keeps them, its creation time, inode generation and filesystem ID;
on NFS or FUSE, which keep neither of the first two, a directory removed and made
again with the same inode number passes. Sessions made by development builds from
before this check record nothing and are not checked: discard them.

## Apply onto a git branch

`apply --branch NAME` leaves your working tree alone and puts the result on a new
branch of the repository instead: the agent's commits, fetched with their history,
then one commit with whatever it left uncommitted (files your `.gitignore` excludes
stay out). Your index, uncommitted edits, `.git/config` and hooks are not touched,
and the agent's git config and hooks are never carried over. Review and merge it
with git as you would a colleague's branch. Changes in `~` stay in the session, and
a queued push is left to you: the work is on the new branch now.
