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
already ran is not undone. A rollback waits for a run of the session that is still
going, from the moment `run --session` takes the session, and the session is not
resumed while a rollback works on it; a run that was killed does not hold it up. It puts the agent's versions back
inside the session's branch and nowhere else. If the agent made a directory on the way there,
or the branch itself, a link out of the branch (in a run resumed after a partial
apply, say), the rollback stops at that path and keeps your versions from before
the apply in the session. Whatever the agent has put at the path itself stays
there as its version, a link included, for the next review to show.

A session records the directories its workspace and a branched `$HOME` were when it
began; on macOS, which never branches `$HOME`, it records the `$HOME` it keeps the
agent's state in. If one is another directory now (moved away, with a link or a new
directory at its path), run, apply, rollback and resume change nothing there and say
so, and the outbox runs nothing while the workspace is; put the directory back first.
Apply and rollback leave a `$HOME` that is not branched alone; on Linux nothing writes
in it at all. On macOS one that could not be recorded (not there, `HOME=/nonexistent`,
say) keeps the agent's state read-only. What the outbox runs on the host, a push or a
deferred command you confirm, runs as you, with your environment and `$HOME` as they
are then, as it would from your own shell. A rollback that finds it so part way stops there and keeps
what is left in its journal; until `airbag rollback` is run again to finish it, apply
refuses. A directory is told by its path, inode, device and, where
the filesystem keeps them, its creation time, inode generation and filesystem ID.
On NFS or FUSE, which keep neither of the first two, a directory removed and made
again with the same inode number passes. A filesystem mounted again under a new
device number passes only where it keeps a creation time and an ID of its own
(ext4, btrfs, an overlay: a container restarted between the run and the apply). On
macOS, NFS and FUSE, and on xfs whose device is renumbered, it is refused, since
nothing tells it from another one: take what you need from `airbag diff`, then
discard the session. On an overlay airbag copies the workspace's directory up to the
top layer when the session begins (it sets the directory's times to what they are),
so it keeps one creation time; a new container from the same image has another. Where
it cannot (a read-only overlay, or a directory you may not write), `airbag run` refuses
to begin, since a directory made again there would pass. Sessions made by development builds from before this check
record nothing and are not checked: discard them.

## Apply onto a git branch

`apply --branch NAME` leaves your working tree alone and puts the result on a new
branch of the repository instead: the agent's commits, fetched with their history,
then one commit with whatever it left uncommitted (files your `.gitignore` excludes
stay out). Your index, uncommitted edits, `.git/config` and hooks are not touched,
and the agent's git config and hooks are never carried over. Review and merge it
with git as you would a colleague's branch. Changes in `~` stay in the session, and
a queued push is left to you: the work is on the new branch now.
