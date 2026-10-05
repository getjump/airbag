#!/bin/sh
# board-poll.sh STATUS puts ai:implement on one open issue of the
# repository owner's that the owner moved to the Status option STATUS
# ("AI To Do") on one of their Projects boards. ai-poll.yml runs it: a
# project owned by a user starts no workflow, so this turns the owner's
# move into the label that starts claude.yml.
#
# An issue qualifies when
#   - the owner wrote it, and it carries neither the <!-- agent: marker
#     nor the labels agent-created, no-agent, ai:implement or ai:working;
#   - its card on a board of the owner's is in STATUS now;
#   - its newest Status change there is to STATUS, by the owner, and not
#     by a project workflow (wasAutomated false);
#   - that change is newer than the issue's last ai:implement label
#     event, so a card claude.yml has already taken is not taken again.
# Nothing is labelled while an issue carries ai:working, and at most one
# issue per run. The workflows move cards with the owner's token too, so
# their moves also read as the owner's; they never move a card to STATUS.
#
# PROJECT_PAT (classic, project scope) reads the board. LABEL_PAT
# (fine-grained, this repository, issues read and write) adds the label:
# one added with GITHUB_TOKEN would start no workflow. Without either the
# script says so and exits 0.
#
# Untested against GitHub: the status change event on a board owned by a
# user, and the issue order (the 100 open issues updated last).
set -eu

die() {
	echo "board-poll: $*" >&2
	exit 1
}

[ $# -eq 1 ] || die "usage: board-poll.sh STATUS"
status=$1
if [ -z "${PROJECT_PAT:-}" ] || [ -z "${LABEL_PAT:-}" ]; then
	echo "board-poll: PROJECT_PAT or LABEL_PAT is not set; nothing to do"
	exit 0
fi
owner=${GITHUB_REPOSITORY%%/*}

# shellcheck disable=SC2016 # $names are GraphQL and jq variables
data=$(GH_TOKEN=$PROJECT_PAT gh api graphql \
	-f owner="$owner" -f repo="${GITHUB_REPOSITORY#*/}" -f query='
query($owner: String!, $repo: String!) {
  repository(owner: $owner, name: $repo) {
    issues(first: 100, states: OPEN, filterBy: {createdBy: $owner},
           orderBy: {field: UPDATED_AT, direction: DESC}) {
      nodes {
        number
        body
        author { login }
        labels(first: 50) { nodes { name } }
        projectItems(first: 10, includeArchived: false) {
          nodes {
            project { owner { ... on User { login } } }
            fieldValueByName(name: "Status") {
              ... on ProjectV2ItemFieldSingleSelectValue { name }
            }
          }
        }
        timelineItems(last: 50, itemTypes: [PROJECT_V2_ITEM_STATUS_CHANGED_EVENT,
                                            LABELED_EVENT, UNLABELED_EVENT]) {
          nodes {
            __typename
            ... on ProjectV2ItemStatusChangedEvent {
              createdAt status wasAutomated
              actor { login }
              project { owner { ... on User { login } } }
            }
            ... on LabeledEvent { createdAt label { name } }
            ... on UnlabeledEvent { createdAt label { name } }
          }
        }
      }
    }
  }
}')

# shellcheck disable=SC2016 # jq variables
numbers=$(printf '%s\n' "$data" | jq -r --arg owner "$owner" --arg status "$status" '
	def lc: ascii_downcase;
	def owned: (.login // "" | lc) == ($owner | lc);
	.data.repository.issues.nodes
	| if any(.[]; any(.labels.nodes[]; .name | lc == "ai:working")) then empty else .[] end
	| select(.author | owned)
	| select((.body // "") | contains("<!-- agent:") | not)
	| select(all(.labels.nodes[]; .name | lc | IN("agent-created", "no-agent", "ai:implement", "ai:working") | not))
	| select(any(.projectItems.nodes[];
		(.project.owner | owned) and ((.fieldValueByName.name // "") | lc) == ($status | lc)))
	| ([.timelineItems.nodes[]
		| select(.__typename == "ProjectV2ItemStatusChangedEvent" and (.project.owner | owned))]
		| last) as $move
	| ([.timelineItems.nodes[]
		| select(.__typename != "ProjectV2ItemStatusChangedEvent" and (.label.name // "" | lc) == "ai:implement")]
		| last) as $label
	| select($move != null
		and ($move.status | lc) == ($status | lc)
		and ($move.actor | owned)
		and $move.wasAutomated == false
		and ($label == null or $move.createdAt > $label.createdAt))
	| .number')

n=$(printf '%s\n' "$numbers" | head -n 1)
if [ -z "$n" ]; then
	echo "board-poll: no card that $owner moved to \"$status\" is waiting"
	exit 0
fi
GH_TOKEN=$LABEL_PAT gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$n/labels" \
	-f 'labels[]=ai:implement' --silent
echo "board-poll: $owner moved #$n to \"$status\"; labelled ai:implement"
