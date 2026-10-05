#!/bin/sh
# board-status.sh NUMBER STATUS moves the card of issue NUMBER of
# $GITHUB_REPOSITORY to the Status option named STATUS (case does not
# matter), on every Projects board of the repository's owner that holds
# the issue.
#
# The board only mirrors the ai:* labels: a project owned by a user
# starts no workflow, so the labels are what triggers. Such a project
# takes only a classic personal access token with the project scope,
# given in PROJECT_PAT; without it the script says so and exits 0. An
# issue that is on no board, and a board without the option, are skipped
# with a message. docs/agents.md has the Status options.
set -eu

die() {
	echo "board-status: $*" >&2
	exit 1
}

[ $# -eq 2 ] || die "usage: board-status.sh NUMBER STATUS"
n=$1 status=$2
case $n in
'' | *[!0-9]*) die "not an issue number: $n" ;;
esac
if [ -z "${PROJECT_PAT:-}" ]; then
	echo "board-status: no PROJECT_PAT secret; the board is not updated"
	exit 0
fi
owner=${GITHUB_REPOSITORY%%/*}

# One line per card on a board of the owner: board number, project,
# item and Status field ids, and the id of the wanted option ("-" when
# the board has no such field or option).
# shellcheck disable=SC2016 # $names are GraphQL and jq variables
cards=$(GH_TOKEN=$PROJECT_PAT gh api graphql -F number="$n" \
	-f owner="$owner" -f repo="${GITHUB_REPOSITORY#*/}" -f query='
query($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      projectItems(first: 20, includeArchived: false) {
        nodes {
          id
          project {
            id
            number
            owner { ... on User { login } }
            field(name: "Status") {
              ... on ProjectV2SingleSelectField { id options { id name } }
            }
          }
        }
      }
    }
  }
}' | jq -r --arg owner "$owner" --arg status "$status" '
	.data.repository.issue.projectItems.nodes[]
	| select((.project.owner.login // "" | ascii_downcase) == ($owner | ascii_downcase))
	| .project as $p
	| [$p.number, $p.id, .id, ($p.field.id // "-"),
	   ([$p.field.options[]? | select((.name | ascii_downcase) == ($status | ascii_downcase)) | .id][0] // "-")]
	| @tsv')

if [ -z "$cards" ]; then
	echo "board-status: issue #$n is on none of $owner's boards"
	exit 0
fi
tab=$(printf '\t')
printf '%s\n' "$cards" | while IFS=$tab read -r board project item field option; do
	if [ "$field" = - ] || [ "$option" = - ]; then
		echo "board-status: board $board has no Status option \"$status\"; skipped"
		continue
	fi
	# shellcheck disable=SC2016 # GraphQL variables
	GH_TOKEN=$PROJECT_PAT gh api graphql --silent \
		-f project="$project" -f item="$item" -f field="$field" -f option="$option" -f query='
mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {
    projectId: $project, itemId: $item, fieldId: $field,
    value: {singleSelectOptionId: $option}
  }) { projectV2Item { id } }
}'
	echo "board-status: issue #$n is \"$status\" on board $board"
done
