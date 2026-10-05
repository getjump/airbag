#!/bin/sh
# labels.sh NUMBER [+LABEL | -LABEL]... adds (+) and removes (-) labels
# on issue or pull request NUMBER of $GITHUB_REPOSITORY, in the order
# given, with the token in GH_TOKEN. Removing a label the item does not
# carry is not an error.
#
# The agent workflows run it with GITHUB_TOKEN: a label event made with
# that token starts no workflow, so a state label can never trigger an
# agent. docs/agents.md has the label scheme.
set -eu

die() {
	echo "labels: $*" >&2
	exit 1
}

[ $# -ge 2 ] || die "usage: labels.sh NUMBER [+LABEL | -LABEL]..."
n=$1
shift
case $n in
'' | *[!0-9]*) die "not an issue or pull request number: $n" ;;
esac
for arg in "$@"; do
	case $arg in
	[+-]?*) ;;
	*) die "want +LABEL or -LABEL, got '$arg'" ;;
	esac
done
api=repos/$GITHUB_REPOSITORY/issues/$n/labels

have=$(gh api --paginate "$api" --jq '.[].name')
for arg in "$@"; do
	name=${arg#?}
	case $arg in
	+*)
		gh api -X POST "$api" -f "labels[]=$name" --silent
		echo "labels: #$n +$name"
		;;
	-*)
		# GitHub compares label names without case.
		if printf '%s\n' "$have" | grep -Fxiq -- "$name"; then
			gh api -X DELETE "$api/$(printf %s "$name" | jq -sRr @uri)" --silent
			echo "labels: #$n -$name"
		fi
		;;
	esac
done
