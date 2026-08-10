#!/usr/bin/env bash
# SessionStart hook: start every session on the latest code, and surface any PR
# that is sitting open waiting to be merged.
#
# Why this exists: #75 and #76 were open at the same time and collided in
# changelog.yaml and in a file one of them deleted. Neither branch was wrong —
# the second one was simply started without looking at what was already in
# flight. Answering "what is already open?" before the first edit is cheaper
# than resolving it afterwards.
#
# This never fails a session. Every step degrades to a note in the report: no
# network, no gh auth, and a detached HEAD all produce output rather than an
# error, because a hook that blocks startup is worse than a stale checkout.
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 0

# Network calls are bounded. A SessionStart hook blocks the prompt, so a stalled
# fetch would otherwise hold the terminal with no indication of why.
NET_TIMEOUT="${SESSION_START_NET_TIMEOUT:-15}"

report=""
add() { report+="$1"$'\n'; }

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    exit 0
fi

branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
dirty=$(git status --porcelain 2>/dev/null)

if timeout "$NET_TIMEOUT" git fetch --prune --quiet 2>/dev/null; then
    fetched=yes
else
    fetched=no
    add "git fetch failed or timed out after ${NET_TIMEOUT}s — the state below may be stale."
fi

if [ "$branch" = "HEAD" ]; then
    add "Detached HEAD; skipped pull."
elif ! upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null); then
    add "Branch '$branch' has no upstream; nothing to pull."
else
    behind=$(git rev-list --count "HEAD..$upstream" 2>/dev/null || echo 0)
    ahead=$(git rev-list --count "$upstream..HEAD" 2>/dev/null || echo 0)

    if [ "$behind" = "0" ]; then
        # Not ${ahead:+...} — that expands on the string "0" as readily as "3".
        if [ "$ahead" != "0" ]; then
            add "On '$branch', up to date with $upstream (ahead $ahead unpushed)."
        else
            add "On '$branch', up to date with $upstream."
        fi
    elif [ -n "$dirty" ]; then
        # A pull here would either fail or start a merge on top of work in
        # progress. Reporting is the useful move; deciding is the user's.
        add "On '$branch', BEHIND $upstream by $behind commit(s), but the working tree is dirty — skipped the pull. Run 'git stash && git pull --ff-only' or commit first."
    elif [ "$ahead" != "0" ]; then
        # Diverged. --ff-only would fail, and picking merge or rebase for
        # someone is exactly the kind of history decision a hook should not make.
        add "On '$branch', DIVERGED from $upstream (ahead $ahead, behind $behind) — skipped the pull. Rebase or merge deliberately."
    elif git pull --ff-only --quiet 2>/dev/null; then
        add "On '$branch', pulled $behind commit(s) from $upstream."
    else
        add "On '$branch', behind $upstream by $behind commit(s); 'git pull --ff-only' failed. Pull manually."
    fi
fi

if [ -n "$dirty" ]; then
    add "Working tree has uncommitted changes ($(printf '%s\n' "$dirty" | wc -l | tr -d ' ') file(s))."
fi

# Open PRs. These are the ones most likely to collide with whatever this
# session is about to start, so they are worth seeing before the first edit.
if [ "$fetched" = "no" ]; then
    add "Skipped the PR check (no network)."
elif ! command -v gh >/dev/null 2>&1; then
    add "gh not installed; skipped the PR check."
else
    prs=$(timeout "$NET_TIMEOUT" gh pr list --state open \
        --json number,title,isDraft,headRefName,reviewDecision \
        --jq '.[] | "  #\(.number) \(.title)\(if .isDraft then " [draft]" else "" end)\(if .reviewDecision == "APPROVED" then " [approved]" else "" end) (\(.headRefName))"' \
        2>/dev/null)
    status=$?
    if [ $status -ne 0 ]; then
        add "Could not list PRs (gh returned $status — not authenticated, or no GitHub remote)."
    elif [ -z "$prs" ]; then
        add "No open PRs."
    else
        count=$(printf '%s\n' "$prs" | wc -l | tr -d ' ')
        add "$count open PR(s) awaiting merge:"
        add "$prs"
        add "Check these for overlap before starting new work — two branches touching changelog.yaml will conflict."
    fi
fi

jq -n --arg ctx "$report" '{
  hookSpecificOutput: {
    hookEventName: "SessionStart",
    additionalContext: ("Repository state at session start:\n" + $ctx)
  },
  systemMessage: $ctx
}'
