---
name: pr-describe
description: Write or rewrite a pull request title and description from a fresh session that sees only master, the branch and the author's facts, then check it with a second session that reads only the description. Use when opening a PR, when asked to write or improve a PR description, or before marking a PR ready. Takes an optional PR number.
---

# pr-describe

The session that wrote the code must not write the description: it remembers every approach it
tried and the words it made up, and the description turns into the story of the work. This skill
hands the writing to new sessions. Read "Pull requests" in `AGENTS.md` first; the template is
`.github/pull_request_template.md`.

Arguments: an optional PR number. Without one, describe the current branch against `origin/master`.

## 1. Collect the author facts

You are the author here. Write down only these, as short lists, from what you know:

- **problem**: one sentence, as a user or operator sees it (a config key, command, path or test
  that misbehaves or is missing). No function names.
- **tested**: where it ran (appengine, device and board), what ran, what passed.
- **not tested**: what was not run. "nothing known" is allowed.
- **related**: other PRs this depends on or goes with, as `owner/repo#N`. May be empty.

If you were not part of the work (for example a PR number on someone else's branch), ask the user
for these instead of guessing. Do not add explanation of the code: the writer works that out from
the diff.

Also note the branch name and base: `git rev-parse --abbrev-ref HEAD`, and `origin/master` unless
the user says otherwise. Run `git fetch origin master` first. With a PR number, use
`gh pr view <n> --json headRefName,baseRefName,title,body` and check the branch out, or have the
writer use `gh pr diff <n>`.

## 2. Write, in a new session

Start a **fresh** agent with the Agent tool, `subagent_type: "general-purpose"`. Never use
`"fork"`: a fork inherits this conversation, which is exactly what must be left behind. Pass only
the prompt below, filled in. Add nothing about how the work went.

```
Write the title and description of a pull request in the pantavisor repository at <repo path>.
You have not seen this work before; that is the point. A reviewer who knows master and nothing
else must understand from your text what the problem is, what the PR does about it, and how.

Read first: the "Pull requests" section of AGENTS.md, and .github/pull_request_template.md.
Then read the change itself:
  git log --format='%h %s%n%n%b' <base>..<branch>
  git diff --stat <base>...<branch>
  git diff <base>...<branch>
Read the surrounding code and docs on master wherever you need to understand a change.

Facts from the author (trust these, do not invent others):
<author facts from step 1>

Rules:
- Use the template headings. Problem, Approach and Tested always; Implementation when the how is
  not obvious; In this PR when there is more than one commit (one line per commit, tests and docs
  included); Review notes when there are risks, behaviour changes for existing devices, or
  related PRs.
- Problem starts with what a user sees. No function names before Implementation.
- Describe the present. No history of earlier designs, no commit hashes as background.
- If a commit does not belong to the problem, list it and say so.
- Tested comes only from the author facts, including what was not tested.
- Plain English and the project's own words (container, revision, group, volume, pvtest).
- Title: a Conventional Commit line that names the behaviour that changes.

Reply with exactly:
TITLE: <one line>
BODY:
<markdown>
```

## 3. Cold read, in another new session

Start another fresh `general-purpose` agent. Give it only the title and body, never the diff or
the author facts:

```
Below is a pull request title and description from the pantavisor project (an embedded Linux
container runtime). You have not seen the code. Answer from the text only:
1. What is the problem?
2. What does the PR do about it?
3. How is it done?
4. Which words, names or steps could you not follow?
5. What would you ask the author before reviewing?
Keep each answer to a few lines. Say "cannot tell" where the text does not say.

<title and body>
```

Compare its answers 1 to 3 with the author facts and the commits. If one is wrong, says
"cannot tell", or 4 lists something a reviewer needs, run step 2 again in a **new** agent with the
reader's answers 4 and 5 added under "A first reader could not follow:". Stop after two rewrites
and show the user what is still unclear.

Do not fix the text yourself between rounds: your edits bring back the context this skill exists
to leave out. Correct a wrong fact only by fixing it in the author facts and rewriting.

## 4. Show, then post

Show the user the title, the body and the cold reader's answers 1 to 3. Post only after they agree:

- existing PR: `gh pr edit <n> --title "<title>" --body-file <file>`
- new PR: `gh pr create --draft --title "<title>" --body-file <file>`

Put the body file in the job or scratch directory, not in the repository.
