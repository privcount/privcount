# The PrivCount Tor Branch

PrivCount obtains its Tor usage data via Tor Control Events. These events have
been implemented specifically for PrivCount: they have not yet been merged into
Tor master.

The privcount branch is kept in the Privcount Tor repository at:

https://github.com/privcount/tor

The latest PrivCount branch is called "privcount". Updates to this branch are
force-pushed to keep it at the latest Tor version. Always use the "privcount" branch: old branches may have an outdated version of the PrivCount code.

## Specific Tor Versions

Versioned branches are created as-needed. They are named after the
corresponding Tor branch or tag. (We don't use tags for PrivCount, because we
rebase the PrivCount code on top of the Tor release.)

Avoid using maint branches, but if you must, add a git commit hash.

Examples:

PrivCount Branch           | Tor Branch
---------------------------|------------
privcount-0.2.9.9          | tor-0.2.9.9
privcount-0.2.7.6          | tor-0.2.7.6
privcount-0.2.9-adaf6a422a | maint-0.2.9

## Rebasing onto the Latest Tor Version

Try to use the latest stable release whenever possible: avoid maint tags,
because they change too often, and avoid outdated or alpha versions.

To rebase privcount onto a newer version of tor, use commands like:
```
git checkout -b privcount-0.2.9.9 privcount
git rebase --onto tor-0.2.9.9 tor-0.2.7.6 privcount-0.2.9.9
```
Then deal with any merge conflicts until the rebase is completed.

To force update the old privcount branch with the newly rebased code:
```
git checkout -b privcount-2017-02-06-0215 privcount
git branch -D privcount
git checkout -b privcount privcount-0.2.9.9
git push --force privcount-remote privcount
```
