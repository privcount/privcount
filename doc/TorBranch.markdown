# The PrivCount Tor Branch

(This document is about the PrivCount Tor events patch. For PrivCount python
code versions, see PrivCountVersion.markdown.)

PrivCount obtains its Tor usage data via Tor Control Events. These events have
been implemented specifically for PrivCount: they have not yet been merged into
Tor master.

The privcount branch is kept in the Privcount Tor repository at:

https://github.com/privcount/tor

The latest PrivCount branch is called "privcount". Updates to this branch are
force-pushed to keep it at the latest Tor version. Always use the "privcount"
branch: old branches may have an outdated version of the PrivCount code.

## Specific Tor Versions

Versioned branches are created as-needed. They are named after the
corresponding PrivCount release, and the corresponding Tor branch or tag.
(We don't use tags for PrivCount, because we rebase the PrivCount code on top
of a Tor release.)

Since PrivCount uses [semantic versioning](http://semver.org), patch versions
are always compatible, and minor versions are compatible *if* you don't use
any new features. See PrivCountVersion.markdown for more details.

Examples:

PrivCount Tor Branch         | Tor Upstream | PrivCount Python Compatibility
-----------------------------|--------------|-------------------------------
privcount-1.0.0-tor-0.3.0.7  | tor-0.3.0.7  | privcount-1.?.*
privcount-1.0.0-tor-0.2.9.10 | tor-0.2.9.10 | privcount-1.?.*
privcount-0.1.1-tor-0.2.7.6  | tor-0.2.7.6  | privcount-0.1.*

Avoid using Tor maint branches, but, if you must, add the latest Tor minor
version and a git commit hash.

Example:

PrivCount Tor Branch                   | Tor Upstream
---------------------------------------|-------------------------------
privcount-1.0.0-tor-0.2.9.10-a7bcab263 | maint-0.2.9 (commit a7bcab263)

## Rebasing onto the Latest Tor Version

Try to use the latest stable release whenever possible: avoid maint tags,
because they change too often, and avoid outdated or alpha versions.

To rebase privcount onto a newer version of tor, use commands like:
```
git checkout -b privcount-0.1.1-tor-0.3.0.7 privcount-0.1.1-tor-0.2.7.6
git rebase --onto tor-0.3.0.7 tor-0.2.7.6 privcount-0.1.1-tor-0.3.0.7
```
Then deal with any merge conflicts until the rebase is completed.

To force update the old privcount branch with the newly rebased code:
```
git checkout -b privcount-old privcount
git branch -D privcount
git checkout -b privcount privcount-1.0.0-tor-0.3.0.7
git push --force privcount-remote privcount
```
