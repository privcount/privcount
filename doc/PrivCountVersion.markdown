# PrivCount Version Scheme

PrivCount is versioned using Semantic Versioning: http://semver.org/

    Given a version number MAJOR.MINOR.PATCH, increment the:
    1. MAJOR version when you make incompatible API changes,
    2. MINOR version when you add functionality in a backwards-compatible
       manner, and
    3. PATCH version when you make backwards-compatible bug fixes.

For example, when we:
* change the protocol or events in incompatible ways, we go from 0.2.0 to
  1.0.0,
  * when the protocol is incompatible, we also increment
    PrivCountProtocol.HANDSHAKE_VERSION to the latest major version,
* add new events or new counters, we go from 0.2.0 to 0.3.0,
* fix bugs, we go from 0.2.0 to 0.2.1.

PrivCount versions can contain changes to the PrivCount python code, Tor patch,
or both. Changes to upstream Tor are managed using Tor's versioning scheme,
and tags contain both the Tor and PrivCount versions.

## Updating the PrivCount version

You can use bumpversion to bump the PrivCount version in all the relevant
files, in both the PrivCount and Tor repositories:

    bumpversion major|minor|patch

The default configuration creates a git commit, and tags it "privcount-a.b.c".

If the PrivCount protocol changes in an incompatible way, you will need to
update PrivCountProtocol.HANDSHAKE_VERSION manually.

The Tor and PrivCount versions will never clash, because the Tor version has
a leading zero.

# Git Repositories

PrivCount consists of nodes implemented in python that securely aggregate Tor
usage data.

PrivCount obtains its Tor usage data via Tor Control Events. These events have
been implemented specifically for PrivCount: they have not yet been merged into
Tor master.

Since PrivCount uses [semantic versioning](http://semver.org), patch versions
are always compatible, and minor versions are compatible *if* you don't use
any new features.

## Latest Stable Branch

The stable branch for PrivCount development is always called:

    privcount

In the Tor PrivCount repository, updates to this branch are force-pushed to
keep it at a recent Tor version.

## Maintenance Branches

Maintenance branches are created as-needed.

Maintenance branches for PrivCount (python) development look like:

    maint-1.0

Maintenance branches for Tor PrivCount have a privcount prefix and Tor version
suffix:

    privcount-maint-1.0-tor-0.3.0.7

## Development Branch

The master branch for PrivCount (python) development is called:

    master

The master branch for Tor PrivCount development is called:

    privcount-master

## Release Tags

Release tags are created as-needed. They are named after the corresponding
PrivCount release. Tor PrivCount tags have a suffix with the Tor branch or tag.

PrivCount release tags look like:

    privcount-1.0.0
    privcount-0.1.1

PrivCount Tor release tags look like:

    privcount-1.0.0-tor-0.3.0.7
    privcount-0.1.1-tor-0.2.7.6

Avoid using Tor maint branches, but, if you must, tag it with the latest Tor
minor version and a git commit hash, like this:

    privcount-1.0.0-tor-0.2.9.10-a7bcab263

# Rebasing onto the Latest Tor Version

Try to use the latest stable release whenever possible: avoid maint tags,
because they change too often, and avoid outdated or alpha versions.

To rebase privcount onto a newer version of tor, use commands like:
```
git checkout -b privcount-maint-1.0-tor-0.3.0.7 privcount-maint-1.0-tor-0.2.7.6
git rebase --onto tor-0.3.0.7 tor-0.2.7.6 privcount-maint-1.0-tor-0.3.0.7
```
Then deal with any merge conflicts until the rebase is completed.

To bump the tor version in the git tags, use:
```
bumpversion --tag-name "privcount-{new_version}-tor-0.3.0.7"
git push --tags privcount-remote
```

To force update the old privcount branch with the newly rebased code:
```
git checkout -b privcount-old privcount
git branch -D privcount
git checkout -b privcount privcount-maint-1.0-tor-0.3.0.7
git push --force privcount-remote privcount
```
