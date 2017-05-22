# PrivCount Version Scheme

(This document is about the PrivCount python code. For the Tor events patch
versions, see TorBranch.markdown.)

PrivCount is versioned using Semantic Versioning: http://semver.org/

    Given a version number MAJOR.MINOR.PATCH, increment the:
    1. MAJOR version when you make incompatible API changes,
    2. MINOR version when you add functionality in a backwards-compatible
       manner, and
    3. PATCH version when you make backwards-compatible bug fixes.

For example, when we:
* change the protocol or events in incompatible ways, we go from 0.2.0 to
  1.0.0,
* add new events or new counters, we go from 0.2.0 to 0.3.0,
* fix bugs, we go from 0.2.0 to 0.2.1.

PrivCount versions can contain changes to the PrivCount python code, Tor patch,
or both. Changes to upstream tor are managed using Tor's versioning scheme.
See TorBranch.markdown for more details.
