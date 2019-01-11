# Building and Installing PrivCount

A PrivCount network consists of a Tally Server (TS), at least two Share Keepers
(SK) and one or more Data Collectors (DCs).

## Download PrivCount (TS, SK, DC)

    git clone https://github.com/privcount/privcount.git
    cd privcount

For the stable version:

    git checkout origin/privcount

For the latest version:

    git checkout origin/master

### Upgrade PrivCount from a previous version

#### Update From Git

To update your chosen branch from remote "origin":

    cd privcount
    git fetch origin
    git checkout origin/<chosen-branch> # privcount or master

#### Update PrivCount

    source pyenv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install --upgrade -r requirements.txt
    # optional: privcount plot
    pip install --upgrade -r requirements-plot.txt
    # optional: position weights
    pip install --upgrade -r requirements-weights.txt
    pip install -I .
    # check you installed the right version
    privcount version
    # relaunch privcount

### Install PrivCount Depencencies

    Debian/Ubuntu:  python2.7 libssl-dev libffi-dev libyaml-dev
    Other Linux:    python2.7 libssl libssl-devel cffi libyaml-devel
    (PrivCount supports BSD and macOS, the package names are similar.)

    python libs:    pyyaml, twisted, pyopenssl, cryptography, ...
                    (see requirements.txt for full list and versions)

PrivCount has been tested with Python 2.7: other versions may not work.

We require OpenSSL version 1.0.2 or later for SHA256-padded RSA encryption.
The tests require the openssl command.

You may need to use your distribution's backports to get an updated OpenSSL.
For example, on Debian 8 (Jessie), the required SSL packages are:

    libssl1.0.0=1.0.2k-1~bpo8+1 libssl-dev=1.0.2k-1~bpo8+1

You may also need to build a statically-linked python cryptography library,
or build your python with OpenSSL 1.0.2 or later. Otherwise, python can pull
in a version of OpenSSL that is too old for cryptography.

See the cryptography build instructions for more details:

    https://cryptography.io/en/latest/installation/#using-your-own-openssl-on-linux

System libs can be install with `apt-get`, `yum`, `brew`, etc. Python libs can
be installed with `pip`, as we explain below.

### Python Package Manager (Recommended)

    Debian/Ubuntu:  python-pip
    Other Linux:    ?

### Building Python Depencencies from Source

If there are no precompiled binaries available for your system, you will need
to build your python dependencies from source:

    Debian/Ubuntu:  libpython2.7-dev
    Other Linux:    ?

Some environments (macOS) might need help locating headers and libraries. If
so, use:

    'CFLAGS="-I/opt/local/include" LDFLAGS="-L/opt/local/lib"'

(substituting your package manager's path) before pip install.

### PrivCount Plot (Optional):

    Debian/Ubuntu: libpng-dev          #TODO this list is incomplete
    Other Linux:   libpng libpng-devel #TODO this list is incomplete

    python libs:   numpy, matplotlib
                   (see requirements-plot.txt for versions)

### PrivCount Tor Relay Consensus Weights (Optional)

    python libs: numpy, stem
                 (see requirements-weights.txt for versions)

## Installing PrivCount

I recommend using virtual environments to isolate the python environment and
avoid conflicts. Run the following from the privcount base directory (the
directory that contains these instructions):

    pip install --upgrade pip setuptools wheel virtualenv
    virtualenv --no-site-packages pyenv
    source pyenv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install --upgrade -r requirements.txt
    # if you want to use the optional privcount plot command
    pip install --upgrade -r requirements-plot.txt
    # if you want to use the optional compute_fractional_position_weights tool
    pip install --upgrade -r requirements-weights.txt
    pip install -I .
    deactivate
    # make run_privcount.sh and test/run_tests.sh use pyenv
    # if venv is an old virtualenv directory, delete it first
    ln -sf pyenv venv

Optionally, use INSTALL.PyPy.markdown to install a pypy environment under
pypyenv, so that privcount uses less CPU. You can switch the default
environments for run_privcount.sh and run_test.sh using:

    # python
    ln -sf pyenv venv
    # pypy
    ln -sf pypyenv venv

If 'pip install virtualenv' fails due to permissions errors, install as root.
Using 'sudo -H' before 'pip install' should work.

Some environments (macOS) have environmental variables or site packages that
conflict with PrivCount depencencies. Try the following workarounds in the
virtualenv:

    pip --isolated install --ignore-installed package
    pip --no-binary :all: install --ignore-installed package
    pip --isolated --no-binary :all: install --ignore-installed package

As a last resort, uninstall the conflicting packages outside the virtualenv:

    pip uninstall package

Some environments (VPSs) have limited RAM. If pip fails with a memory error,
try using --no-cache.

### Optional PrivCount Tests

Unit tests and basic ('inject') integration test:

    test/run_test.sh -I .

If the encryption unit tests fail with an "UnsupportedAlgorithm" exception,
make sure you have cryptography >= 1.4 with OpenSSL >= 1.0.2. You may be using
a binary wheel that was compiled with an older OpenSSL version. If so, rebuild
and reinstall cryptography using:

    pip install --ignore-installed --no-binary cryptography cryptography

## Installing a PrivCount-patched Tor (Data Collectors)

A custom compiled PrivCount-patched Tor can be used to run a data collector.
It is also used to run the PrivCount tor relay ('tor') and tor network
('chutney') integration tests.

### Tor Dependencies

    Debian/Ubuntu:  libssl-dev libevent-dev
    Other Linux:    libssl libssl-dev libevent libevent-devel

### Tor Dependencies

#### Linux Sandbox (Optional)

    Debian/Ubuntu:  libseccomp-dev
    Other Linux:    libseccomp2 libseccomp-devel

On by default, if the libraries are available.

#### Linux Capabilities (Optional)

    Debian/Ubuntu:  libcap-dev
    Other Linux:    libcap libcap-devel

On by default, if the libraries are available.
Recommended if you are on Linux which supports capabilities, particularly if
your init system uses them.

#### Linux systemd notifications (Required if using systemd)

    Debian/Ubuntu:  libsystemd-dev pkg-config
    Other Linux:    ?

    ./configure --enable-systemd

The Debian tor packages are built with systemd notifications by default. If
you want to use systemd to manage your privcount-patched tor, install it in
/usr/local, so that systemd's ProtectHome works correctly.

Once tor is installed in /usr/local, use the systemd drop-in file
    dist/systemd_privcount_tor.conf
to activate it. Instructions are in that file.

#### scrypt Control Port Password Encryption (Optional)

    Debian/Ubuntu:  libscrypt-dev
    Other Linux:    libscrypt-devel

On by default, if the libraries are available.
Recommended if you are using a control port password.

#### Other Tor Dependencies (Optional)

Tor also supports lzma and zstd compression of directory documents (in 0.3.1 and
later).

For details, read the output of:

    ./configure --help

### Building Tor

Tor builds with --prefix=/usr/local by default.

We recommend that you perform the following steps to install a
privcount-patched tor in /usr/local:

#### Download PrivCount-Patched Tor


    git clone https://github.com/privcount/tor.git tor-privcount
    cd tor-privcount

For the stable version:

    git checkout origin/privcount

For the latest version:

    git checkout origin/privcount-master

#### Upgrade Tor from a previous version

To update your chosen branch from remote "origin":

    cd tor-privcount
    git fetch origin
    git checkout origin/<chosen-branch> # privcount or privcount-master

#### Build and Install Tor

    ./autogen.sh
    ./configure --disable-asciidoc --prefix=/usr/local # other options
    make
    sudo make install

### Tor Tests (Optional)

    make check
    make test-network-all # requires chutney

### Installing Chutney (Optional)

Chutney is used to run the PrivCount tor network ('chutney') integration test.
It can be used to test tor as well.

    git clone https://git.torproject.org/chutney.git

You will need a recent version of chutney with networks/hs-exit-min, git
revision 72fa261 or later.

### Optional PrivCount Data Collector Tests

These tests require a PrivCount-patched Tor.

Start an unpublished relay:

    test/run_test.sh -I . -x -z -s tor

Check an existing relay:

    source pyenv/bin/activate
    test/test_tor_ctl_event.py <control-port-or-control-socket-path>
    deactivate

#### PrivCount Network Integration Test

This test requires chutney.

    test/run_test.sh -I . -x -z -s chutney
