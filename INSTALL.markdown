# Building and Installing PrivCount

Getting PrivCount:

    git clone https://github.com/privcount/privcount.git
    git checkout privcount

## PrivCount depencencies:

    Debian/Ubuntu:  libssl-dev libffi-dev
    Other Linux:    libssl libssl-devel cffi
    (PrivCount supports BSD and macOS, the package names are similar.)

    python libs:    pyyaml, twisted, pyopenssl, cryptography, ...
                    (see requirements.txt for full list and versions)

We require OpenSSL version 1.0.2 or later for SHA256-padded RSA encryption.
Some tests require the openssl command.

System libs can be install with `apt-get`, `yum`, `brew`, etc. Python libs can
be installed with `pip`, as we explain below.

### If building python libs from source:

    Debian/Ubuntu:  libpython2.7-dev
    Other Linux:    ?

### Optional python package manager:

    Debian/Ubuntu:  python-pip
    Other Linux:    ?

### Optional graphing extensions (required only for the `plot` subcommand):

    Debian/Ubuntu: libpng-dev          #TODO this list is incomplete
    Other Linux:   libpng libpng-devel #TODO this list is incomplete

    python libs:   numpy, matplotlib
                   (see requirements-plot.txt for versions)

### Optional Tor relay consensus weight tool:

    python libs: numpy, stem
                 (see requirements-weights.txt for versions)

## Optional: Installing Chutney

Chutney is used to run the PrivCount tor network ('chutney') integration test.
It can be used to test tor as well.

    git clone https://git.torproject.org/chutney.git

## Optional: Installing a PrivCount-patched Tor

A custom compiled PrivCount-patched Tor can be used to run a data collector.
It is also used to run the PrivCount tor relay ('tor') and tor network
('chutney') integration tests.

### Tor Dependencies:

    Debian/Ubuntu:  libssl-dev libevent-dev
    Other Linux:    libssl libssl-dev libevent libevent-devel

### Optional Tor Dependencies:

#### Linux Sandbox:

    Debian/Ubuntu:  libseccomp-dev
    Other Linux:    libseccomp2 libseccomp-devel

    On by default, if the libraries are available.

#### Linux systemd notifications:

    Debian/Ubuntu:  libsystemd-dev pkg-config
    Other Linux:    ?

    --enable-systemd

The Debian tor packages are built with systemd notifications by default. If
you want to use systemd to manage your privcount-patched tor, install it in
/usr/local, so that systemd's ProtectHome works correctly.

Once tor is installed in /usr/local, use the systemd drop-in file
    dist/systemd_privcount_tor.conf
to activate it. Instructions are in that file.

#### scrypt Control Port Password Encryption:

    Debian/Ubuntu:  libscrypt-dev
    Other Linux:    libscrypt-devel

    On by default, if the libraries are available.

Recommended if you are using a control port password.

#### Other Optional Tor Dependencies:

Tor also supports xz and zstd compression of directory documents (in 0.3.1 and
later).

For details, read the output of:
    ./configure --help

### Building Tor:

Tor builds with --prefix=/usr/local by default.

We recommend that you perform the following steps to install a
privcount-patched tor in /usr/local:

    git clone https://github.com/privcount/tor.git tor-privcount
    git checkout privcount
    ./autogen.sh
    ./configure --disable-asciidoc --prefix=/usr/local
    make
    sudo make install

### Optional Tor tests:

    make check
    make test-network-all # requires chutney

# Installing PrivCount

I recommend using virtual environments to isolate the python environment and avoid conflicts.
Run the following from the base directory of this package (i.e., the same location of this README).

    pip install virtualenv
    virtualenv --no-site-packages venv
    source venv/bin/activate
    pip install -r requirements.txt
    # if you want to use the optional privcount plot command
    pip install -r requirements-plot.txt
    # if you want to use the optional compute_fractional_position_weights tool
    pip install -r requirements-weights.txt
    pip install -I .
    deactivate

## Optional PrivCount Tests

Unit tests and basic ('inject') integration test:

    test/run_test.sh -I .

Tor relay integration tests (requires a PrivCount-patched Tor):

Start an unpublished relay:

    test/run_test.sh -I . -x -z -s tor

Check an existing relay:

    source venv/bin/activate
    test/test_tor_ctl_event.py <control-port-or-control-socket-path>
    deactivate

Tor network integration test (requires chutney):

    test/run_test.sh -I . -x -z -s chutney

## Troubleshooting

If 'pip install virtualenv' fails due to permissions errors, install as root. Using 'sudo -H' before 'pip install' should work.

Some environments (macOS) might need help locating headers and libraries. If so, use 'CFLAGS="-I/opt/local/include" LDFLAGS="-L/opt/local/lib"' (substituting your package manager's path) before pip install.

Some environments (macOS) use the site packages, even if '--no-site-packages' is specified. This can cause failures. Use 'pip install -I' to work around this. 'pip --isolated' might also help, as may 'pip uninstall' outside the virtualenv.

Some environments (VPSs) have limited RAM. If pip fails with a memory error, try using --no-cache.

If the encryption unit tests fail with an "UnsupportedAlgorithm" exception, make sure you have cryptography >= 1.4 with OpenSSL >= 1.0.2. You may be using a binary wheel that was compiled with an older OpenSSL version. If so, rebuild and reinstall cryptography using 'pip install -I --no-binary cryptography cryptography'.
