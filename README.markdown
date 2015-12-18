# requirements

    system libs: libssl libssl-dev cffi
    python libs: pyyaml, stem, twisted, pyopenssl, service-identity

System libs can be install with `apt-get`, `yum`, `brew`, etc. Python libs can be installed with `pip`,
as we explain below.

# installation

I recommend using virtual environments to isolate the python environment and avoid conflicts.
Run the following from the base directory of this package (i.e., the same location of this README).

    pip install virtualenv
    virtualenv --no-site-packages venv
    source venv/bin/activate
    pip install pyyaml stem twisted pyopenssl service-identity
    pip install .
    deactivate

You can replace the `pip install ...` above with the following to mirror my dev environment:

    pip install -r requirements.txt

During Privex development, include your latest development changes by forcing a reinstall:

    pip install -I .

# running

To run privex, simply activate the virtual environment that you created earlier and then run
privex as normal. For example:

    source venv/bin/activate # enter the virtual environment
    privex --help
    ...
    deactivate # exit the virtual environment

# setting up privex entities

## tally server

## tally key server

## data collector
