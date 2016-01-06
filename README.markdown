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

During PrivCount development, include your latest development changes by forcing a reinstall:

    pip install -I .

# running

To run PrivCount, simply activate the virtual environment that you created earlier and then run
PrivCount as normal. For example:

    source venv/bin/activate # enter the virtual environment
    privcount --help
    ...
    deactivate # exit the virtual environment

# testing

After installing PrivCount as above, testing is quite simple. You'll need 4 terminals, each of which
you have 'activated' using virtualenv as above so that they have PrivCount in the PATH. Change a
terminal into each of the `test/ts`, `test/tks`, `test/dc`, and `test` directories (4 terms total).

Then start up the nodes from the respective terminal as follows and in this order:
  + From `test/ts` run `privcount ../privcount-test-config.yaml ts`
  + From `test/tks` run `privcount ../privcount-test-config.yaml tks`
  + From `test/dc` run `privcount ../privcount-test-config.yaml dc`

Then wait for the log messages to indicate the first epoch has started. Once that has happened:
  + From `test/` run `privcount-inject -p 20003 -l tor-test-events.txt`

# setting up PrivCount entities

## tally server

## tally key server

## data collector
