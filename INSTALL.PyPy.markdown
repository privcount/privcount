# pypy virtual environment setup

Running PrivCount in a pypyenv dramatically improves efficiency.
These instructions have been tested on a few different systems (ymmv).

## install pypy

### Debian / Ubuntu

You can't install pypy for privcount on Debian jessie. You need Debian stretch
or later, because python cryptography requires pypy 2.6.1 (cryptography 1.5.2)
or pypy 5.3.0 (cryptography 1.9).

As root (Debian), or using sudo (Ubuntu):

```bash
apt-get install pypy pypy-setuptools curl
curl -fsSL https://bootstrap.pypa.io/get-pip.py | pypy
# On Debian, pypy overrides the standard python pip
alias pip_pypy=/usr/local/bin/pip
alias pip=/usr/bin/pip2
```

### CentOS 7

```bash
sudo yum install pypy pypy-devel
```

### macOS / Homebrew

```bash
brew install pypy openssl
```

## upgrade tools (optional)

As root, or using sudo:

```bash
pip_pypy install --upgrade pip setuptools wheel virtualenv
```

## Create a Local Build Directory (optional, required on CentOS 7)

### CentOS 7

```bash
cd ~
mkdir -p local/pypyenv
cd local
```

## create a pypy virtual environment

# install pypy environment, update environment
```bash
virtualenv -p pypy --no-site-packages pypyenv
source pypyenv/bin/activate
pip install --upgrade pip setuptools wheel
```

## Build Dependencies (required for CentOS 7, optional otherwise)

### Centos 7

#### OpenSSL

On my machine, I need openssl-1.0.2k.tar.gz for the python cryptography library
And I need a custom build as described here:
https://cryptography.io/en/latest/installation/#static-wheels

```bash
wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2k.tar.gz
tar xaf openssl-1.0.2k.tar.gz
cd openssl-1.0.2k
./config enable-ec_nistp_64_gcc_128 no-shared no-ssl2 no-ssl3 -fPIC --prefix=/home/rjansen/local/openssl-privcount --openssldir=/home/rjansen/local/openssl-privcount
make depend
make -j8
make install
```

#### Python cryptography

Build python cryptography lib.

```bash
mkdir cryptowheels
cd cryptowheels
```

OpenSSL paths reference openssl build from above.

```bash
CFLAGS="-I/home/rjansen/local/openssl-privcount/include" LDFLAGS="-L/home/rjansen/local/openssl-privcount/lib" pip wheel --no-binary :all: cryptography==1.5.2
pip install *whl
cd ..
```

## Install PrivCount

```bash
git clone https://github.com/privcount/privcount.git
cd privcount
git checkout origin/master
# optional commands: if using local prefix
cd privcount
ln -s ../local/pypyenv .
```

## Pin Python cryptography requirement (CentOS 7 only)

### Centos 7

Apply the following diff, to force cryptography version 1.5.2, which is
compatible with pypy. (This may not be necessary if you already installed
cryptography==1.5.2 as specified above.)

```
diff --git a/requirements.txt b/requirements.txt
index 576109e..ae02848 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -8,7 +8,7 @@ PyYAML>=3.11
 Twisted>=15.5.0
 attrs>=15.2.0
 cffi>=1.5.2
-cryptography>=1.5.2 # must be >=1.4 for SHA256 hashes in RSA encryption
+cryptography==1.5.2 # must be >=1.4 for SHA256 hashes in RSA encryption
 enum34>=1.1.2
 idna>=2.0
 ipaddress>=1.0.16
 ```

## Install PrivCount requirements

### Debian / Ubuntu / CentOS 7

```bash
pip install -r requirements.txt
```

### macOS / Homebrew

```bash
# tell cryptography where to find openssl
CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib pip install -r requirements.txt
```

## Install PrivCount

```bash
pip install -I .
```

## Test PrivCount

Now you should be able to run privcount like usual, except it will run much
faster with pypy.

```bash
privcount -h
# optionally, remove the old venv so that run_privcount.sh and run_test.sh use
# pypyenv
rm -rf venv
ln -s pypyenv venv
```

## Create Python and PyPy virtualenvs

You can use INSTALL.markdown to install a python environment under pyenv for
privcount plot and compute_fractional_position_weights. Then you can switch
the default environments for run_privcount.sh and run_test.sh using:

```bash
# python
ln -sf pyenv venv
# pypy
ln -sf pypyenv venv
```
