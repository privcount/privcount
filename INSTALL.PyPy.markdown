## pypy virtual environment setup, for various systems (ymmv)
## running PrivCount in a pypyenv dramatically improves efficiency

# install pypy

## CentOS 7

```bash
sudo yum install pypy pypy-devel
# optional
sudo pip_pypy install --upgrade pip setuptools
```

## macOS / Homebrew

```bash
brew install pypy openssl
pip_pypy install --upgrade pip setuptools
```

## Other Systems

Install dependencies, see above for hints

# create a pypy virtual environment

## CentOS 7 / Local Build Directory

# optional commands: use a local prefix for openssl build
```bash
cd ~
mkdir -p local/pypyenv
cd local
```

## All Systems, including CentOS 7

# install pypy environment, update environment
```bash
virtualenv -p pypy --no-site-packages pypyenv
source pypyenv/bin/activate
pip install --upgrade pip setuptools
```

## Centos 7

# On my machine, I need openssl-1.0.2k.tar.gz for the python cryptography library
# And I need a custom build as described here:
# https://cryptography.io/en/latest/installation/#static-wheels
```bash
wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2k.tar.gz
tar xaf openssl-1.0.2k.tar.gz
cd openssl-1.0.2k
./config enable-ec_nistp_64_gcc_128 no-shared no-ssl2 no-ssl3 -fPIC --prefix=/home/rjansen/local/openssl-privcount --openssldir=/home/rjansen/local/openssl-privcount
make depend
make -j8
make install
```

## Centos 7

# build python cryptography lib (custom build needed for cent os 7)
```bash
mkdir cryptowheels
cd cryptowheels
```

## Centos 7

# openssl paths reference openssl build from above
```bash
CFLAGS="-I/home/rjansen/local/openssl-privcount/include" LDFLAGS="-L/home/rjansen/local/openssl-privcount/lib" pip wheel --no-binary :all: cryptography==1.5.2
pip install *whl
cd ..
```

## All Systems

# install privcount
```bash
git clone https://github.com/privcount/privcount.git
cd privcount
git checkout origin/master
# optional commands: if using local prefix
cd privcount
ln -s ../local/pypyenv .
```

## Centos 7

# apply the following diff, to force cryptography version 1.5.2, which is compatible with pypy
# (This may not be necessary if you already installed cryptography==1.5.2 as specified above.)
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

## Centos 7 / Other Systems

# install deps
```bash
pip install -r requirements.txt
```

## macOS / Homebrew

# install deps
```bash
# tell cryptography where to find openssl
CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib pip install -r requirements.txt
```

## All Systems

# install PrivCount
```bash
pip install -I .
```

## All Systems

# now you should be able to run privcount like usual
# except it will run much faster with pypy
```bash
privcount -h
# optionally, remove the old venv so that run_privcount.sh and run_test.sh use
# pypyenv
rm -rf venv
ln -s pypyenv venv
```

## All Systems

# You can use INSTALL.markdown to install a python environment under pyenv for
# privcount plot and compute_fractional_position_weights. Then you can switch
# the default environments for run_privcount.sh and run_test.sh using:

```bash
# python
ln -sf pyenv venv
# pypy
ln -sf pypyenv venv
```
