## pypy virtual environment setup on cent os 7 (ymmv)
## running PrivCount in a pypyenv dramatically improves efficiency

# install pypy
```bash
sudo yum install pypy pypy-devel
```

# create a pypy virtual environment
```bash
cd ~
mkdir -p local/pypyenv
cd local
virtualenv -p /usr/bin/pypy --no-site-packages pypyenv
```

# update environment
```bash
source pypyenv/bin/activate
pip install -U setuptools
pip install -U wheel pip
```

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

# build python cryptography lib (custom build needed for cent os 7)
```bash
mkdir cryptowheels
cd cryptowheels
```

# openssl paths reference openssl build from above
```bash
CFLAGS="-I/home/rjansen/local/openssl-privcount/include" LDFLAGS="-L/home/rjansen/local/openssl-privcount/lib" pip wheel --no-use-wheel cryptography==1.5.2
pip install *whl
cd ..
```

# install privcount
```bash
git clone git@github.com:robgjansen/privcount-viterbi.git
cd privcount-viterbi
git checkout -b viterbi-v3 origin/vitrbi-v3
```

# apply the following diff, to force cryptography version 1.5.2, which is compatible with pypy
# (This may not be necessary if you already installed cryptography==1.5.2 as specefied above.)
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

 # install deps, then privcount
 ```bash
 pip install -r requirements.txt
 pip install -I .
```

 # now you should be able to run privcount like usual
 # except it will run much faster with pypy
 ```bash
 privcount -h
```
