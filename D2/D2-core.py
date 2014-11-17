#!/usr/bin/env python
import cffi
from StatKeeper import StatKeeper
from binascii import hexlify

from noise import Noise
from exit_weight import *

num_DC=10
num_TKG=3
num_websites=100

sigma = 240
resolution = 10

_FFI = cffi.FFI()

_FFI.cdef("""


typedef enum {
  /* values as defined in X9.62 (ECDSA) and elsewhere */
  POINT_CONVERSION_COMPRESSED = 2,
  POINT_CONVERSION_UNCOMPRESSED = 4,
  POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef ... BN_CTX;
typedef ... BIGNUM;

EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP* x);
void EC_GROUP_clear_free(EC_GROUP *);

const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);
int EC_GROUP_get_curve_name(const EC_GROUP *group);

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);

int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);

int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);

/* EC_GROUP_precompute_mult() stores multiples of generator for faster point multiplication */
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
/* EC_GROUP_have_precompute_mult() reports whether such precomputation has been done */
int EC_GROUP_have_precompute_mult(const EC_GROUP *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
        const unsigned char *buf, size_t len, BN_CTX *);


typedef ... EC_KEY;

EC_KEY *EC_KEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);

int EC_KEY_up_ref(EC_KEY *);

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
int EC_KEY_set_group(EC_KEY *, const EC_GROUP *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);

unsigned EC_KEY_get_enc_flags(const EC_KEY *);
void EC_KEY_set_enc_flags(EC_KEY *, unsigned int);

/* EC_KEY_generate_key() creates a ec private (public) key */
int EC_KEY_generate_key(EC_KEY *);
/* EC_KEY_check_key() */
int EC_KEY_check_key(const EC_KEY *);


typedef struct { 
  int nid;
  const char *comment;
  } EC_builtin_curve;

/* EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number 
 * of all available curves or zero if a error occurred. 
 * In case r ist not zero nitems EC_builtin_curve structures 
 * are filled with the data of the first nitems internal groups */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

typedef unsigned int BN_ULONG;

BN_CTX *BN_CTX_new(void);
void    BN_CTX_free(BN_CTX *c);

BIGNUM *BN_new(void);
void  BN_init(BIGNUM *);
void  BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void  BN_swap(BIGNUM *a, BIGNUM *b);
int     BN_cmp(const BIGNUM *a, const BIGNUM *b);
int   BN_set_word(BIGNUM *a, BN_ULONG w);
void    BN_set_negative(BIGNUM *b, int n);
int     BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int     BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int     BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
char *  BN_bn2dec(const BIGNUM *a);
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);

typedef unsigned int SHA_LONG;
#define SHA_LBLOCK 16

typedef struct SHA256state_st
        {
        SHA_LONG h[8];
        SHA_LONG Nl,Nh;
        SHA_LONG data[SHA_LBLOCK];
        unsigned int num,md_len;
        } SHA256_CTX;

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);

""")

_C = _FFI.verify("""
#include <openssl/ec.h>
#include <openssl/sha.h>

""", libraries=["crypto"], extra_compile_args=['-Wno-deprecated-declarations'])

# # NIST/X9.62/SECG curve over a 192 bit prime field
# curveID = 409

# Commit to a list of encrypted counters by hashing
def hash_clidata(ecgroup, data):
    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    for (a,b) in data:
        buf, size = point2str(ecgroup, a)
        _C.SHA256_Update(ctx, buf, size)
        # print _FFI.buffer(buf, size)[:].encode("hex"),
        buf, size = point2str(ecgroup, b)
        _C.SHA256_Update(ctx, buf, size)
        # print _FFI.buffer(buf, size)[:].encode("hex")
    _C.SHA256_Final(md, ctx)
    hashval = _FFI.buffer(md, 32)[:]
    return hashval

class crypto_counts:
  def __init__(self, labels, pubkey, curveID = 409, fingerprint = "fingerprint"):
    global _C
    self._C = _C
    self.num = len(labels)
    self.curveID = curveID
    self.pubkey = pubkey
    self.lab = {}

    # Store the group we work in
    # precompute tables and the generator
    self.ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)
    if not _C.EC_GROUP_have_precompute_mult(self.ecgroup):
        _C.EC_GROUP_precompute_mult(self.ecgroup, _FFI.NULL);
    self.gen = _C.EC_GROUP_get0_generator(self.ecgroup)

    # This is where we store the ECEG ciphertexts
    self.buf = []

    # This DC's weight for noise calculation
    twbw, p_exit, num_of_dc, sum_of_sq = prob_exit(consensus, fingerprint)

    for label in labels:
      # Make session key
      session = _C.EC_KEY_new_by_curve_name(curveID)
      _C.EC_KEY_set_group(session, self.ecgroup)
      _C.EC_KEY_generate_key(session)

      s_pub = _C.EC_KEY_get0_public_key(session)
      s_priv = _C.EC_KEY_get0_private_key(session)

      alpha = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_copy(alpha, s_pub);

      beta = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_copy(beta, self.pubkey);
      _C.EC_POINT_mul(self.ecgroup, beta, _FFI.NULL, beta, s_priv, _FFI.NULL)

      # Adding noise and setting the resolution
      n = _C.BN_new()
      res_noise = int(Noise(sigma, sum_of_sq, p_exit) * resolution)
      
      if res_noise < 0:
        _C.BN_set_word(n, -res_noise)
        _C.BN_set_negative(n, 1)
      else: 
        _C.BN_set_word(n, res_noise)

      kappa = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_mul(self.ecgroup, kappa, _FFI.NULL, self.gen, n, _FFI.NULL)
      _C.EC_POINT_add(self.ecgroup, beta, beta, kappa, _FFI.NULL)   
      _C.EC_POINT_free(kappa)

      _C.EC_KEY_free(session)
      _C.BN_clear_free(n)

      # Save the ECEG ciphertext
      c = (alpha, beta)
      self.lab[label] = c
      self.buf += [c]

      # Save the resolution
      resolute = _C.BN_new()
      _C.BN_set_word(resolute, resolution)
      self.resolution = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_mul(self.ecgroup, self.resolution, _FFI.NULL, self.gen, resolute, _FFI.NULL)
      _C.BN_clear_free(resolute)

  def addone(self, label):
    _C = self._C
    (_, beta) = self.lab[label]

    _C.EC_POINT_add(self.ecgroup, beta, beta, self.resolution, _FFI.NULL);

  def randomize(self):
    _C = self._C
    for (a,b) in self.buf:
      # Make session key
      session = _C.EC_KEY_new_by_curve_name(self.curveID)
      _C.EC_KEY_set_group(session, self.ecgroup)
      _C.EC_KEY_generate_key(session)

      s_pub = _C.EC_KEY_get0_public_key(session)
      s_priv = _C.EC_KEY_get0_private_key(session)

      alpha = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_copy(alpha, s_pub);

      beta = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_copy(beta, self.pubkey);
      _C.EC_POINT_mul(self.ecgroup, beta, _FFI.NULL, beta, s_priv, _FFI.NULL)

      _C.EC_POINT_add(self.ecgroup, a, a, alpha, _FFI.NULL);
      _C.EC_POINT_add(self.ecgroup, b, b, beta, _FFI.NULL);

      _C.EC_POINT_clear_free(alpha)
      _C.EC_POINT_clear_free(beta)

      _C.EC_KEY_free(session)

  def extract(self):
    buf = []
    for (a,b) in self.buf:
        acopy = _C.EC_POINT_dup(a, self.ecgroup)
        bcopy = _C.EC_POINT_dup(b, self.ecgroup)
        buf.append((acopy,bcopy))
    return buf

  def extract_into(self, data):
    clidata = self.buf
    hashval = hash_clidata(self.ecgroup, clidata)

    if data is None:
      return self.extract(), clidata, hashval

    assert len(self.buf) == len(data)

    for ((a,b), (alpha, beta)) in zip(data, self.buf):
      _C.EC_POINT_add(self.ecgroup, a, a, alpha, _FFI.NULL);
      _C.EC_POINT_add(self.ecgroup, b, b, beta, _FFI.NULL);

    return data, clidata, hashval

  def __del__(self):
    self._C.EC_GROUP_free(self.ecgroup)
    if self.buf is not None:
      for (a,b) in self.buf:
        self._C.EC_POINT_clear_free(a)
        self._C.EC_POINT_clear_free(b)

## Convert a point to a string representation
def point2str(ecgroup, point):
    bnctx = _C.BN_CTX_new()
    size = _C.EC_POINT_point2oct(ecgroup, point, _C.POINT_CONVERSION_COMPRESSED,
    _FFI.NULL, 0, bnctx)
    buf = _FFI.new("unsigned char[]", size)
    _C.EC_POINT_point2oct(ecgroup, point, _C.POINT_CONVERSION_COMPRESSED,
    buf, size, bnctx)
    _C.BN_CTX_free(bnctx)
    return buf, size

## Functions to create and check NIZKPKs
def NIZKPK_prove_DL(ecgroup, pub, priv):
    # b rand
    # B = b * G
    # c = H(G, pub, B)
    # s = priv * c + b
    # return (c,s)
    bB = _C.EC_KEY_new_by_curve_name(_C.EC_GROUP_get_curve_name(ecgroup))
    _C.EC_KEY_set_group(bB, ecgroup)
    _C.EC_KEY_generate_key(bB)
    b = _C.EC_KEY_get0_private_key(bB)
    B = _C.EC_KEY_get0_public_key(bB)
    G = _C.EC_GROUP_get0_generator(ecgroup)

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    c = _C.BN_bin2bn(md, 32, _FFI.NULL)

    bnctx = _C.BN_CTX_new()
    order = _C.BN_new()
    _C.EC_GROUP_get_order(ecgroup, order, bnctx)
    
    privc = _C.BN_new()
    s = _C.BN_new()
    _C.BN_mul(privc, priv, c, bnctx)
    _C.BN_mod_add(s, privc, b, order, bnctx)

    _C.EC_KEY_free(bB)
    _C.BN_CTX_free(bnctx)
    _C.BN_clear_free(privc)
    _C.BN_clear_free(order)
    return c,s

def NIZKPK_verify_DL(ecgroup, pub, proof):
    # c =?= H(G, pub, s * G - c * pub)
    c,s = proof

    negc = _C.BN_new()
    _C.BN_copy(negc, c)
    _C.BN_set_negative(negc, 1)

    G = _C.EC_GROUP_get0_generator(ecgroup)
    B = _C.EC_POINT_new(ecgroup)
    _C.EC_POINT_mul(ecgroup, B, s, pub, negc, _FFI.NULL)
    _C.BN_clear_free(negc)

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    cprime = _C.BN_bin2bn(md, 32, _FFI.NULL)

    diff = _C.BN_cmp(cprime, c)

    _C.BN_clear_free(cprime)
    _C.EC_POINT_free(B)

    if diff != 0:
        raise Exception("DL proof failed")

def NIZKPK_free_DL_proof(proof):
    c,s = proof
    _C.BN_clear_free(c)
    _C.BN_clear_free(s)

# Prove that DL_G(pub) = DL_X(Y) for each (X,Y) \in pairs.
# priv is this common private value.
def NIZKPK_prove_eqDL(ecgroup, pub, pairs, priv):
    # b rand
    # B = b * G
    # c = H(G, pub, <X,Y>_{(X,Y}\in pairs}, B, <b*X>_{(X,Y)\in pairs})
    # s = priv * c + b
    # return (c,s)
    bB = _C.EC_KEY_new_by_curve_name(_C.EC_GROUP_get_curve_name(ecgroup))
    _C.EC_KEY_set_group(bB, ecgroup)
    _C.EC_KEY_generate_key(bB)
    b = _C.EC_KEY_get0_private_key(bB)
    B = _C.EC_KEY_get0_public_key(bB)
    G = _C.EC_GROUP_get0_generator(ecgroup)
    T = _C.EC_POINT_new(ecgroup)
    bnctx = _C.BN_CTX_new()

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        buf, size = point2str(ecgroup, X)
        _C.SHA256_Update(ctx, buf, size)
        buf, size = point2str(ecgroup, Y)
        _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        _C.EC_POINT_mul(ecgroup, T, _FFI.NULL, X, b, bnctx)
        buf, size = point2str(ecgroup, T)
        _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    c = _C.BN_bin2bn(md, 32, _FFI.NULL)

    bnctx = _C.BN_CTX_new()
    order = _C.BN_new()
    _C.EC_GROUP_get_order(ecgroup, order, bnctx)

    privc = _C.BN_new()
    s = _C.BN_new()
    _C.BN_mul(privc, priv, c, bnctx)
    _C.BN_mod_add(s, privc, b, order, bnctx)

    _C.EC_KEY_free(bB)
    _C.EC_POINT_free(T)
    _C.BN_CTX_free(bnctx)
    _C.BN_clear_free(privc)
    _C.BN_clear_free(order)

    return pub, (pairs,c,s)

def NIZKPK_verify_eqDL(ecgroup, pub, proof):
    # c =?= H(G, pub, <X,Y>_{(X,Y)\in pairs}, s * G - c * pub,
    #            <s * X - c * Y>_{(X,Y)\in pairs})
    pairs,c,s = proof

    negc = _C.BN_new()
    _C.BN_copy(negc, c)
    _C.BN_set_negative(negc, 1)

    bnctx = _C.BN_CTX_new()
    G = _C.EC_GROUP_get0_generator(ecgroup)
    B = _C.EC_POINT_new(ecgroup)
    _C.EC_POINT_mul(ecgroup, B, s, pub, negc, bnctx)
    T1 = _C.EC_POINT_new(ecgroup)
    T = _C.EC_POINT_new(ecgroup)

    ctx = _FFI.new("SHA256_CTX *")
    md = _FFI.new("unsigned char[]", 32)
    _C.SHA256_Init(ctx)
    buf, size = point2str(ecgroup, G)
    _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, pub)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        buf, size = point2str(ecgroup, X)
        _C.SHA256_Update(ctx, buf, size)
        buf, size = point2str(ecgroup, Y)
        _C.SHA256_Update(ctx, buf, size)
    buf, size = point2str(ecgroup, B)
    _C.SHA256_Update(ctx, buf, size)
    for (X,Y) in pairs:
        _C.EC_POINT_mul(ecgroup, T1, _FFI.NULL, X, s, bnctx)
        _C.EC_POINT_mul(ecgroup, T, _FFI.NULL, Y, negc, bnctx)
        _C.EC_POINT_add(ecgroup, T, T, T1, bnctx)
        buf, size = point2str(ecgroup, T)
        _C.SHA256_Update(ctx, buf, size)
    _C.SHA256_Final(md, ctx)
    cprime = _C.BN_bin2bn(md, 32, _FFI.NULL)

    diff = _C.BN_cmp(cprime, c)

    _C.BN_clear_free(negc)
    _C.BN_clear_free(cprime)
    _C.EC_POINT_free(B)
    _C.EC_POINT_free(T)
    _C.EC_POINT_free(T1)
    _C.BN_CTX_free(bnctx)

    if diff != 0:
        raise Exception("eqDL proof failed")

def NIZKPK_free_eqDL_proof(proof):
    pairs,c,s = proof
    for (X,Y) in pairs:
        _C.EC_POINT_free(X)
        _C.EC_POINT_free(Y)
    _C.BN_clear_free(c)
    _C.BN_clear_free(s)

class partialDecryptor:
  def __init__(self, curveID = 409):
    global _C
    self._C = _C
    self.curveID = curveID

    # Store the group we work in
    # precompute tables and the generator
    self.ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)
    if not _C.EC_GROUP_have_precompute_mult(self.ecgroup):
        _C.EC_GROUP_precompute_mult(self.ecgroup, _FFI.NULL);
    self.gen = _C.EC_GROUP_get0_generator(self.ecgroup)

    ctx = _C.BN_CTX_new()
    self.bnorder = _C.BN_new()
    _C.EC_GROUP_get_order(self.ecgroup, self.bnorder, ctx)
    self.order = int(_FFI.string(_C.BN_bn2dec(self.bnorder)))
    _C.BN_CTX_free(ctx)

    self.key = _C.EC_KEY_new_by_curve_name(self.curveID)
    _C.EC_KEY_set_group(self.key, self.ecgroup)
    _C.EC_KEY_generate_key(self.key)

    s_priv = _C.EC_KEY_get0_private_key(self.key)
    s_pub = _C.EC_KEY_get0_public_key(self.key)
    self.proof = NIZKPK_prove_DL(self.ecgroup, s_pub, s_priv)


  def __del__(self):
    _C = self._C
    _C.EC_KEY_free(self.key)
    _C.EC_GROUP_free(self.ecgroup)
    _C.BN_clear_free(self.bnorder)

  def combinekey(self, pubkey = None):
    _C = self._C
    s_pub = _C.EC_KEY_get0_public_key(self.key)
    NIZKPK_verify_DL(self.ecgroup, s_pub, self.proof)
    NIZKPK_free_DL_proof(self.proof)
    self.proof = None
      
    if pubkey == None:
      
      pk = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_copy(pk, s_pub)
      return pk

    else:
      _C.EC_POINT_add(self.ecgroup, pubkey, pubkey, s_pub, _FFI.NULL);
      return pubkey
      
  def partialdecrypt(self, buf):
    _C = self._C
    pairs = []
    for (a,b) in buf:

      k_priv = _C.EC_KEY_get0_private_key(self.key)
      k_pub = _C.EC_KEY_get0_public_key(self.key)
      alpha = _C.EC_POINT_dup(a, self.ecgroup)
      savealpha = _C.EC_POINT_dup(a, self.ecgroup)

      _C.EC_POINT_mul(self.ecgroup, alpha, _FFI.NULL, alpha, k_priv, _FFI.NULL);
      savealphapriv = _C.EC_POINT_dup(alpha, self.ecgroup)
      pairs.append((savealpha, savealphapriv))
      _C.EC_POINT_invert(self.ecgroup, alpha, _FFI.NULL);
      _C.EC_POINT_add(self.ecgroup, b, b, alpha, _FFI.NULL);


      _C.EC_POINT_clear_free(alpha)

    proof = NIZKPK_prove_eqDL(self.ecgroup, k_pub, pairs, k_priv)
    return proof


  def finaldecrypt(self, buf, table=None, table_size=100000):
    _C = self._C
    gamma = _C.EC_POINT_new(self.ecgroup)

    table_min = _C.BN_new()
    _C.BN_set_word(table_min, table_size)
    _C.BN_set_negative(table_min, 1)

    _C.EC_POINT_mul(self.ecgroup, gamma, _FFI.NULL, self.gen, table_min, _FFI.NULL) 

    point_size = 200 ## Only use the first bytes as ID
    point_oct = _FFI.new("unsigned char[]", point_size)
    
    lookup = {}
    for i in range(-table_size,table_size):
        xsize = _C.EC_POINT_point2oct(self.ecgroup, gamma,  _C.POINT_CONVERSION_COMPRESSED,
          point_oct, point_size, _FFI.NULL);

        assert 0 < xsize < point_size

        lkey = _FFI.buffer(point_oct)[:min(16,xsize)]
        try:
            assert lkey not in lookup
            
        except:
            print "Key \"%s\"" % hexlify(lkey)
            print "Collision between %s and %s" % (i, lookup[lkey])
            raise
        lookup[lkey] = i

        _C.EC_POINT_add(self.ecgroup, gamma, gamma, self.gen, _FFI.NULL);         

    _C.EC_POINT_clear_free(gamma)

    cleartext = []
    for (_, b) in buf:
        xsize = _C.EC_POINT_point2oct(self.ecgroup, b,  _C.POINT_CONVERSION_COMPRESSED,
            point_oct, point_size, _FFI.NULL);

        lkey = _FFI.buffer(point_oct)[:min(16,xsize)]
        if lkey in lookup:
          cleartext += [int(lookup[lkey]/resolution)]
        else:
          #if _C.EC_POINT_is_at_infinity(self.ecgroup, b) == 1:
          #  cleartext += [0]
          #else:
          cleartext += [None]
    
    return cleartext     

  def test_decrypt(self):
        vals = []
        v = _C.BN_new()

        for i in range(-100, 100):
            gamma = _C.EC_POINT_new(self.ecgroup)
    
            if i < 0:
                _C.BN_set_word(v, -i*resolution)
                _C.BN_set_negative(v, 1)
            else:
                _C.BN_set_word(v, i*resolution)
            _C.EC_POINT_mul(self.ecgroup, gamma, _FFI.NULL, self.gen, v, _FFI.NULL) 

            vals += [(None, gamma)]
        return vals



if __name__ == "__main__":
  stats = StatKeeper()

  #ctx = _FFI.new("SHA256_CTX *")
  #md = _FFI.new("unsigned char[]", 32)
  #_C.SHA256_Init(ctx)
  #_C.SHA256_Update(ctx, "he", 2)
  #_C.SHA256_Update(ctx, "llo", 3)
  #_C.SHA256_Final(md, ctx)
  #print _FFI.buffer(md, 32)[:].encode("hex")

  D = []
  for _ in range(num_TKG): #changed from 5 to 10 TKGs.
    with(stats["decrypt_init"]):
      D += [partialDecryptor()]

  pk = None
  for Di in D:
    with(stats["decrypt_combinekey"]):
      pk = Di.combinekey(pk)

  labels = range(num_websites)
  clients = []
  for _ in range(num_DC): #changed from 10 to 1000 clients
    with(stats["client_init"]):
      c = crypto_counts(labels, pk)
      clients += [c]

  items = 100000
  mock = [0] * len(labels)
  for i in range(items):
    l = len(labels)
    x = clients[i % 10]
    ## Keep the last 10 as zero to test decryption
    with(stats["client_addone"]):
      x.addone(i % (l-10))
      mock[i % (l-10)] += 1

  for c in clients:
    with(stats["client_rerandomize"]):
      c.randomize()

  data = None
  hashes = []
  eqDLproofs = []
  for c in clients:
    with(stats["client_aggregate"]):
      data, clidata, hashval = c.extract_into(data)
      hashes.append((clidata, hashval))

  for Di in D:
    with(stats["decrypt_partial"]):
      # Check the hashes
      for (clidata, hashval) in hashes:
        if hash_clidata(Di.ecgroup, clidata) != hashval:
            raise Exception("Hash mismatch!")
      eqDLproofs.append(Di.partialdecrypt(data))

  for (a,b) in data[-10:]:
    # assert _C.EC_POINT_is_at_infinity(x.ecgroup, b) == 1
    pass

  with(stats["decrypt_final"]):
    for p in eqDLproofs:
        NIZKPK_verify_eqDL(x.ecgroup, p[0], p[1])
        NIZKPK_free_eqDL_proof(p[1])
    res = D[-1].finaldecrypt(data)

    # test decryption
    buf = D[-1].test_decrypt()
    result = D[-1].finaldecrypt(buf)
    assert result == range(-100,100)
    


    print res
    #assert sum(res) == items

  stats.print_stats()

  for (a,b) in data:
    _C.EC_POINT_clear_free(a)
    _C.EC_POINT_clear_free(b)
