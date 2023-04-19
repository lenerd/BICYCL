/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef EC_INL__
#define EC_INL__

/******************************************************************************/
/* */
inline
BN::BN () : bn_(BN_new())
{
  if (bn_ == NULL)
    throw std::runtime_error ("could not allocate BIGNUM");
}

/* */
inline
BN::~BN ()
{
  BN_free (bn_);
}

/* */
inline
bool BN::operator== (const BN &other) const
{
  return BN_cmp (bn_, other.bn_) == 0;
}

/* */
inline
BN & BN::operator= (const HashAlgo::Digest &digest)
{
  const BIGNUM *ret = BN_bin2bn (digest.data(), digest.size(), bn_);
  if (ret == NULL)
    throw std::runtime_error ("Could not set BIGNUM from binary");
  return *this;
}

/* */
inline
bool BN::is_zero () const
{
  return BN_is_zero (bn_);
}

/* */
inline
BN::operator BIGNUM *() const
{
  return bn_;
}

/****************************************************************************/
/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::ECPoint (const Cryptosystem &C) : P_(C.new_ec_point())
{
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::ECPoint (const Cryptosystem &C, const EC_POINT *Q)
  : P_(C.new_ec_point_copy (Q))
{
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem> & ECPoint<Cryptosystem>::operator= (const EC_POINT *Q)
{
  int ret = EC_POINT_copy (P_, Q);
  if (ret != 1)
    throw ("EC_POINT_copy failed in ECPoint::operator=");
  return *this;
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::~ECPoint ()
{
  EC_POINT_free (P_);
}

/* */
template <typename Cryptosystem>
inline
ECPoint<Cryptosystem>::operator EC_POINT * () const
{
  return P_;
}

/******************************************************************************/
/* */
template <typename Cryptosystem>
inline
ECKey<Cryptosystem>::ECKey (const Cryptosystem &C)
    : key_ (C.new_ec_key())
{
}

/* */
template <typename Cryptosystem>
inline
ECKey<Cryptosystem>::~ECKey ()
{
  EC_KEY_free (key_);
}

/* */
template <typename Cryptosystem>
inline
ECKey<Cryptosystem>::operator const BIGNUM *() const
{
  return EC_KEY_get0_private_key (key_);
}

/* */
template <typename Cryptosystem>
inline
const EC_POINT * ECKey<Cryptosystem>::get_ec_point () const
{
  return EC_KEY_get0_public_key (key_);
}

/******************************************************************************/
/* */
inline
ECGroup::ECGroup (SecLevel seclevel) : ctx_ (BN_CTX_new())
{
  int nid = seclevel.elliptic_curve_openssl_nid(); /* openssl curve id */
  ec_group_ = EC_GROUP_new_by_curve_name (nid);
  if (ec_group_ == NULL)
    throw std::runtime_error ("could not allocate elliptic curve");

  if (ctx_ == NULL)
    throw std::runtime_error ("could not allocate BN_CTX");

  order_ = EC_GROUP_get0_order (ec_group_);
}

/* */
inline
ECGroup::~ECGroup ()
{
  EC_GROUP_free (ec_group_);
  BN_CTX_free (ctx_);
}

/* */
inline
const EC_POINT * ECGroup::gen () const
{
  return EC_GROUP_get0_generator (ec_group_);
}

/* */
inline
const Mpz & ECGroup::order () const
{
  return order_;
}

/* */
inline
void ECGroup::get_coords_of_point (BIGNUM *x, BIGNUM *y,
                                              const EC_POINT *P) const
{
  int ret = EC_POINT_get_affine_coordinates (ec_group_, P, x, y, ctx_);
  if (ret != 1)
    throw std::runtime_error ("Could not get x, y coordinates");
}

/* */
inline
void ECGroup::get_x_coord_of_point (BIGNUM *x, const EC_POINT *P) const
{
  get_coords_of_point (x, NULL, P);
}

/* */
inline
bool ECGroup::ec_point_eq (const EC_POINT *P, const EC_POINT *Q) const
{
  return EC_POINT_cmp (ec_group_, P, Q, ctx_) == 0;
}

/* */
inline
void ECGroup::ec_add (EC_POINT *R, const EC_POINT *P, const EC_POINT *Q) const
{
  int ret = EC_POINT_add (ec_group_, R, P, Q, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_add failed in add");
}

/* */
inline
void ECGroup::scal_mul_gen (EC_POINT *R, const BIGNUM *n) const
{
  int ret = EC_POINT_mul (ec_group_, R, n, NULL, NULL, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul_gen");
}

/* */
inline
void ECGroup::scal_mul (EC_POINT *R, const BIGNUM *n, const EC_POINT *P) const
{
  int ret = EC_POINT_mul (ec_group_, R, NULL, P, n, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul");
}

/* We assume that the order is prime (which must be the case for NIST curves) */
inline
bool ECGroup::has_correct_order (const EC_POINT *G) const
{
  if (EC_POINT_is_at_infinity (ec_group_, G))
    return false;

  if (!EC_POINT_is_on_curve (ec_group_, G, ctx_))
    return false;

  EC_POINT *T = EC_POINT_new (ec_group_);
  if (T == NULL)
    throw std::runtime_error ("EC_POINT_new failed in has_correct_order");

  scal_mul (T, EC_GROUP_get0_order (ec_group_), G);
  bool is_gen = EC_POINT_is_at_infinity (ec_group_, T);
  EC_POINT_free (T);
  return is_gen;
}

/* */
inline
EC_POINT * ECGroup::new_ec_point () const
{
  EC_POINT *P = EC_POINT_new (ec_group_);
  if (P == NULL)
    throw ("EC_POINT_new failed in new_ec_point");
  return P;

}

/* */
inline
EC_POINT * ECGroup::new_ec_point_copy (const EC_POINT *P) const
{
  EC_POINT *Q = EC_POINT_dup (P, ec_group_);
  if (Q == NULL)
    throw ("EC_POINT_dup failed in new_ec_point_copy");
  return Q;
}

/* */
inline
EC_KEY * ECGroup::new_ec_key () const
{
  EC_KEY *key = EC_KEY_new();
  if (key == NULL)
    throw std::runtime_error ("could not allocate EC_KEY in new_ec_key");

  int ret = EC_KEY_set_group (key, ec_group_);
  if (ret != 1)
    throw std::runtime_error ("could not set group in new_ec_key");

  ret = EC_KEY_generate_key (key);
  if (ret != 1)
    throw std::runtime_error ("could not generate key in new_ec_key");

  return key;
}

/* */
inline
void ECGroup::mod_order (BIGNUM *r, const BIGNUM *a) const
{
  int ret = BN_nnmod (r, a, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_nnmod failed");
}

/* */
inline
void ECGroup::add_mod_order (BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const
{
  int ret = BN_mod_add (r, a, b, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_mod_add failed");
}

/* */
inline
void ECGroup::mul_mod_order (BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const
{
  int ret = BN_mod_mul (r, a, b, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_mod_mul failed");
}

/* */
inline
void ECGroup::inverse_mod_order (BIGNUM *r, const BIGNUM *a) const
{
  BIGNUM *ret = BN_mod_inverse (r, a, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret == NULL)
    throw std::runtime_error ("could not inverse modulo order");
}

/* */
inline
bool ECGroup::is_positive_less_than_order (const BIGNUM *v) const
{
  const BIGNUM *order = EC_GROUP_get0_order (ec_group_);
  return  !BN_is_negative (v) && !BN_is_zero (v) && BN_cmp (v, order) < 0;
}

/******************************************************************************/
/* */
inline
ECDSA::ECDSA (SecLevel seclevel) : ECGroup(seclevel), H_(seclevel)
{
}

/* */
inline
ECDSA::SecretKey ECDSA::keygen () const
{
  return SecretKey (*this);
}

/* */
inline
ECDSA::PublicKey ECDSA::keygen (const SecretKey &sk) const
{
  return PublicKey (*this, sk.get_ec_point());
}

/* */
inline
void ECDSA::hash_message (BN &h, const Message &m) const
{
  h = H_ (m);
}

/* */
inline
ECDSA::Signature ECDSA::sign (const SecretKey &sk, const Message &m) const
{
  return Signature (*this, sk, m);
}

/* */
inline
ECDSA::Signature::Signature (const ECDSA &C, const SecretKey &sk,
                                             const Message &m)
{
  BN z, tmp;

  C.hash_message (z, m);

  do
  {
    SecretKey k (C);
    if (BN_is_zero (k))
      continue;

    C.get_x_coord_of_point (tmp, k.get_ec_point());
    C.mod_order (r_, tmp);
    if (r_.is_zero())
      continue;

    C.mul_mod_order (s_, r_, sk);

    int ret = BN_add (s_, s_, z);
    if (ret != 1)
      throw std::runtime_error ("BN_add failed in signature");

    C.inverse_mod_order (tmp, k);
    C.mul_mod_order (s_, s_, tmp);
  } while (s_.is_zero());
}

/* */
inline
bool ECDSA::verif (const Signature &signature, const PublicKey &Q,
                                               const Message &m) const
{
  BN z, sinv, u1, u2, x1, tmp;

  if (!has_correct_order (Q)) /* check that Q as order n */
    return false;

  if (!is_positive_less_than_order (signature.r_))
    return false;

  if (!is_positive_less_than_order (signature.s_))
    return false;

  bool ok = true;
  ECPoint<ECDSA> T (*this);
  hash_message (z, m);
  inverse_mod_order (sinv, signature.s_);
  mul_mod_order (u1, sinv, z);
  mul_mod_order (u2, sinv, signature.r_);

  int ret = EC_POINT_mul (ec_group_, T, u1, Q, u2, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in verif");

  if (EC_POINT_is_at_infinity (ec_group_, T))
    ok = false;
  else
  {
    get_x_coord_of_point (tmp, T);
    mod_order (x1, tmp);

    ok = BN_cmp (x1, signature.r_) == 0;
  }

  return ok;
}

/* random message of random length between 4 and UCHAR_MAX */
inline
ECDSA::Message ECDSA::random_message () const
{
  unsigned char size;
  RAND_bytes (&size, 1 * sizeof (unsigned char));
  size = (size < 4) ? 4 : size;
  Message m (size);
  RAND_bytes (m.data(), m.size() * sizeof (unsigned char));
  return m;
}

/******************************************************************************/
/* */
inline
ECNIZK::ECNIZK (SecLevel seclevel) : ECGroup(seclevel), H_(seclevel)
{
}

/* */
inline
ECNIZK::PublicValue ECNIZK::public_value_from_secret (const SecretValue &s) const
{
  return PublicValue (*this, s.get_ec_point());
}

/* */
inline
void ECNIZK::hash_for_challenge (BN &c, const EC_POINT *R,
                                                const EC_POINT *Q) const
{
  BN xG, yG, xR, yR, xQ, yQ;
  get_coords_of_point (xG, yG, gen());
  get_coords_of_point (xR, yR, R);
  get_coords_of_point (xQ, yQ, Q);

  c = H_ (xG, yG, xR, yR, xQ, yQ);
}

/* */
inline
ECNIZK::Proof ECNIZK::noninteractive_proof (const SecretValue &s) const
{
  return Proof (*this, s);
}

/* */
inline
ECNIZK::Proof::Proof (const ECNIZK &C, const SecretValue &s) : R_(C)
{
  SecretValue r (C);
  R_ = r.get_ec_point();
  BN tmp;

  C.hash_for_challenge (c_, R_, s.get_ec_point ());

  C.mul_mod_order (tmp, c_, s);
  C.add_mod_order (z_, tmp, r); /* z = r + c*s */
}

/* */
inline
bool ECNIZK::noninteractive_verify (const PublicValue &Q,
                                    const Proof &proof) const
{
  return proof.verify (*this, Q);
}

/* */
inline
bool ECNIZK::Proof::verify (const ECNIZK &C, const PublicValue &Q) const
{
  BN c;
  C.hash_for_challenge (c, R_, Q);

  ECPoint<ECNIZK> lhs (C);
  ECPoint<ECNIZK> rhs (C);

  C.scal_mul_gen (lhs, z_); /* z*G */

  C.scal_mul (rhs, c, Q);
  C.ec_add (rhs, R_, rhs); /* R + c*Q */

  return c == c_ && C.ec_point_eq (lhs, rhs);
}

/******************************************************************************/
/* */
template <>
void HashAlgo::hash_update (const BN &v)
{
  std::vector<unsigned char> bin (BN_num_bytes (v));
  BN_bn2bin (v.bn_, bin.data());
  hash_update (bin);
}

#endif /* EC_INL__ */
