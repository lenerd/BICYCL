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

/* */
inline
ECGroup::ECGroup (SecLevel seclevel)
{
  int nid = seclevel.elliptic_curve_openssl_nid(); /* openssl curve id */
  ec_group_ = EC_GROUP_new_by_curve_name (nid);
  if (ec_group_ == NULL)
    throw std::runtime_error ("could not allocate elliptic curve");

  order_ = EC_GROUP_get0_order (ec_group_);
}

/* */
inline
ECGroup::~ECGroup ()
{
  EC_GROUP_free (ec_group_);
}

/* */
inline
const Mpz & ECGroup::order () const
{
  return order_;
}

/* */
inline
const EC_GROUP * ECGroup::group () const
{
  return ec_group_;
}

/* We assume that the order is prime (which must be the case for NIST curves) */
inline
bool ECGroup::is_generator (const EC_POINT *G) const
{
  if (EC_POINT_is_at_infinity (ec_group_, G))
    return false;

  if (!EC_POINT_is_on_curve (ec_group_, G, NULL))
    return false;

  EC_POINT *T = EC_POINT_new (ec_group_);
  if (T == NULL)
    throw std::runtime_error ("could not allocate EC_POINT in is_generator");

  scal_mul_by_order (T, G);
  bool is_gen = EC_POINT_is_at_infinity (ec_group_, T);
  EC_POINT_free (T);
  return is_gen;
}

/* */
inline
void ECGroup::scal_mul_by_order (EC_POINT *R, const EC_POINT *P) const
{
  const BIGNUM *n = EC_GROUP_get0_order (ec_group_);
  int ret = EC_POINT_mul (ec_group_, R, NULL, P, n, NULL);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul_by_order");
}

/******************************************************************************/
/* */
inline
ECDSA::ECDSA (SecLevel seclevel) : ec_(seclevel), H_(seclevel)
{
}

/* */
const Mpz & ECDSA::order () const
{
  return ec_.order();
}

/* */
inline
ECDSA::SecretKey ECDSA::keygen () const
{
  return SecretKey (*this);
}

/* */
inline
ECDSA::SecretKey::SecretKey (const ECDSA &C)
{
  const EC_GROUP *ec = C.ec_.group();
  int ret;

  key_ = EC_KEY_new();
  if (key_ == NULL)
    throw std::runtime_error ("could not allocate EC_KEY");

  ret = EC_KEY_set_group (key_, ec);
  if (ret != 1)
    throw std::runtime_error ("could not associate SecretKey with ECDSA group");

  EC_KEY_generate_key (key_);
  sk_ = EC_KEY_get0_private_key (key_);
}

/* */
inline
const Mpz & ECDSA::SecretKey::get_secret_key () const
{
  return sk_;
}

/* */
inline
const EC_POINT * ECDSA::SecretKey::get_public_key () const
{
  return EC_KEY_get0_public_key (key_);
}

/* */
inline
ECDSA::SecretKey::~SecretKey ()
{
  EC_KEY_free (key_);
}

/* */
inline
ECDSA::PublicKey ECDSA::keygen (const SecretKey &sk) const
{
  return PublicKey (sk);
}

/* */
inline
ECDSA::PublicKey::PublicKey (const SecretKey &sk) : pk_(sk.get_public_key ())
{
}

/* */
inline
const EC_POINT * ECDSA::PublicKey::ec_point () const
{
  return pk_;
}

/* */
Mpz ECDSA::hash_message (const Message &m) const
{
  size_t Ln = std::min ((size_t) H_.digest_size () * CHAR_BIT, order().nbits());
  return Mpz (H_(m), Ln);
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
  const Mpz & n = C.order();
  Mpz z = C.hash_message (m);
  Mpz kinv;
  do
  {
    SecretKey per_message (C);
    const Mpz & k = per_message.get_secret_key();
    if (k.is_zero())
      continue;
    const EC_POINT *Q = per_message.get_public_key ();

    BIGNUM *t = BN_new();
    EC_POINT_get_affine_coordinates (C.ec_.group(), Q, t, NULL, NULL);
    r_ = t;
    BN_free (t);
    Mpz::mod (r_, r_, n);
    if (r_.is_zero())
      continue;

    Mpz::mul (s_, r_, sk.get_secret_key());
    Mpz::mod (s_, s_, n);
    Mpz::add (s_, s_, z);
    Mpz::mod_inverse (kinv, k, n);
    Mpz::mul (s_, s_, kinv);
    Mpz::mod (s_, s_, n);
  } while (s_.is_zero() && false);
}

/* */
inline
const Mpz & ECDSA::Signature::r () const
{
  return r_;
}

/* */
inline
const Mpz & ECDSA::Signature::s () const
{
  return s_;
}

/* */
inline
bool ECDSA::verif (const Signature &s, const PublicKey &pk,
                                       const Message &m) const
{
  const EC_GROUP *ec = ec_.group();
  const EC_POINT *Q = pk.ec_point();
  const Mpz & n = order();

  if (!ec_.is_generator (Q)) /* check that Q as order n */
    return false;

  if (s.r() < 1UL || s.r() >= n || s.s() < 1UL || s.s() >= n)
    return false;

  bool ok = true;
  EC_POINT *T = EC_POINT_new (ec);
  Mpz z = hash_message (m);
  Mpz u1, u2, sinv;
  Mpz::mod_inverse (sinv, s.s(), n);
  Mpz::mul (u1, sinv, z);
  Mpz::mod (u1, u1, n);
  Mpz::mul (u2, sinv, s.r());
  Mpz::mod (u2, u2, n);

  BIGNUM *bn_u1 = u1;
  BIGNUM *bn_u2 = u2;

  int ret = EC_POINT_mul (ec, T, bn_u1, Q, bn_u2, NULL);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in verif");

  if (EC_POINT_is_at_infinity (ec, T))
    ok = false;
  else
  {
    BIGNUM *bn_x1 = BN_new();
    ret = EC_POINT_get_affine_coordinates (ec, T, bn_x1, NULL, NULL);
    if (ret != 1)
      throw std::runtime_error ("Could not get x coordinates in verif");
    Mpz x1;
    x1 = bn_x1;
    Mpz::mod (x1, x1, n);

    ok = (x1 == s.r());

    BN_free (bn_x1);
  }

  BN_free (bn_u1);
  BN_free (bn_u2);
  EC_POINT_free (T);

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

#endif /* EC_INL__ */
