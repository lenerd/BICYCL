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

  BIGNUM *tmp = BN_new();
  if (tmp == NULL)
    throw std::runtime_error ("could not allocate OpenSSL BIGNUM");

  int ret = EC_GROUP_get_order (ec_group_, tmp, NULL);
  if (!ret)
    throw std::runtime_error ("EC_GROUP_get_order failed");

  order_ = tmp;

  BN_free (tmp);
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

/******************************************************************************/
/* */
inline
ECDSA::ECDSA (SecLevel seclevel) : ec_(seclevel),
                          md_(EVP_get_digestbynid (seclevel.sha3_openssl_nid()))
{
  if (md_ == NULL)
    throw std::runtime_error ("could not allocate EVP from nid in ECDSA");

  mdctx_ = EVP_MD_CTX_new ();
  if (mdctx_ == NULL)
    throw std::runtime_error ("EVP_MD_CTX_new failed in ECDSA");
}

/* */
const Mpz & ECDSA::order () const
{
  return ec_.order();
}

/* */
inline
ECDSA::SecretKey ECDSA::keygen (RandGen &randgen) const
{
  return SecretKey (*this, randgen);
}

/* */
inline
ECDSA::SecretKey::SecretKey (const ECDSA &C, RandGen &randgen)
{
  const EC_GROUP *ec = C.ec_.group();
  int ret;

  key_ = EC_KEY_new();
  if (key_ == NULL)
    throw std::runtime_error ("could not allocate EC_KEY");

  ret = EC_KEY_set_group (key_, ec);
  if (ret != 1)
    throw std::runtime_error ("could not associate SecretKey with ECDSA group");

  sk_ = (randgen.random_mpz (C.ec_.order()));

  BIGNUM *s = static_cast<BIGNUM *>(sk_);

  ret = EC_KEY_set_private_key (key_, s);
  if (ret != 1)
    throw std::runtime_error ("could not set private key of EC_KEY");

  EC_POINT *P = EC_POINT_new (ec);
  if (key_ == NULL)
    throw std::runtime_error ("could not allocate temporary EC_POINT");
  ret = EC_POINT_mul (ec, P, s, NULL, NULL, NULL);
  if (ret != 1)
    throw std::runtime_error ("could not compute public key from private key");
  EC_KEY_set_public_key (key_, P);
  if (ret != 1)
    throw std::runtime_error ("could not set public key of EC_KEY");

  EC_POINT_free (P);
  BN_free (s);
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
  int ret;

  ret = EVP_DigestInit_ex (mdctx_, md_, NULL);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestInit_ex failed in ECDSA");

  ret = EVP_DigestUpdate (mdctx_, m.data(), m.size());

  if (ret != 1)
    throw std::runtime_error ("EVP_DigestUpdate failed in ECDSA");

  std::vector<unsigned char> digest (EVP_MD_size (md_));
  ret = EVP_DigestFinal_ex (mdctx_, digest.data(), NULL);

  size_t Ln = std::min ((size_t) EVP_MD_size (md_) * CHAR_BIT, order().nbits());
  return Mpz (digest, Ln); // TODO do the same for ZKAoK
}

/* */
inline
ECDSA::Signature ECDSA::sign (const SecretKey &sk, const Message &m,
                                                   RandGen &randgen) const
{
  return Signature (*this, sk, m, randgen);
}

/* */
inline
ECDSA::Signature::Signature (const ECDSA &C, const SecretKey &sk,
                                             const Message &m, RandGen &randgen)
{
  const Mpz & n = C.order();
  Mpz z = C.hash_message (m);
  Mpz kinv;
  do
  {
    SecretKey per_message (C, randgen);
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

  bool ok = true;

  if (EC_POINT_is_at_infinity (ec, Q))
    return false;

  if (!EC_POINT_is_on_curve (ec, Q, NULL))
    return false;

  BIGNUM *bn_order = n;
  EC_POINT *T = EC_POINT_new (ec);

  int ret = EC_POINT_mul (ec, T, NULL, Q, bn_order, NULL);
  if (ret != 1 || !EC_POINT_is_at_infinity (ec, T))
    ok = false;
  else
  {
    if (s.r() < 1UL || s.r() >= n || s.s() < 1UL || s.s() >= n)
      ok = false;
    {
      Mpz z = hash_message (m);
      Mpz u1, u2, sinv;
      Mpz::mod_inverse (sinv, s.s(), n);
      Mpz::mul (u1, sinv, z);
      Mpz::mod (u1, u1, n);
      Mpz::mul (u2, sinv, s.r());
      Mpz::mod (u2, u2, n);

      BIGNUM *bn_u1 = u1;
      BIGNUM *bn_u2 = u2;

      ret = EC_POINT_mul (ec, T, bn_u1, Q, bn_u2, NULL);
      if (ret != 1 || EC_POINT_is_at_infinity (ec, T))
        ok = false;
      else
      {
        BIGNUM *bn_x1 = BN_new();
        EC_POINT_get_affine_coordinates (ec, T, bn_x1, NULL, NULL);
        Mpz x1;
        x1 = bn_x1;
        Mpz::mod (x1, x1, n);

        ok = (x1 == s.r());

        BN_free (bn_x1);
      }

      BN_free (bn_u1);
      BN_free (bn_u2);
    }
  }

  BN_free (bn_order);
  EC_POINT_free (T);

  return ok;
}

/* */
inline
ECDSA::~ECDSA ()
{
  EVP_MD_CTX_free (mdctx_);
}

#endif /* EC_INL__ */
