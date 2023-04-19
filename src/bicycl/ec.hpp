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
#ifndef EC_HPP__
#define EC_HPP__

#include <stdexcept>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h> /* for SHA3 */
#include <openssl/rand.h>

#include "bicycl/seclevel.hpp"
#include "bicycl/gmp_extras.hpp"

namespace BICYCL
{
  /*****/
  class BN
  {
    protected:
      BIGNUM *bn_;

    public:
      BN ();
      ~BN ();

      /* */
      BN & operator= (const HashAlgo::Digest &digest);
      bool operator== (const BN &other) const;
      bool is_zero () const;

    friend class ECGroup;
    friend class ECDSA;
    friend class ECNIZK;
    friend HashAlgo;

    protected:
      operator BIGNUM *() const;
  }; /* BN */

  /*****/
  template <typename Cryptosystem>
  class ECPoint
  {
    protected:
      EC_POINT *P_;

    public:
      ECPoint (const Cryptosystem &C);
      ECPoint (const Cryptosystem &C, const EC_POINT *Q);
      ~ECPoint ();

      ECPoint & operator= (const EC_POINT *Q);

      friend Cryptosystem;

    protected:
      operator EC_POINT *() const;
  }; /* ECPoint */


  /*****/
  template <typename Cryptosystem>
  class ECKey
  {
    protected:
      EC_KEY *key_;

    public:
      /* constructors */
      ECKey (const Cryptosystem &);

      /* destructor */
      ~ECKey ();

      friend Cryptosystem;

    protected:
      /* conversion */
      operator const BIGNUM *() const;

      /* getters */
      const EC_POINT * get_ec_point () const;
  }; /* ECKey */

  /****/
  class ECGroup
  {
    protected:
      EC_GROUP *ec_group_;
      Mpz order_;
      BN_CTX *ctx_;

    public:
      /* constructors */
      ECGroup (SecLevel seclevel);

      /* destructor */
      ~ECGroup ();

      /* getters */
      const Mpz & order () const;

      /* Wrapper to easily create EC_POINT * and EC_KEY *.
       * Return values must be freed using EC_POINT_free or EC_KEY_free.
       */
      EC_POINT * new_ec_point () const;
      EC_POINT * new_ec_point_copy (const EC_POINT *P) const;
      EC_KEY * new_ec_key () const;

    protected:
      /* utils */
      const EC_POINT * gen () const;
      bool has_correct_order (const EC_POINT *G) const;

      /* arithmetic operations modulo the group order */
      void mod_order (BIGNUM *r, const BIGNUM *a) const;
      void add_mod_order (BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const;
      void mul_mod_order (BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const;
      void inverse_mod_order (BIGNUM *r, const BIGNUM *a) const;
      bool is_positive_less_than_order (const BIGNUM *v) const;

      /* elliptic operations */
      bool ec_point_eq (const EC_POINT *P, const EC_POINT *Q) const;
      void get_coords_of_point (BIGNUM *x, BIGNUM *y, const EC_POINT *P) const;
      void get_x_coord_of_point (BIGNUM *x, const EC_POINT *P) const;
      void ec_add (EC_POINT *R, const EC_POINT *P, const EC_POINT *Q) const;
      void scal_mul_gen (EC_POINT *R, const BIGNUM *n) const;
      void scal_mul (EC_POINT *R, const BIGNUM *n, const EC_POINT *P) const;

  }; /* ECGroup */

  /*****/
  class ECDSA : public ECGroup
  {
    protected:
      mutable HashAlgo H_;

    public:
      using SecretKey = ECKey<ECDSA>;
      using PublicKey = ECPoint<ECDSA>;
      using Message = std::vector<unsigned char>;

      /*** Signature ***/
      class Signature
      {
        protected:
          BN r_, s_;

        public:
          /* constructors */
          Signature (const ECDSA &C, const SecretKey &sk, const Message &m);

          friend ECDSA;
      };

      /* constructors */
      ECDSA (SecLevel seclevel);

      /* crypto protocol */
      SecretKey keygen () const;
      PublicKey keygen (const SecretKey &sk) const;
      Signature sign (const SecretKey &sk, const Message &m) const;
      bool verif (const Signature &s, const PublicKey &pk, const Message &m) const;

      /* utils */
      Message random_message () const;

    protected:
      void hash_message (BN &h, const Message &m) const;
  }; /* ECDSA */

  /*****/
  class ECNIZK : public ECGroup
  {
    protected:
      mutable HashAlgo H_;

    public:
      using SecretValue = ECKey<ECNIZK>;
      using PublicValue = ECPoint<ECNIZK>;

      class Proof
      {
        protected:
          ECPoint<ECNIZK> R_;
          BN c_;
          BN z_;

        public:
          Proof (const ECNIZK &C, const SecretValue &s);

          bool verify (const ECNIZK &C, const PublicValue &Q) const;
      };

      /* constructors */
      ECNIZK (SecLevel seclevel);

      PublicValue public_value_from_secret (const SecretValue &s) const;

      /* crypto protocol */
      Proof noninteractive_proof (const SecretValue &s) const;
      bool noninteractive_verify (const PublicValue &Q,
                                  const Proof &proof) const;

    protected:
      /* utils */
      void hash_for_challenge (BN &c, const EC_POINT *R,
                                              const EC_POINT *Q) const;

  }; /* ECNIZK */

  #include "ec.inl"

} /* BICYCL namespace */

#endif /* EC_HPP__ */
