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

  class ECGroup
  {
    protected:
      EC_GROUP *ec_group_;
      Mpz order_;

    public:
      /* constructors */
      ECGroup (SecLevel seclevel);

      /* destructor */
      ~ECGroup ();

      /* getters */
      const Mpz & order () const;
      const EC_GROUP * group () const;

      /* */
      bool is_generator (const EC_POINT *G) const;

    protected:
      /* utils */
      void scal_mul_by_order (EC_POINT *R, const EC_POINT *P) const;

  }; /* ECGroup */

  class ECDSA
  {
    protected:
      ECGroup ec_;
      mutable HashAlgo H_;

    public:
      /*** Secret Key ***/
      class SecretKey
      {
        protected:
          EC_KEY *key_;
          Mpz sk_;

        public:
          /* constructors */
          SecretKey (const ECDSA &);

          /* destructor */
          ~SecretKey ();

          /* getters */
          const EC_POINT * get_public_key () const;
          const Mpz & get_secret_key () const;
      };

      /*** Public Key ***/
      class PublicKey
      {
        protected:
          const EC_POINT * pk_;

        public:
          /* constructors */
          PublicKey (const SecretKey &);

          /* getters */
          const EC_POINT * ec_point () const;
      };

      /*** Message ***/
      using Message = std::vector<unsigned char>;

      /*** Signature ***/
      class Signature
      {
        protected:
          Mpz r_, s_;

        public:
          /* constructors */
          Signature (const ECDSA &C, const SecretKey &sk, const Message &m);

          /* getters */
          const Mpz & r () const;
          const Mpz & s () const;
      };

      /* constructors */
      ECDSA (SecLevel seclevel);

      /* getters */
      const Mpz & order () const;

      /* crypto protocol */
      SecretKey keygen () const;
      PublicKey keygen (const SecretKey &sk) const;
      Mpz hash_message (const Message &m) const;
      Signature sign (const SecretKey &sk, const Message &m) const;
      bool verif (const Signature &s, const PublicKey &pk, const Message &m) const;

      /* utils */
      Message random_message () const;
  }; /* ECDSA */

  #include "ec.inl"

} /* BICYCL namespace */

#endif /* EC_HPP__ */
