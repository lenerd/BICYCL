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
#ifndef HASH_HPP__
#define HASH_HPP__

#include <stdexcept>
#include <vector>

#include <openssl/evp.h>

#include "bicycl/seclevel.hpp"

namespace BICYCL
{
  class HashAlgo
  {
    protected:
      const EVP_MD *md_;
      EVP_MD_CTX *mdctx_;

    public:
      using Digest = std::vector<unsigned char>;

      /* constructors */
      HashAlgo (SecLevel seclevel); /* Use SHA3 with desired security level */
      HashAlgo (int nid);

      /* destructor */
      ~HashAlgo ();

      /* getters */
      int digest_size () const;

      template <typename First, typename... Rem>
      Digest operator() (const First &first, const Rem&... rem);

    protected:
      template <typename First, typename... Rem>
      void hash_update (const First & first, const Rem&... rem);

      void hash_update_implem (const void *ptr, size_t n);
  };

  #include "hash.inl"

} /* BICYCL namespace */


#endif /* HASH_HPP__ */
