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
#ifndef HASH_INL__
#define HASH_INL__

/* */
inline
HashAlgo::HashAlgo (int nid) : md_(EVP_get_digestbynid (nid))
{
  if (md_ == NULL)
    throw std::runtime_error ("could not allocate EVP from nid in HashAlgo");

  mdctx_ = EVP_MD_CTX_new ();
  if (mdctx_ == NULL)
    throw std::runtime_error ("EVP_MD_CTX_new failed in HashAlgo");
}

/* */
inline
HashAlgo::HashAlgo (SecLevel seclevel) : HashAlgo (seclevel.sha3_openssl_nid())
{
}

/* */
inline
HashAlgo::~HashAlgo ()
{
  EVP_MD_CTX_free (mdctx_);
}

/* */
inline
int HashAlgo::digest_size () const
{
  return EVP_MD_size (md_);
}

/* */
template <typename First, typename... Rem>
inline
HashAlgo::Digest HashAlgo::operator() (const First &first, const Rem&... rem)
{
  int ret = EVP_DigestInit_ex (mdctx_, md_, NULL);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestInit_ex failed in HashAlgo");

  Digest h (digest_size ());
  hash_update (first, rem...);

  ret = EVP_DigestFinal_ex (mdctx_, h.data(), NULL);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestFinal_ex failed in HashAlgo");

  return h;
}

/* */
template <typename First, typename... Rem>
inline
void HashAlgo::hash_update (const First &first, const Rem&... rem)
{
  hash_update (first);
  hash_update (rem...);
}

/* */
inline
void HashAlgo::hash_update_implem (const void *ptr, size_t n)
{
  int ret = EVP_DigestUpdate (mdctx_, ptr, n);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestUpdate failed in hash_update_implem");
}

/* */
template <>
void HashAlgo::hash_update (const std::vector<unsigned char> &m)
{
  hash_update_implem (m.data(), m.size() * sizeof(unsigned char));
}

#endif /* HASH_INL__ */
