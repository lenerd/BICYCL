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
#include <cstring>

#include "bicycl.hpp"
#include "internals.hpp"

using namespace BICYCL;

bool
test_mpz_extract_bits (RandGen &randgen)
{
  bool ret = true;
  Mpz n, t;

  /* test for different sizes */
  for (size_t abits = 1; abits < 200; abits+=5)
  {
    n = randgen.random_mpz_2exp (abits);

    for (size_t j = 0; j < 100; j++)
    {
      unsigned long len = randgen.random_ui (GMP_LIMB_BITS);
      unsigned long index = randgen.random_ui (abits);

      mp_limb_t r = n.extract_bits (index, len);

      if (len < index+1)
        Mpz::divby2k (t, n, index-len+1);
      else
        Mpz::mulby2k (t, n, len-index-1);
      Mpz::mod2k (t, t, len);

      ret &= (t == r);
    }
  }

  return ret;
}

bool
test_mpz_random_prime (RandGen &randgen)
{
  bool ret = true;
  Mpz p;

  /* test that with nbits <= 1, random_prime returns 2 */
  p = randgen.random_prime (0);
  ret &= (p == 2UL);
  p = randgen.random_prime (1);
  ret &= (p == 2UL);

  /* test for different sizes that the output is prime with the required number
   * of bits.
   */
  for (size_t nb = 5; nb < 200; nb+=5)
  {
    p = randgen.random_prime (nb);
    ret &= p.is_prime ();
    ret &= p.nbits() == nb;
  }

  return ret;
}

bool
test_mpz_sqrt_mod_prime (RandGen &randgen)
{
  bool ret = true;
  Mpz l, r, s;

  for (size_t nb = 5; nb < 200; nb+=5)
  {
    l = randgen.random_prime (nb);

    for (size_t i = 0; i < 10; i++)
    {
      s = randgen.random_mpz (l);
      for (; s.kronecker (l) != 1; s = randgen.random_mpz (l));
      Mpz::sqrt_mod_prime (r, s, l);
      Mpz::mul (r, r, r);
      Mpz::mod (r, r, l);
      ret &= r == s;
    }
  }

  return ret;
}

bool
test_mpz_partial_euclid_scratch (RandGen &randgen)
{
  //test negative b
  // do we need |a| > |b|
  bool ret = true;
  Mpz a0, b0, a, b, m00, m01, m10, m11, t;

  /* test for different sizes of nlimb, a and b */
  for (size_t nlimb = 1; nlimb < 10; nlimb++)
  {
    for (size_t abits = 1; abits < 1280; abits+=50)
    {
      a0 = randgen.random_mpz_2exp (abits);
      if (randgen.random_bool ())
        a0.neg ();
      for (size_t bbits = 1; bbits < 1280; bbits+=50)
      {
        b0 = randgen.random_mpz_2exp (bbits);
        if (randgen.random_bool ())
          b0.neg ();
        a = a0;
        b = b0;
        Mpz::partial_euclid (m00, m01, m10, m11, a, b, nlimb);

        Mpz::mul (t, m00, m11);
        Mpz::submul (t, m10, m01);
        ret &= t.is_one(); /* det(M) == 1 */

        Mpz::mul (t, m00, a);
        Mpz::addmul (t, m01, b);
        ret &= t == a0; /* M*(a,b) == (a0, ...) */

        Mpz::mul (t, m10, a);
        Mpz::addmul (t, m11, b);
        ret &= t == b0; /* M*(a,b) = (..., b0) */
      }
    }
  }

  return ret;
}

bool
test_JSF (RandGen &randgen)
{
  Mpz n0, n1, f0, f1, r, t, tab[4];
  bool ret = true;

  for (size_t n0bits = 1; n0bits < 1280; n0bits+=50)
  {
    for (size_t n1bits = 1; n1bits < 1280; n1bits+=50)
    {
      for (size_t niter = 0; niter < 10; niter++)
      {
        do
        {
          n0 = randgen.random_mpz_2exp (n0bits);
          n1 = randgen.random_mpz_2exp (n1bits);
        } while (n0.is_zero() && n1.is_zero());

        JSF jsf (n0, n1);

        f0 = randgen.random_mpz_2exp (10);
        f1 = randgen.random_mpz_2exp (20);

        tab[0] = f0;
        tab[1] = f1;
        Mpz::add (tab[2], f0, f1);
        Mpz::sub (tab[3], f0, f1);

        /* init r */
        uint8_t most_significant = jsf[jsf.size()-1];
        if (most_significant == 0x01)
          r = tab[0];
        else if (most_significant == 0x10)
          r = tab[1];
        else if (most_significant == 0x11)
          r = tab[2];

        /* main loop (skipping first nonzero digit) */
        for (size_t j = jsf.size()-1; j > 0; j--)
        {
          uint8_t d = jsf[j-1];

          Mpz::mulby2 (r, r);
          if (d == 0x01) /* f0 */
            Mpz::add (r, r, tab[0]);
          else if (d == 0x03) /* f0^-1 */
            Mpz::sub (r, r, tab[0]);
          else if (d == 0x10) /* f1 */
            Mpz::add (r, r, tab[1]);
          else if (d == 0x30) /* f1^-1 */
            Mpz::sub (r, r, tab[1]);
          else if (d == 0x11) /* f0 * f1 */
            Mpz::add (r, r, tab[2]);
          else if (d == 0x13) /* f0^-1 * f1 */
            Mpz::sub (r, r, tab[3]);
          else if (d == 0x31) /* f0 * f1^-1 */
            Mpz::add (r, r, tab[3]);
          else if (d == 0x33) /* f0^-1 * f1^-1 */
            Mpz::sub (r, r, tab[2]);
        }

        Mpz::mul (t, f0, n0);
        Mpz::addmul (t, f1, n1);
        ret &= r == t;
      }
    }
  }

  return ret;
}

bool
test_assignment_from_bignum (RandGen &randgen)
{
  bool ret = true;

  Mpz v;

  BIGNUM *bn = BN_new();
  if (bn == NULL)
    throw std::runtime_error ("could not allocate OpenSSL BIGNUM");

  for (int n = 10; n < 500; n+=3)
  {
    for (int i = 0; i < 25; i++)
    {
      BN_pseudo_rand (bn, n, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
      if (randgen.random_bool ())
        BN_set_negative (bn, 1);

      v = bn;
      char *bn_str = BN_bn2dec (bn);
      char *v_str = mpz_get_str (NULL, 10, v);

      ret &= strcmp (bn_str, v_str) == 0;

      OPENSSL_free (bn_str);
      free (v_str);
    }
  }

  BN_free (bn);

  return ret;
}

bool
test_convert_to_bignum (RandGen &randgen)
{
  bool ret = true;

  for (int n = 10; n < 500; n+=3)
  {
    for (int i = 0; i < 25; i++)
    {
      Mpz v (randgen.random_mpz_2exp (n));
      if (randgen.random_bool ())
        v.neg ();

      BIGNUM *bn = v;

      char *bn_str = BN_bn2dec (bn);
      char *v_str = mpz_get_str (NULL, 10, v);

      ret &= strcmp (bn_str, v_str) == 0;

      OPENSSL_free (bn_str);
      BN_free (bn);
      free (v_str);
    }
  }

  return ret;
}

int
main (int argc, char *argv[])
{
  bool success = true;

  RandGen randgen;
  randseed_from_argv (randgen, argc, argv);

  #define RUN_TEST_AND_PRINT_RESULT_LINE(test_fct, ...) do {  \
      bool ret = test_fct (__VA_ARGS__);                      \
      Test::result_line (#test_fct, ret);                     \
      success &= ret;                                         \
    } while (0)

  RUN_TEST_AND_PRINT_RESULT_LINE (test_mpz_extract_bits, randgen);
  RUN_TEST_AND_PRINT_RESULT_LINE (test_mpz_random_prime, randgen);
  RUN_TEST_AND_PRINT_RESULT_LINE (test_mpz_sqrt_mod_prime, randgen);
  RUN_TEST_AND_PRINT_RESULT_LINE (test_mpz_partial_euclid_scratch, randgen);
  RUN_TEST_AND_PRINT_RESULT_LINE (test_JSF, randgen);
  RUN_TEST_AND_PRINT_RESULT_LINE (test_assignment_from_bignum, randgen);
  RUN_TEST_AND_PRINT_RESULT_LINE (test_convert_to_bignum, randgen);

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
