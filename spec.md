# Adept Secret Sharing (ADSS)

Adept Secret Sharing (ADSS) is a [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) construction based on a [2020 paper by Bellare, Dai, and Rogaway](https://eprint.iacr.org/2020/800) along with a [2010 draft RFC by McGrew, Patnala, and Hoenes](https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03).

The goal of ADSS is to provide a simple and safe secret sharing interface. You have some highly sensitive data and want to divide it across multiple parties such that they can later cooperate and recover it. You might need all of them or some subset of them to complete the recovery. ADSS is *not* intended as a low-level primitive for use building larger MPC protocols because it (intentionally) is not additively homomorphic.

## Introduction

Securely sharing a secret value amongst multiple parties such that only a sufficiently large subset can reconstruct the secret is an uncommon, but critical, need in high security systems.
While there are several de-facto standards, none are clearly documented and people generally roll-their-own because the fundamentals of Shamir Secret Sharing are simple enough that they can. This does not result in a healthy ecosystem with secure interoperable tools.

ADSS targets the *simplest* cases. You have a secret and want to threshold share it.
No fancier access control structures or logic.

### Security Properties

**TO WRITE**

## Notation and Terms

We use the term "byte" to refer to an 8-bit value (sometimes called an "octet"). We use the term "bytestring" to refer to an ordered sequence of bytes. We assume that an underlying hash function implementation handles bit ordering when hashing bytes and bytestrings.

We will use `||` to concatenate bytes, bytestrings, and values.
We will implicitly `ENCODE` and `DECODE` when necessary and obvious.

We use `^` to represent a bitwise xor operation.
In an expression `a ^ b`, the lengths of `a` and `b` MUST be identical.

In some of the examples, we will place notes or comments next to inputs and pseudocode. These will be marked with the comment indicator `#`, which continues to the end of the line.

We use the terms MUST and MUST NOT to indicate that an implementation cannot be considered compliant with the specification if the condition described is not met.

We use the terms SHOULD and SHOULD NOT to describe behaviors that are considered best practice. An implementation that deviates from SHOULD/SHOULD NOT guidance can still be compliant, but implementers are strongly encouraged to clearly document such deviations from SHOULD/SHOULD NOT guidance. For instance, implementations SHOULD zeroize key material when no longer needed (though the determination of how long key material may be needed is left to implementers).

We use the term MAY to indicate optional behavior that is not required for compliance with the specification, but that implementers can include at their own discretion without compromising specification compliance. For example, implementations MAY emit warnings or raise errors when known-weak hash functions are used. Implementers are encouraged to document such decisions.

Some of the math is done relative to GF(256) (also just called GF256), the finite field with exactly 256 elements.
GF(256) addition is notated as `(+)`. GF(256) multiplication is notated as `(*)`. GF(256) division is written as a fraction.

*All* values in this specification are unsigned.

All data types have an associated `ENCODE` and `DECODE` function.
For bytes and bytestrings, this is the identity function (and so is just the raw bytes).
For integers it is an unsigned 32-bit (4-byte) bigendian encoding.
For all other types it is explicitly defined and the `DECODE` function MUST reject invalid input.

## Support functions and general requirements

### len

`len(x)` returns the length, in bytes of the bytestring `x`.

### Hashing / PRFs / XOFs

We define the following domain separation constants (ASCII, non-null terminated)

- S1_XOF_DOMAIN_SEP: `C2SP/ADSS/S1/XOF:`
- AX_HASH_DOMAIN_SEP: `C2SP/ADSS/AX/HASH:`
- AX_PRF_DOMAIN_SEP: `C2SP/ADSS/AX/PRF:`
- AX_CPRF_DOMAIN_SEP: `C:`
- AX_DPRF_DOMAIN_SEP: `D:`

#### SHAKE256

We use SHAKE256 for all internal hashing, PRFs, XOFs, and Random Oracles.

#### HashItem

`HashItem(h, item)` takes in an instance of `SHAKE2566` and hashes in a length-prefixed version of `item` where `item` is a bytestring.

```
HashItem(h, item):
    h.update(len(item))
    h.update(item)
```

**SHAKE256 is never updated directly and is only ever updated via `HashItem`**

#### axHash

`axHash(array)` takes in an array of bytestrings and returns the 128-**byte** result.

```
axHash(array):
    hash = SHAKE256
    HashItem(hash, AX_HASH_DOMAIN_SEP)
    for i in array:
      HashItem(hash, i)
    return hash.xof(256) // Return 256 bytes of output
```

#### ax_dprf

`ax_dprf` is a PRF (keyed hash function) which produces 32 bytes of output.

```
ax_dprf(key):
    prf = SHAKE256
    HashItem(prf, AX_PRF_DOMAIN_SEP)
    HashItem(prf, key)
    HashItem(prf, AX_DPRF_DOMAIN_SEP)
    return hash.xof(32) // Return 32 bytes of output
```
return hash.xof(256)

#### s1_xof

`s1_xof` returns an XOF which can be used to produce arbitrarily long sequences of pseudo-random data.

```
s1_xof(coins):
    xof = SHAKE256
    HashItem(xof, S1_XOF_DOMAIN_SEP)
    HashItem(xof, coins)
    return xof
```

### GF(256)

Building the **SS** primitive requires math over the finite field GF(256).

### Constant time functions

Implementing ADSS requires constant-time equality checks over bytestrings (`ct_eq(x,y)`) and may require `ct_and(x,y)`, `ct_or(x,y)`, or `ct_lookup(idx, array[])`. `ct_and` and `ct_or` are the obvious logical `and` and `or` operators (not bitwise). `ct_lookup(idx, array[])` is equivalent to `array[idx]` but operates in constant-time. `ct_zero(x)` returns whether `x` is equal to zero. 

### Data Types

#### GF(256) Elements

Elements of GF(256) are encoded as a single byte in the trivial way and represented as a single hex byte in documentation.
All byte values are valid elements (and vice-versa).
The additive identity is `0x00` and the the multiplicative identity is `0x01`.

#### CompactShare

A `CompactShare` contains the information unique to each party and has three parts:
- A one byte `id` which MUST NOT be equal to `0`
- A 32-byte bytestring `secret_part`

The `ENCODE` operation for `CompactShare` is the 33-byte bytestring starting with `0x01` followed by `id` and `secret_part`. (e.g., `0x01 || id || secret_part`)

`DECODE` MUST reject a byte string of the wrong length, not starting with `0x01` or with an invalid `id` value.

**Example:** `ENCODE(CompactShare{id: 5, secret_part: 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f})` => `0x0105000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`

#### AccessStructure / ThresholdAccess

An `AccessStructure` defines the rules around which parties are able to recover a given secret.
Currently, the only defined `AccessStructure` is `ThresholdAccess` which defines an m-of-n mode.
That is, a secret is split across `n` different parties and any `m` of them are able to recover it.

`ThresholdAccess` has two one byte values:
- `threshold` (the number of parties needed to recover a secret. Must be non-zero.)
- `total` (the total number of parties the secret was shared to. Must be greater than or equal to `threshold`)

`ENCODE` for `ThresholdAccess` simply outputs a two-byte bytestring consisting of `threshold` followed by `total`. (e.g., `threshold || total`)

`DECODE` for `ThresholdAccess` is the obvious inverse but MUST reject values where:
- The bytestring is not 2 bytes long
- `threshold` is `0`
- `total < threshold`

#### CommonInfo

A `CommonInfo` contains the information which is common across all parties for a given secret share.
It has three elements:

- `access_structure` (of type `AccessStructure`)
- `public_part` (bytestring)
- `aad` (bytestring)

`ENCODE = 0x02 || access_structure || len(public_part) || public_part || len(aad) || aad`

#### ExpandedShare

An expanded share contains all of the information from both `CompactShare` and `CommonInfo`.
This is usually the better way for parties to save their shares as it ensures that a threshold of parties *always* has all needed information to actually recover the secret.

It has two elements:
- `share` (`CompactShare`)
- `common` (`CommonInfo`)

`ENCODE = 0x03 || share || common`

#### RecoveryInput

`RecoveryInput` is all information needed to actually recover a secret and is the input to the `recover` method.

It has two elements:

- `shares[]` (an array of `CompactShare`)
- `common` (`CommonInfo`)

There is no need for these structure to be serialized or deserialized and so `ENCODE` / `DECODE` is not defined for it.

`RecoveryInput` may be split into `CompactShares` and a `CommonInfo` in the trivial way.

`RecoveryInput` may be split into `ExpandedShares` in the trivial way (by duplicating `CommonInfo` across all of them)

`RecoveryInput` may be created from one or more `CompactShares`and a `CommonInfo` in the obvious way but the implementation MUST fail if:
- Any share Ids are duplicated or invalid
- Any share Ids are greater than `CommonInfo.access_structure.total`

`RecoveryInput` may be created from one or more `ExpandedShares` in the obvious way but the implementation MUST fail if:
- Any shares have different `common` values
- Any share Ids are duplicated or invalid
- Any share Ids are greater than `CommonInfo.access_structure.total`

### GF(256)

All finite-field math and encodings is *exactly that* describe in the [2010 draft RFC by McGrew, Patnala, and Hoenes](https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03).
Portions are duplicated here completeness.

All GF operations MUST be constant-time.

Addition `(+)` is a bitwise xor of two elements.

Multiplication and division use the `GF_LOG` and `GF_EXP` arrays defined later.

Multiplication `(*)` is defined as:
```
GF_MULT(x, y):
   is_zero = ct_or(ct_zero(x), ct_zero(y))
   idx = (ct_lookup(x, GF_LOG) + ct_lookup(y, GF_LOG)) % 255
   result = ct_lookup(idx, GF_EXP)
   return ct_select(is_zero, 0, result)
```

Division:
```
GF_DIV(x, y):
   is_zero = ct_or(ct_zero(x), ct_zero(y))
   idx = (ct_lookup(x, GF_LOG) - ct_lookup(y, GF_LOG)) % 255
   result = ct_lookup(idx, GF_EXP)
   return ct_select(is_zero, 0, result)
```

`GF_SUM()

`GF_EXP` is a tables of 256 GF(256) elements. Technically the last element (at index 255) is unused.
```
0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x00
```

`GF_LOG` is a table of 256 integers. Technically the first entry at index 0 is unused.

```
0,      0,   25,    1,   50,    2,   26,  198,
75,   199,   27,  104,   51,  238,  223,    3,
100,    4,  224,   14,   52,  141,  129,  239,
76,   113,    8,  200,  248,  105,   28,  193,
125,  194,   29,  181,  249,  185,   39,  106,
77,   228,  166,  114,  154,  201,    9,  120,
101,   47,  138,    5,   33,   15,  225,   36,
18,   240,  130,   69,   53,  147,  218,  142,
150,  143,  219,  189,   54,  208,  206,  148,
19,    92,  210,  241,   64,   70,  131,   56,
102,  221,  253,   48,  191,    6,  139,   98,
179,   37,  226,  152,   34,  136,  145,   16,
126,  110,   72,  195,  163,  182,   30,   66,
58,   107,   40,   84,  250,  133,   61,  186,
43,   121,   10,   21,  155,  159,   94,  202,
78,   212,  172,  229,  243,  115,  167,   87,
175,   88,  168,   80,  244,  234,  214,  116,
79,   174,  233,  213,  231,  230,  173,  232,
44,   215,  117,  122,  235,   22,   11,  245,
89,   203,   95,  176,  156,  169,   81,  160,
127,   12,  246,  111,   23,  196,   73,  236,
216,   67,   31,   45,  164,  118,  123,  183,
204,  187,   62,   90,  251,   96,  177,  134,
59,    82,  161,  108,  170,   85,   41,  157,
151,  178,  135,  144,   97,  190,  220,  252,
188,  149,  207,  205,   55,   63,   91,  209,
83,    57,  132,   60,   65,  162,  109,   71,
20,    42,  158,   93,   86,  242,  211,  171,
68,    17,  146,  217,   35,   32,   46,  137,
180,  124,  184,   38,  119,  153,  227,  165,
103,   74,  237,  222,  197,   49,  254,   24,
13,    99,  140,  128,  192,  247,  112,    7
```

## TODOs

- [ ] Security Properties
- [ ] Limitations
  - Computationally secure (256 bits of security), but not information theoretically secure
  - Not additively homomorphic
- [ ] Serialization