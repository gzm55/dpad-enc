# double padding encryption format

Before encryption, prepend and append random bytes padding to the original secret.

# Encrypt multiple secrets

A PoC of merging different secrets together with different passwords into a single file. Each can be decrypted via its own password.

# Build

After cloning, edit `build.sh`, change the location of `libsodium`, then run `build.sh` to generate the executable `dpad`.

# Usage

```bash
Usage:
    dpad [-h]
        Print this help.

    dpad -e <out-file> <password> <secret> [password secret ...]
        Encrypt secrets with the corresponding passwords, write to <out-file>.

    dpad -d <in-file> <password>
        Decrypt the secret from <in-file> with the <password>.

```

# Example

```
$ ./dpad -e test.bin pwdAAA secretAAA pwdBBB secretBBB pwdCCC secretCCC

$ ls test.bin
test.bin

$ ./dpad -d test.bin pwdCCC
secretCCC

$ ./dpad -d test.bin pwdAAA
secretAAA

$ ./dpad -d test.bin fake
_Sf3}ڭuEo,hu>HZqD:ojO5?37CB?T6h@
```

# Format and Descrypt

```
RAW FILE FORMAT:
| 32 bytes encrypted master entropy EM | encrypt body (default 2048 bytes) EB |

PADDING BODY FORMAT:
| P (prefix padding length) bytes prefix random padding | 2 bytes LE secret length L | L bytes secrets | tail random paddings |
```

1. Use first 32 bytes of `H = hash(user-password, salt)` as the key to decrypt `EM` to `ML`.
2. read the prefix padding length `P` from first two bytes of `ML`, as LE endian order, `P = ML[0] || ML[1]`
3. get final `M = (ML[0] xor H[32]) || (ML[1] xor H[33]) || ML[2:31]`
4. Use `M` as the key to descrpyt `EB` to `B`
5. after the prefix padding, decode a length-prefix binary as a 2 byte LE unsigned short followed by the real secret.
