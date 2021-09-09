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
| 2 bytes LE prefix padding length P | P-2 bytes prefix random padding | 2 bytes LE secret length L | L bytes secrets | tail random paddings |
```

1. Use `hash(user-password)` as the key to descrypt `EM` to `M`.
2. Use `M` as the key to descrpyt `EB` to `B`
3. read `B[0]` and `B[1]` as a LE `unsigned short`, which is the prefix padding length.
3. after the prefix padding, decode a length-prefix binary as a 2 byte LE unsigned short followed by the real secret.
