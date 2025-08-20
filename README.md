# yagpass
Password generator and manager CLI - based in C - coded alongside ChatGPT - in CLion Community Edition - here is the ChatGPT link: 
url: [ChatGPT Link 08-20-2025](https://chatgpt.com/share/68a528d8-503c-800c-9efa-bcf311df8ff9)

After reading through the material, it is important to note that structures, types, and other information presented in this context does not translate clearly in every corner of the world. When working with other people make sure the information is clearly defined and the context is clearly stated.

## Glossary and Appendices
Here you go—an easy-to-skim **Glossary** plus **Appendices** that document the key terms, operations, syntax, and structural elements used in the project.

# Glossary

**Argon2id**
A memory-hard password hashing algorithm used to derive a symmetric key from the master password. Resistant to GPU/ASIC cracking.

**Ciphertext**
The encrypted bytes written to the `.yag` file after sealing the plaintext vault.

**Fisher–Yates shuffle**
An unbiased shuffle used to randomize character order in generated passwords.

**KDF (Key Derivation Function)**
Transforms a password into a fixed-size cryptographic key. Here: `crypto_pwhash_*` (Argon2id) in libsodium.

**libsodium**
A modern, high-level cryptography library providing secure primitives (randomness, AEAD/secretbox, KDF, etc.).

**Master password**
User-supplied secret from which the vault’s encryption key is derived. Never stored.

**Nonce**
A unique, single-use value required by the cipher to ensure semantic security. Stored in the vault header.

**Randombytes / `randombytes_uniform()`**
Cryptographically secure RNG from libsodium. `uniform` avoids modulo bias.

**Salt**
Random value stored with the file to make password-derived keys unique per vault (prevents rainbow-table reuse).

**Secretbox (XChaCha20-Poly1305)**
Authenticated encryption construction used here via `crypto_secretbox_easy()`.

**Unbiased selection**
Character picking using `randombytes_uniform()` (not `%`) to prevent statistical bias.

**Vault**
In-memory list of entries `{login, password, url, notes}`; serialized, then encrypted to disk as `.yag`.

---

# Appendix A — Cryptographic Operations

1. **Key derivation (KDF)**

   * Function: `crypto_pwhash`
   * Algorithm: Argon2id (v13)
   * Parameters: `OPSLIMIT_SENSITIVE`, `MEMLIMIT_SENSITIVE`
   * Inputs: master password, 16-byte `salt`
   * Output: 32-byte `key` (`crypto_secretbox_KEYBYTES`)

2. **Encryption**

   * Primitive: `crypto_secretbox_easy`
   * Cipher: XChaCha20-Poly1305
   * Inputs: plaintext vault blob, 24-byte `nonce`, 32-byte `key`
   * Output: `ciphertext = MAC(16B) + encrypted bytes`

3. **Decryption**

   * Primitive: `crypto_secretbox_open_easy`
   * Fails if MAC invalid or wrong key/password.

4. **Randomness**

   * `randombytes_buf()` for salt and nonce
   * `randombytes_uniform(n)` for unbiased index selection in password generation and shuffling

---

# Appendix B — File Format: `.yag` (On-Disk)

**Header (fixed-size, packed):**

```
offset  size  field
0       4     magic = "YAG1"
4       1     version = 1
5       3     reserved (zeros)
8       16    salt (crypto_pwhash_SALTBYTES)
24      24    nonce (crypto_secretbox_NONCEBYTES)
48      ...   ciphertext (MAC + encrypted plaintext vault)
```

**Plaintext vault (before encryption):**

```
uint32  count
repeat count times:
  uint32 len_login    | bytes (login)
  uint32 len_password | bytes (password)
  uint32 len_url      | bytes (url)
  uint32 len_notes    | bytes (notes)
```

Notes:

* Endianness: little-endian 32-bit lengths.
* Entire plaintext segment is encrypted as one blob.
* No plaintext metadata beyond the header.

---

# Appendix C — Data Structures (In-Memory)

```c
typedef struct {
    char *login;
    char *password;
    char *url;
    char *notes;
} YAG_Entry;

typedef struct {
    YAG_Entry *items;  // dynamic array
    size_t     count;  // number of entries
    size_t     cap;    // allocated capacity
    int        dirty;  // unsaved changes
} YAG_Vault;
```

**Passgen options:**

```c
typedef struct {
    size_t length;
    bool use_lower;
    bool use_upper;
    bool use_digits;
    bool use_symbols;
    bool exclude_ambiguous;
} PG_Options;
```

---

# Appendix D — Menu Flow (Runtime)

1. **Startup**

   * Prompt for vault path.
   * Prompt for master password (hidden input).
   * Try `yag_vault_load()`:

     * If file absent → “new vault” in memory.
     * If present → derive key and decrypt; fail if wrong password/corrupted.

2. **Menu Options**

   1. **Add entry** → capture fields; optional autogenerate password → `yag_vault_add()`.
   2. **List entries** → index + summary.
   3. **Search** → substring match on login/url/notes.
   4. **Show entry** → print full entry by index.
   5. **Save vault** → `yag_vault_save()` (serialize → encrypt → write).
   6. **Generate password** → on-demand `pg_generate()` with user length.
   7. **Exit** → prompt to save if `dirty`.

3. **Shutdown**

   * Zeroize sensitive buffers (master password, generated password).
   * Free vault entries.

---

# Appendix E — Command-Line & UI Conventions

**Generator flags (standalone `yagpass_sodium`):**

* `-l <N>`: length (4–4096)
* `-U`: exclude uppercase
* `-L`: exclude lowercase
* `-D`: exclude digits
* `-S`: exclude symbols
* `-A`: exclude ambiguous (`0 O o 1 l I`)
* `-h`: help

**Vault UI prompts (interactive):**

* `Login/username`
* `URL/label`
* `Notes`
* `Password` (hidden input; blank → autogenerate)

---

# Appendix F — Memory Handling & Safety Patterns

* **Zeroization**

  * `sodium_memzero(buf, len)` for sensitive data (passwords, keys, plaintext buffers).
* **Allocation**

  * `xmalloc`/`xstrdup` wrappers to fail-fast; check `realloc` return.
* **Bounds & Types**

  * All serialized lengths are `uint32_t`; verify buffer space before copying.
* **Error Codes**

  * `yag_vault_load()` may return:

    * `-2` → file missing (new vault)
    * `-3` → bad password or corrupted data
    * other negative → parsing or I/O error
* **I/O**

  * Binary `fopen("wb")`/`fopen("rb")`; check `fwrite`/`fread` sizes.
* **Portability**

  * Packed header with fixed field sizes; avoid platform-dependent padding.
* **Permissions**

  * Encourage `chmod 600 <vault>.yag` by the user.

---

# Appendix G — libsodium API Calls (Syntax Quick-Ref)

```c
// Initialize library
if (sodium_init() < 0) { /* fail */ }

// Random
randombytes_buf(void *buf, size_t size);
uint32_t randombytes_uniform(uint32_t upper_bound);

// KDF (Argon2id)
int crypto_pwhash(unsigned char *out, unsigned long long outlen,
                  const char *passwd, unsigned long long passwdlen,
                  const unsigned char salt[crypto_pwhash_SALTBYTES],
                  unsigned long long opslimit, size_t memlimit, int alg);

// Secretbox (XChaCha20-Poly1305)
int crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
                          unsigned long long mlen, const unsigned char *n,
                          const unsigned char *k);

int crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
                               unsigned long long clen, const unsigned char *n,
                               const unsigned char *k);

// Secure wipe
void sodium_memzero(void *pnt, size_t len);
```

Constants to remember:

* `crypto_secretbox_KEYBYTES` = 32
* `crypto_secretbox_NONCEBYTES` = 24
* `crypto_secretbox_MACBYTES` = 16
* `crypto_pwhash_SALTBYTES` = 16
* `crypto_pwhash_ALG_ARGON2ID13`
* `crypto_pwhash_OPSLIMIT_SENSITIVE`, `crypto_pwhash_MEMLIMIT_SENSITIVE`

---

# Appendix H — CMake & Build Structure

**Target definition**

```cmake
add_executable(yagpass
  src/menu.c
  src/vault.c
  src/passgen.c
)
```

**Linking libsodium**

```cmake
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM QUIET libsodium)
endif()

if(SODIUM_FOUND)
  target_include_directories(yagpass PRIVATE ${SODIUM_INCLUDE_DIRS})
  target_link_directories(yagpass PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_link_libraries(yagpass PRIVATE ${SODIUM_LIBRARIES})
else()
  target_link_libraries(yagpass PRIVATE sodium)
endif()
```

**Compiler hygiene**

```cmake
set(CMAKE_C_STANDARD 11)
target_compile_options(yagpass PRIVATE -Wall -Wextra -Wpedantic)
```

---

# Appendix I — Testing & Troubleshooting

* **Duplicate `_main` symbol**
  Ensure only one file defines `main()` (here: `menu.c`). Remove/rename any old `main.c`.

* **Linker errors for `-lsodium`**
  Install dev package (e.g., `libsodium-dev` or `brew install libsodium`) and/or ensure `pkg-config` is installed.

* **Wrong password / corrupted file**
  The program prints a specific message when `crypto_secretbox_open_easy()` fails. Confirm path and master password.

* **Terminal echo for passwords**
  On macOS, `stty -echo` is used to hide input. On other systems, consider integrating `getpass(3)` or a cross-platform approach.




