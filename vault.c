#include "vault.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct __attribute__((packed)) {
    char magic[4];  // "YAG1"
    uint8_t version;
    uint8_t reserved[3];
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
} YAG_FileHeader;

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) { fprintf(stderr, "Out of memory\n"); exit(2); }
    return p;
}
static char *xstrdup(const char *s) {
    size_t n = strlen(s);
    char *p = (char*)xmalloc(n+1);
    memcpy(p, s, n+1);
    return p;
}

int yag_vault_init(YAG_Vault *v) {
    v->items=NULL; v->count=0; v->cap=0; v->dirty=0;
    return 0;
}

static void free_entry(YAG_Entry *e) {
    if (!e) return;
    if (e->login)    { sodium_memzero(e->login,    strlen(e->login));    free(e->login); }
    if (e->password) { sodium_memzero(e->password, strlen(e->password)); free(e->password); }
    if (e->url)      { free(e->url); }
    if (e->notes)    { free(e->notes); }
    memset(e,0,sizeof(*e));
}

void yag_vault_free(YAG_Vault *v) {
    if (!v || !v->items) return;
    for (size_t i=0;i<v->count;i++) free_entry(&v->items[i]);
    free(v->items);
    v->items=NULL; v->count=0; v->cap=0; v->dirty=0;
}

int yag_vault_add(YAG_Vault *v, const char *login, const char *password,
                  const char *url, const char *notes) {
    if (v->count==v->cap) {
        size_t ncap = v->cap? v->cap*2 : 8;
        YAG_Entry *ni = (YAG_Entry*)realloc(v->items, ncap*sizeof(YAG_Entry));
        if (!ni) return -1;
        v->items=ni; v->cap=ncap;
    }
    YAG_Entry *e = &v->items[v->count++];
    e->login    = login? xstrdup(login): xstrdup("");
    e->password = password? xstrdup(password): xstrdup("");
    e->url      = url? xstrdup(url): xstrdup("");
    e->notes    = notes? xstrdup(notes): xstrdup("");
    v->dirty=1;
    return 0;
}

void yag_vault_list(const YAG_Vault *v) {
    if (!v->count) { printf("[empty]\n"); return; }
    for (size_t i=0;i<v->count;i++) {
        printf("%zu) %s  <%s>\n", i, v->items[i].login, v->items[i].url);
    }
}

int yag_vault_search(const YAG_Vault *v, const char *q) {
    int matches=0;
    for (size_t i=0;i<v->count;i++) {
        const YAG_Entry *e=&v->items[i];
        if ((strstr(e->login,q)) || (strstr(e->url,q)) || (strstr(e->notes,q))) {
            printf("%zu) %s  <%s>\n", i, e->login, e->url);
            matches++;
        }
    }
    if (!matches) printf("No matches.\n");
    return matches;
}

void yag_vault_show(const YAG_Vault *v, size_t idx) {
    if (idx>=v->count) { printf("Index out of range.\n"); return; }
    const YAG_Entry *e=&v->items[idx];
    printf("Login   : %s\n", e->login);
    printf("Password: %s\n", e->password);
    printf("URL     : %s\n", e->url);
    printf("Notes   : %s\n", e->notes);
}

/* --------- Serialization (plaintext before encryption) ----------

Plaintext layout (little-endian):
uint32_t count
repeat count times:
  uint32_t len_login   + bytes
  uint32_t len_password+ bytes
  uint32_t len_url     + bytes
  uint32_t len_notes   + bytes

------------------------------------------------------------------ */

static void put_u32(uint8_t **p, uint32_t x) {
    (*p)[0]=(uint8_t)(x); (*p)[1]=(uint8_t)(x>>8);
    (*p)[2]=(uint8_t)(x>>16); (*p)[3]=(uint8_t)(x>>24);
    *p+=4;
}
static uint32_t get_u32(const uint8_t **p, const uint8_t *end, int *ok) {
    if ((size_t)(end-*p) < 4) { *ok=0; return 0; }
    uint32_t x = (uint32_t)(*p)[0] | ((uint32_t)(*p)[1]<<8) | ((uint32_t)(*p)[2]<<16) | ((uint32_t)(*p)[3]<<24);
    *p += 4; return x;
}

static int serialize_plain(const YAG_Vault *v, uint8_t **out, size_t *out_len) {
    size_t total = 4; // count
    for (size_t i=0;i<v->count;i++) {
        const YAG_Entry *e=&v->items[i];
        total += 4+strlen(e->login) + 4+strlen(e->password) + 4+strlen(e->url) + 4+strlen(e->notes);
    }
    uint8_t *buf=(uint8_t*)xmalloc(total);
    uint8_t *p=buf;
    put_u32(&p,(uint32_t)v->count);
    for (size_t i=0;i<v->count;i++) {
        const YAG_Entry *e=&v->items[i];
        uint32_t L;
        L=(uint32_t)strlen(e->login);    put_u32(&p,L); memcpy(p,e->login,L);       p+=L;
        L=(uint32_t)strlen(e->password); put_u32(&p,L); memcpy(p,e->password,L);    p+=L;
        L=(uint32_t)strlen(e->url);      put_u32(&p,L); memcpy(p,e->url,L);         p+=L;
        L=(uint32_t)strlen(e->notes);    put_u32(&p,L); memcpy(p,e->notes,L);       p+=L;
    }
    *out=buf; *out_len=total;
    return 0;
}

static int deserialize_plain(YAG_Vault *v, const uint8_t *buf, size_t len) {
    const uint8_t *p=buf, *end=buf+len;
    int ok=1;
    uint32_t cnt=get_u32(&p,end,&ok);
    if(!ok) return -1;
    yag_vault_free(v);
    yag_vault_init(v);
    for (uint32_t i=0;i<cnt;i++) {
        uint32_t L;
        L=get_u32(&p,end,&ok); if(!ok || (size_t)(end-p)<L) return -1;
        char *login=(char*)xmalloc(L+1); memcpy(login,p,L); login[L]='\0'; p+=L;

        L=get_u32(&p,end,&ok); if(!ok || (size_t)(end-p)<L) { free(login); return -1; }
        char *password=(char*)xmalloc(L+1); memcpy(password,p,L); password[L]='\0'; p+=L;

        L=get_u32(&p,end,&ok); if(!ok || (size_t)(end-p)<L) { free(login); free(password); return -1; }
        char *url=(char*)xmalloc(L+1); memcpy(url,p,L); url[L]='\0'; p+=L;

        L=get_u32(&p,end,&ok); if(!ok || (size_t)(end-p)<L) { free(login); free(password); free(url); return -1; }
        char *notes=(char*)xmalloc(L+1); memcpy(notes,p,L); notes[L]='\0'; p+=L;

        yag_vault_add(v, login, password, url, notes);
        free(login); free(password); free(url); free(notes); // yag_vault_add duplicates them
    }
    v->dirty=0;
    return 0;
}

/* ------------------------ Crypto helpers ----------------------- */

static int derive_key(unsigned char key[crypto_secretbox_KEYBYTES],
                      const char *pw, const unsigned char salt[crypto_pwhash_SALTBYTES]) {
    return crypto_pwhash(key, crypto_secretbox_KEYBYTES,
                         pw, strlen(pw), salt,
                         crypto_pwhash_OPSLIMIT_SENSITIVE,
                         crypto_pwhash_MEMLIMIT_SENSITIVE,
                         crypto_pwhash_ALG_ARGON2ID13);
}

int yag_vault_save(const YAG_Vault *v, const char *path, const char *master_pw) {
    if (!v) return -1;
    uint8_t *plain=NULL; size_t plain_len=0;
    if (serialize_plain(v, &plain, &plain_len)!=0) return -1;

    YAG_FileHeader hdr;
    memcpy(hdr.magic, YAG_MAGIC, 4);
    hdr.version = YAG_VERSION;
    memset(hdr.reserved, 0, sizeof(hdr.reserved));
    randombytes_buf(hdr.salt, sizeof(hdr.salt));
    randombytes_buf(hdr.nonce, sizeof(hdr.nonce));

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (derive_key(key, master_pw, hdr.salt)!=0) { sodium_memzero(plain, plain_len); free(plain); return -1; }

    size_t ciph_len = plain_len + crypto_secretbox_MACBYTES;
    uint8_t *ciph = (uint8_t*)xmalloc(ciph_len);
    if (crypto_secretbox_easy(ciph, plain, (unsigned long long)plain_len, hdr.nonce, key) != 0) {
        sodium_memzero(key,sizeof(key)); sodium_memzero(plain,plain_len); free(plain); free(ciph); return -1;
    }

    FILE *f=fopen(path,"wb");
    if (!f) { perror("fopen"); sodium_memzero(key,sizeof(key)); sodium_memzero(plain,plain_len); free(plain); free(ciph); return -1; }
    if (fwrite(&hdr, sizeof(hdr), 1, f)!=1) { perror("fwrite hdr"); fclose(f); goto FAIL; }
    if (fwrite(ciph, 1, ciph_len, f)!=ciph_len) { perror("fwrite data"); fclose(f); goto FAIL; }
    fclose(f);

    // Cleanup
    sodium_memzero(key,sizeof(key));
    sodium_memzero(plain,plain_len);
    free(plain); free(ciph);
    return 0;

FAIL:
    sodium_memzero(key,sizeof(key));
    sodium_memzero(plain,plain_len);
    free(plain); free(ciph);
    return -1;
}

int yag_vault_load(YAG_Vault *v, const char *path, const char *master_pw) {
    FILE *f=fopen(path,"rb");
    if (!f) return -2; // file does not exist
    YAG_FileHeader hdr;
    if (fread(&hdr, sizeof(hdr), 1, f)!=1) { fclose(f); return -1; }
    if (memcmp(hdr.magic, YAG_MAGIC, 4)!=0 || hdr.version!=YAG_VERSION) { fclose(f); return -1; }

    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, sizeof(hdr), SEEK_SET);
    size_t ciph_len = (size_t)(flen - (long)sizeof(hdr));
    if ((long)ciph_len <= 0) { fclose(f); return -1; }

    uint8_t *ciph=(uint8_t*)xmalloc(ciph_len);
    if (fread(ciph,1,ciph_len,f)!=ciph_len) { free(ciph); fclose(f); return -1; }
    fclose(f);

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (derive_key(key, master_pw, hdr.salt)!=0) { free(ciph); return -1; }

    if (ciph_len < crypto_secretbox_MACBYTES) { sodium_memzero(key,sizeof(key)); free(ciph); return -1; }
    size_t plain_len = ciph_len - crypto_secretbox_MACBYTES;
    uint8_t *plain=(uint8_t*)xmalloc(plain_len);

    if (crypto_secretbox_open_easy(plain, ciph, (unsigned long long)ciph_len, hdr.nonce, key) != 0) {
        // wrong password or corrupted file
        sodium_memzero(key,sizeof(key)); free(ciph); free(plain); return -3;
    }

    int rc = deserialize_plain(v, plain, plain_len);
    sodium_memzero(key,sizeof(key));
    sodium_memzero(plain, plain_len);
    free(ciph); free(plain);
    return rc;
}
