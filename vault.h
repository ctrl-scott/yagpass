#ifndef YAGPASS_VAULT_H
#define YAGPASS_VAULT_H

#include <stddef.h>

#define YAG_MAGIC "YAG1"
#define YAG_VERSION 1

typedef struct {
    char *login;
    char *password;
    char *url;
    char *notes;
} YAG_Entry;

typedef struct {
    YAG_Entry *items;
    size_t count;
    size_t cap;
    int dirty; // unsaved changes
} YAG_Vault;

int  yag_vault_init(YAG_Vault *v);
void yag_vault_free(YAG_Vault *v);
int  yag_vault_add(YAG_Vault *v, const char *login, const char *password,
                   const char *url, const char *notes);
void yag_vault_list(const YAG_Vault *v);
int  yag_vault_search(const YAG_Vault *v, const char *q); // returns matches printed; returns count
void yag_vault_show(const YAG_Vault *v, size_t idx);

// Load/save using master password; file extension recommended: .yag
int  yag_vault_load(YAG_Vault *v, const char *path, const char *master_pw);
int  yag_vault_save(const YAG_Vault *v, const char *path, const char *master_pw);

#endif
