#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "vault.h"
#include "passgen.h"

static void read_line(const char *prompt, char *buf, size_t n) {
    if (prompt) printf("%s", prompt);
    if (!fgets(buf, (int)n, stdin)) { buf[0]='\0'; return; }
    size_t L=strlen(buf); if (L && buf[L-1]=='\n') buf[L-1]='\0';
}

static char *read_hidden(const char *prompt) {
#ifdef __APPLE__
    // macOS: use "stty -echo" for simple hidden input
    system("/bin/stty -echo");
    printf("%s", prompt);
    fflush(stdout);
    char tmp[4096];
    if (!fgets(tmp, sizeof(tmp), stdin)) tmp[0]='\0';
    size_t L=strlen(tmp); if (L && tmp[L-1]=='\n') tmp[L-1]='\0';
    system("/bin/stty echo");
    printf("\n");
    char *pw=(char*)malloc(L+1);
    strcpy(pw,tmp);
    return pw;
#else
    // Portable fallback (not fully hidden in all terminals)
    char tmp[4096];
    read_line(prompt, tmp, sizeof(tmp));
    char *pw=(char*)malloc(strlen(tmp)+1);
    strcpy(pw,tmp);
    return pw;
#endif
}

static void print_menu(void) {
    printf("\n=== YAG Password Vault ===\n");
    printf("1) Add entry\n");
    printf("2) List entries\n");
    printf("3) Search entries\n");
    printf("4) Show entry (by index)\n");
    printf("5) Save vault\n");
    printf("6) Generate password\n");
    printf("0) Exit\n");
    printf("> ");
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    char path[1024];
    read_line("Vault path (e.g., myvault.yag): ", path, sizeof(path));
    if (!path[0]) { fprintf(stderr,"No path given.\n"); return 1; }

    char *master = read_hidden("Master password: ");
    if (!master) { fprintf(stderr,"No master password.\n"); return 1; }

    YAG_Vault vault; yag_vault_init(&vault);

    int rc = yag_vault_load(&vault, path, master);
    if (rc == -2) {
        printf("No existing vault. Creating new vault at '%s'.\n", path);
    } else if (rc == -3) {
        fprintf(stderr, "Wrong password or corrupted file.\n");
        sodium_memzero(master, strlen(master)); free(master);
        return 1;
    } else if (rc != 0) {
        fprintf(stderr, "Failed to load vault (code %d). Starting empty.\n", rc);
    } else {
        printf("Vault loaded: %zu entries.\n", vault.count);
    }

    for (;;) {
        print_menu();
        char opt[16]; read_line(NULL, opt, sizeof(opt));
        if (strcmp(opt,"1")==0) {
            char login[1024], url[1024], notes[2048], pwd[4096];
            read_line("Login/username: ", login, sizeof(login));
            read_line("URL/label     : ", url,   sizeof(url));
            read_line("Notes         : ", notes, sizeof(notes));
            char *pw = read_hidden("Password (leave empty to auto-generate): ");
            if (!pw || !pw[0]) {
                PG_Options po = { .length=20, .use_lower=true,.use_upper=true,.use_digits=true,.use_symbols=true,.exclude_ambiguous=false };
                char *gen=NULL;
                if (pg_generate(&po, &gen)==0) {
                    strcpy(pwd, gen);
                    sodium_memzero(gen, strlen(gen)); free(gen);
                } else {
                    fprintf(stderr, "Generation failed; leave blank.\n");
                    pwd[0]='\0';
                }
            } else {
                strncpy(pwd, pw, sizeof(pwd)-1); pwd[sizeof(pwd)-1]='\0';
                sodium_memzero(pw, strlen(pw)); free(pw);
            }
            if (yag_vault_add(&vault, login, pwd, url, notes)!=0) {
                fprintf(stderr,"Add failed.\n");
            } else {
                printf("Added.\n");
            }
            sodium_memzero(pwd, strlen(pwd));
        }
        else if (strcmp(opt,"2")==0) {
            yag_vault_list(&vault);
        }
        else if (strcmp(opt,"3")==0) {
            char q[512]; read_line("Search text: ", q, sizeof(q));
            (void)yag_vault_search(&vault, q);
        }
        else if (strcmp(opt,"4")==0) {
            char sidx[32]; read_line("Index: ", sidx, sizeof(sidx));
            size_t idx=(size_t)strtoul(sidx,NULL,10);
            yag_vault_show(&vault, idx);
        }
        else if (strcmp(opt,"5")==0) {
            if (yag_vault_save(&vault, path, master)==0) {
                printf("Saved to %s\n", path);
                vault.dirty=0;
            } else {
                fprintf(stderr,"Save failed.\n");
            }
        }
        else if (strcmp(opt,"6")==0) {
            PG_Options po = { .length=20, .use_lower=true,.use_upper=true,.use_digits=true,.use_symbols=true,.exclude_ambiguous=false };
            char lens[32];
            read_line("Length [default 20]: ", lens, sizeof(lens));
            if (lens[0]) {
                long L=strtol(lens,NULL,10);
                if (L>=4 && L<=4096) po.length=(size_t)L;
            }
            char *pw=NULL;
            if (pg_generate(&po, &pw)==0) {
                printf("Generated: %s\n", pw);
                sodium_memzero(pw, strlen(pw)); free(pw);
            } else {
                fprintf(stderr,"Generation failed.\n");
            }
        }
        else if (strcmp(opt,"0")==0) {
            if (vault.dirty) {
                char yn[8]; read_line("Unsaved changes. Save before exit? [y/N]: ", yn, sizeof(yn));
                if (yn[0]=='y' || yn[0]=='Y') {
                    if (yag_vault_save(&vault, path, master)==0) printf("Saved.\n");
                    else fprintf(stderr, "Save failed.\n");
                }
            }
            break;
        }
        else {
            printf("Unknown option.\n");
        }
    }

    sodium_memzero(master, strlen(master)); free(master);
    yag_vault_free(&vault);
    return 0;
}
