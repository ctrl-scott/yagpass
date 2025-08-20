#include "passgen.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static char *maybe_copy(const char *s) {
    char *p = (char*)malloc(strlen(s)+1);
    if (!p) return NULL;
    strcpy(p, s);
    return p;
}

static char *filter_ambiguous(const char *src) {
    const char *amb = "0Oo1lI";
    size_t n = strlen(src);
    char *dst = (char*)malloc(n+1);
    if (!dst) return NULL;
    size_t j=0;
    for (size_t i=0;i<n;i++) if (!strchr(amb, src[i])) dst[j++]=src[i];
    dst[j]='\0';
    return dst;
}

static int choose_one(const char *set, char *out) {
    size_t n = strlen(set);
    if (!n) return -1;
    size_t idx = (size_t)randombytes_uniform((uint32_t)n);
    *out = set[idx];
    return 0;
}

static void fisher_yates(char *buf, size_t n) {
    if (n<=1) return;
    for (size_t i=n-1;i>0;i--) {
        size_t j = (size_t)randombytes_uniform((uint32_t)(i+1));
        char t = buf[i]; buf[i]=buf[j]; buf[j]=t;
    }
}

int pg_generate(const PG_Options *opt, char **out_pw) {
    const char *LOWER="abcdefghijklmnopqrstuvwxyz";
    const char *UPPER="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *DIGITS="0123456789";
    const char *SYMS="!@#$%^&*()-_=+[]{};:,.<>/?~";

    char *l=NULL,*u=NULL,*d=NULL,*s=NULL;
    l = opt->use_lower   ? (opt->exclude_ambiguous?filter_ambiguous(LOWER):maybe_copy(LOWER)) : NULL;
    u = opt->use_upper   ? (opt->exclude_ambiguous?filter_ambiguous(UPPER):maybe_copy(UPPER)) : NULL;
    d = opt->use_digits  ? (opt->exclude_ambiguous?filter_ambiguous(DIGITS):maybe_copy(DIGITS)) : NULL;
    s = opt->use_symbols ? (opt->exclude_ambiguous?filter_ambiguous(SYMS) :maybe_copy(SYMS))  : NULL;

    size_t total = (l?strlen(l):0)+(u?strlen(u):0)+(d?strlen(d):0)+(s?strlen(s):0);
    if (total==0 || opt->length==0) { free(l);free(u);free(d);free(s); return -1; }

    char *combined=(char*)malloc(total+1);
    if(!combined){ free(l);free(u);free(d);free(s); return -1; }
    combined[0]='\0';
    if(l)strcat(combined,l); if(u)strcat(combined,u); if(d)strcat(combined,d); if(s)strcat(combined,s);

    // count required classes
    size_t req= (!!l)+ (!!u)+ (!!d)+ (!!s);
    if (opt->length < req) { free(l);free(u);free(d);free(s);free(combined); return -1; }

    char *pw=(char*)malloc(opt->length+1);
    if(!pw){ free(l);free(u);free(d);free(s);free(combined); return -1; }

    size_t k=0;
    if(l) choose_one(l,&pw[k++]);
    if(u) choose_one(u,&pw[k++]);
    if(d) choose_one(d,&pw[k++]);
    if(s) choose_one(s,&pw[k++]);

    while (k<opt->length) {
        size_t idx=(size_t)randombytes_uniform((uint32_t)total);
        pw[k++]=combined[idx];
    }

    fisher_yates(pw, opt->length);
    pw[opt->length]='\0';

    free(l);free(u);free(d);free(s);free(combined);
    *out_pw = pw;
    return 0;
}
