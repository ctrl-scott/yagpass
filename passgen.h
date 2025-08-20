#ifndef YAGPASS_PASSGEN_H
#define YAGPASS_PASSGEN_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    size_t length;
    bool use_lower;
    bool use_upper;
    bool use_digits;
    bool use_symbols;
    bool exclude_ambiguous;
} PG_Options;

int pg_generate(const PG_Options *opt, char **out_pw);

#endif
