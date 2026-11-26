#ifndef CRUNCH_COMMON_COMPILER_H
#define CRUNCH_COMMON_COMPILER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum number of local IR slots and simultaneously visible local bindings. */
#define CRUNCH_LOCAL_LIMIT 1024

typedef enum {
    COMPILER_OK = 0,
    COMPILER_INVALID_INPUT,
    COMPILER_LEX_ERROR,
    COMPILER_PARSE_ERROR,
    COMPILER_SEMA_ERROR,
    COMPILER_CODEGEN_ERROR,
    COMPILER_OUT_OF_MEMORY,
    COMPILER_IO_ERROR,
    COMPILER_INTERNAL_ERROR
} CompilerStatus;

typedef struct {
    const char *filename;
    const char *data;
    size_t length;
} SourceFile;

typedef struct {
    size_t offset;
    uint32_t line;
    uint32_t column;
} SourceLocation;

typedef struct {
    CompilerStatus status;
    unsigned error_count;
    unsigned warning_count;
} CompilerResult;

#endif
