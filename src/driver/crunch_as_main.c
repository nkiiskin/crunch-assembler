#include "assembler/assembler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Parses command-line arguments and invokes the object assembler.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument vector.
 * @return Zero on success, or a nonzero process exit status on failure.
 */
int main(int argc, char **argv)
{
    const char *output = NULL;
    const char **inputs = calloc((size_t)argc + 1, sizeof *inputs);
    const char **include_dirs = calloc((size_t)argc + 1, sizeof *include_dirs);
    size_t count = 0, include_count = 0;
    if (!inputs || !include_dirs) {
        fprintf(stderr, "crunch-as: out of memory\n");
        free(inputs);
        free(include_dirs);
        return 1;
    }
    if (argc == 3 && argv[1][0] != '-' && argv[2][0] != '-') {
        inputs[count++] = argv[1];
        output = argv[2];
    } else {
        for (int i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "-o")) {
                if (++i >= argc || output) {
                    fprintf(stderr, "crunch-as: -o requires exactly one output path\n");
                    free(inputs);
                    free(include_dirs);
                    return 2;
                }
                output = argv[i];
            } else if (!strcmp(argv[i], "-I")) {
                if (++i >= argc || !*argv[i]) {
                    fprintf(stderr, "crunch-as: -I requires an include directory\n");
                    free(inputs);
                    free(include_dirs);
                    return 2;
                }
                include_dirs[include_count++] = argv[i];
            } else if (!strncmp(argv[i], "-I", 2) && argv[i][2]) {
                include_dirs[include_count++] = argv[i] + 2;
            } else if (argv[i][0] == '-' && strcmp(argv[i], "-")) {
                fprintf(stderr, "crunch-as: unknown option: %s\n", argv[i]);
                free(inputs);
                free(include_dirs);
                return 2;
            } else {
                inputs[count++] = argv[i];
            }
        }
    }
    if (!output) {
        fprintf(stderr, "usage: crunch-as [-I dir] -o output.o [input.s ...]\n");
        free(inputs);
        free(include_dirs);
        return 2;
    }
    if (!count) inputs[count++] = "-";
    CompilerStatus status = crunch_assemble_files_with_includes(inputs, count, output,
                                                               include_dirs, include_count);
    free(inputs);
    free(include_dirs);
    return status == COMPILER_OK ? 0 : 1;
}
