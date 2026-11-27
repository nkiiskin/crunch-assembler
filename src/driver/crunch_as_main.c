#define _POSIX_C_SOURCE 200809L
#include "assembler/assembler.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __CRUNCH__
#include <fcntl.h>
#include <sys/random.h>
#endif

/**
 * @brief Looks up a variable in the process environment.
 * @param env Process environment.
 * @param name Variable name.
 * @return The value, or NULL if absent.
 */
static const char *environment_value(char **env, const char *name)
{
    size_t length = strlen(name);
    for (size_t i = 0; env && env[i]; ++i)
        if (!strncmp(env[i], name, length) && env[i][length] == '=')
            return env[i] + length + 1;
    return NULL;
}

/**
 * @brief Creates a uniquely named temporary object.
 * @param path Writable path ending in six placeholder characters.
 * @param length Length of the path.
 * @return Open descriptor, or -1 on failure.
 */
static int create_temporary(char *path, size_t length)
{
#ifdef __CRUNCH__
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int attempt = 0; attempt < 256; ++attempt) {
        unsigned char bytes[6];
        size_t used = 0;
        while (used < sizeof bytes) {
            ssize_t n = getrandom(bytes + used, sizeof bytes - used, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) return -1;
            if (!n) { errno = EIO; return -1; }
            used += (size_t)n;
        }
        for (size_t i = 0; i < sizeof bytes; ++i)
            path[length - 6 + i] = alphabet[bytes[i] % 62];
        int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd >= 0 || errno != EEXIST) return fd;
    }
    errno = EEXIST;
    return -1;
#else
    (void)length;
    return mkstemp(path);
#endif
}

/**
 * @brief Derives an object filename from an input path.
 * @param input Source path or "-" for standard input.
 * @return Allocated object filename, or NULL on allocation failure.
 */
static char *default_object_name(const char *input)
{
    const char *name = strrchr(input, '/');
    name = name ? name + 1 : input;
    if (!strcmp(name, "-")) name = "stdin";
    size_t len = strlen(name);
    if (len >= 2 && !strcmp(name + len - 2, ".s")) len -= 2;
    char *result = malloc(len + 3);
    if (result) {
        memcpy(result, name, len);
        memcpy(result + len, ".o", 3);
    }
    return result;
}

/**
 * @brief Rejects an output referring to any input file.
 * @param output Proposed output path.
 * @param inputs Input paths, including "-" for standard input.
 * @param count Number of input paths.
 * @return Zero if safe, or nonzero on collision or inspection failure.
 */
static int check_output_inputs(const char *output, const char *const *inputs, size_t count)
{
    struct stat output_stat;
    if (stat(output, &output_stat) != 0) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "crunch-as: cannot inspect output '%s': %s\n", output, strerror(errno));
        return 1;
    }
    for (size_t i = 0; i < count; ++i) {
        struct stat input_stat;
        int status = !strcmp(inputs[i], "-") ? fstat(STDIN_FILENO, &input_stat)
                                              : stat(inputs[i], &input_stat);
        if (status != 0) {
            fprintf(stderr, "crunch-as: cannot inspect input '%s': %s\n",
                    inputs[i], strerror(errno));
            return 1;
        }
        if (output_stat.st_dev == input_stat.st_dev &&
            output_stat.st_ino == input_stat.st_ino) {
            fprintf(stderr, "crunch-as: output '%s' is the same file as input '%s'\n",
                    output, inputs[i]);
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Rejects default object paths that could overwrite each other.
 * @param outputs Derived object paths.
 * @param count Number of output paths.
 * @return Zero if distinct, or nonzero on collision or inspection failure.
 */
static int check_distinct_outputs(char *const *outputs, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        struct stat left;
        int left_exists = stat(outputs[i], &left) == 0;
        if (!left_exists) {
            if (errno != ENOENT) {
                fprintf(stderr, "crunch-as: cannot inspect output '%s': %s\n",
                        outputs[i], strerror(errno));
                return 1;
            }
            struct stat link_stat;
            if (lstat(outputs[i], &link_stat) == 0) {
                fprintf(stderr, "crunch-as: output '%s' is a dangling symlink or changed during inspection\n",
                        outputs[i]);
                return 1;
            } else if (errno != ENOENT) {
                fprintf(stderr, "crunch-as: cannot inspect output '%s': %s\n",
                        outputs[i], strerror(errno));
                return 1;
            }
        }
        for (size_t j = 0; j < i; ++j) {
            struct stat right;
            int same = !strcmp(outputs[i], outputs[j]);
            if (!same && left_exists) {
                if (stat(outputs[j], &right) == 0)
                    same = left.st_dev == right.st_dev && left.st_ino == right.st_ino;
                else if (errno != ENOENT) {
                    fprintf(stderr, "crunch-as: cannot inspect output '%s': %s\n",
                            outputs[j], strerror(errno));
                    return 1;
                }
            }
            if (same) {
                fprintf(stderr, "crunch-as: output paths '%s' and '%s' refer to the same file\n",
                        outputs[j], outputs[i]);
                return 1;
            }
        }
    }
    return 0;
}

/**
 * @brief Invokes the adjacent linker and waits for it.
 * @param objects Temporary object paths.
 * @param count Number of objects.
 * @param output Executable output path.
 * @param nostdlib Whether to disable default runtime libraries.
 * @param env Process environment.
 * @return Linker exit status, or nonzero on failure.
 */
static int link_objects(char *const *objects, size_t count, const char *output,
                        int nostdlib, char **env)
{
    char linker[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", linker, sizeof linker - 1);
    if (len < 0 || (size_t)len >= sizeof linker - 1) {
        fprintf(stderr, "crunch-as: cannot locate crunch-ld\n");
        return 1;
    }
    linker[len] = '\0';
    char *slash = strrchr(linker, '/');
    if (!slash || (size_t)(slash - linker) + sizeof "/crunch-ld" > sizeof linker) {
        fprintf(stderr, "crunch-as: cannot locate crunch-ld\n");
        return 1;
    }
    strcpy(slash + 1, "crunch-ld");
    char **args = calloc(count + 5, sizeof *args);
    if (!args) {
        fprintf(stderr, "crunch-as: out of memory\n");
        return 1;
    }
    size_t n = 0;
    args[n++] = "crunch-ld";
    if (nostdlib) args[n++] = "-nostdlib";
    args[n++] = "-o";
    args[n++] = (char *)output;
    for (size_t i = 0; i < count; ++i) args[n++] = objects[i];
    pid_t pid = fork();
    if (pid < 0) {
        perror("crunch-as: fork");
        free(args);
        return 1;
    }
    if (pid == 0) {
        execve(linker, args, env);
        perror("crunch-as: cannot execute crunch-ld");
        _exit(127);
    }
    free(args);
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        perror("crunch-as: waitpid");
        return 1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
}

/**
 * @brief Parses command-line arguments and assembles, optionally linking.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument vector.
 * @param env Process environment.
 * @return Zero on success, or a nonzero process exit status on failure.
 */
int main(int argc, char **argv, char **env)
{
    const char *output = NULL;
    const char **inputs = calloc((size_t)argc + 1, sizeof *inputs);
    const char **include_dirs = calloc((size_t)argc + 1, sizeof *include_dirs);
    size_t count = 0, include_count = 0;
    int compile_only = 0, nostdlib = 0, result = 1;
    char **outputs = NULL, **temporary = NULL;
    if (!inputs || !include_dirs) {
        fprintf(stderr, "crunch-as: out of memory\n");
        goto done;
    }
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-c")) {
            compile_only = 1;
        } else if (!strcmp(argv[i], "-nostdlib")) {
            nostdlib = 1;
        } else if (!strcmp(argv[i], "--help")) {
            puts("usage: crunch-as [-c] [-nostdlib] [-I dir] [-o output] [input.s ...]");
            result = 0;
            goto done;
        } else if (!strcmp(argv[i], "-o")) {
            if (++i >= argc || output || !*argv[i]) {
                fprintf(stderr, "crunch-as: -o requires exactly one output path\n");
                result = 2;
                goto done;
            }
            output = argv[i];
        } else if (!strcmp(argv[i], "-I")) {
            if (++i >= argc || !*argv[i]) {
                fprintf(stderr, "crunch-as: -I requires an include directory\n");
                result = 2;
                goto done;
            }
            include_dirs[include_count++] = argv[i];
        } else if (!strncmp(argv[i], "-I", 2) && argv[i][2]) {
            include_dirs[include_count++] = argv[i] + 2;
        } else if (argv[i][0] == '-' && strcmp(argv[i], "-")) {
            fprintf(stderr, "crunch-as: unknown option: %s\n", argv[i]);
            result = 2;
            goto done;
        } else {
            inputs[count++] = argv[i];
        }
    }
    if (!count) inputs[count++] = "-";
    if (!output && compile_only) {
        outputs = calloc(count, sizeof *outputs);
        if (!outputs) {
            fprintf(stderr, "crunch-as: out of memory\n");
            goto done;
        }
        for (size_t i = 0; i < count; ++i) {
            outputs[i] = default_object_name(inputs[i]);
            if (!outputs[i]) {
                fprintf(stderr, "crunch-as: out of memory\n");
                goto done;
            }
            if (check_output_inputs(outputs[i], inputs, count)) goto done;
        }
        if (count > 1 && check_distinct_outputs(outputs, count)) goto done;
        if (count == 1) {
            result = crunch_assemble_files_with_includes(inputs, count, outputs[0],
                                                         include_dirs, include_count) == COMPILER_OK ? 0 : 1;
            goto done;
        }
    } else {
        if (!output) output = "a.out";
        if (check_output_inputs(output, inputs, count)) goto done;
    }
    if (compile_only && !outputs) {
        result = crunch_assemble_files_with_includes(inputs, count, output,
                                                     include_dirs, include_count) == COMPILER_OK ? 0 : 1;
        goto done;
    }
    const char *dir = environment_value(env, "TMPDIR");
    if (!dir || !*dir) dir = "/tmp";
    size_t length = strlen(dir);
    if (length > SIZE_MAX - sizeof "/crunch-as-XXXXXX") {
        fprintf(stderr, "crunch-as: temporary directory path is too long\n");
        goto done;
    }
    temporary = calloc(count, sizeof *temporary);
    if (!temporary) {
        fprintf(stderr, "crunch-as: out of memory\n");
        goto done;
    }
    for (size_t i = 0; i < count; ++i) {
        temporary[i] = malloc(length + sizeof "/crunch-as-XXXXXX");
        if (!temporary[i]) {
            fprintf(stderr, "crunch-as: out of memory\n");
            goto done;
        }
        sprintf(temporary[i], "%s/crunch-as-XXXXXX", dir);
        int fd = create_temporary(temporary[i], strlen(temporary[i]));
        if (fd < 0) {
            perror("crunch-as: temporary object");
            free(temporary[i]);
            temporary[i] = NULL;
            goto done;
        }
        if (close(fd) < 0) {
            perror("crunch-as: temporary object");
            goto done;
        }
        const char *const *protected_outputs = outputs ? (const char *const *)outputs : &output;
        size_t protected_count = outputs ? count : 1;
        if (crunch_assemble_files_protecting_outputs(&inputs[i], 1, temporary[i],
                                                     include_dirs, include_count,
                                                     protected_outputs, protected_count) != COMPILER_OK)
            goto done;
    }
    if (outputs) {
        result = 0;
        for (size_t i = 0; i < count; ++i)
            if (crunch_copy_object_safely(temporary[i], outputs[i]) != COMPILER_OK) result = 1;
    } else {
        result = link_objects(temporary, count, output, nostdlib, env);
    }
done:
    if (temporary) {
        for (size_t i = 0; i < count; ++i) {
            if (temporary[i]) unlink(temporary[i]);
            free(temporary[i]);
        }
    }
    free(temporary);
    if (outputs) for (size_t i = 0; i < count; ++i) free(outputs[i]);
    free(outputs);
    free(inputs);
    free(include_dirs);
    return result;
}
