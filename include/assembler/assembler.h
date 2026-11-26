#ifndef CRUNCH_ASSEMBLER_ASSEMBLER_H
#define CRUNCH_ASSEMBLER_ASSEMBLER_H

#include "common/compiler.h"

/**
 * @brief Assembles GNU-style x86-64 input files into an ELF64 object.
 * @param inputs Input paths; "-" reads standard input.
 * @param count Number of input paths.
 * @param output Output object path.
 * @return Compiler status; diagnostics are currently written to standard error.
 * @note Calls must not overlap; the experimental assembler uses shared state.
 */
CompilerStatus crunch_assemble_files(const char *const *inputs, size_t count,
                                     const char *output);

/**
 * @brief Assembles input files with additional assembler include directories.
 * @param inputs Input paths; "-" reads standard input.
 * @param count Number of input paths.
 * @param output Output object path.
 * @param include_dirs Include directories searched in order after the working directory.
 * @param include_count Number of include directories.
 * @return Compiler status; diagnostics are currently written to standard error.
 * @note Calls must not overlap; the experimental assembler uses shared state.
 */
CompilerStatus crunch_assemble_files_with_includes(const char *const *inputs, size_t count,
                                                   const char *output,
                                                   const char *const *include_dirs,
                                                   size_t include_count);

#endif
