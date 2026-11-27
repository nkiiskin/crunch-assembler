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

/**
 * @brief Assembles while protecting additional output paths from included files.
 * @param inputs Input paths; "-" reads standard input.
 * @param count Number of input paths.
 * @param output Output object path, always protected.
 * @param include_dirs Include directories searched after the working directory.
 * @param include_count Number of include directories.
 * @param protected_outputs Additional output paths to protect.
 * @param protected_count Number of additional output paths.
 * @return Compiler status; diagnostics are written to standard error.
 * @note Calls must not overlap; the experimental assembler uses shared state.
 */
CompilerStatus crunch_assemble_files_protecting_outputs(const char *const *inputs, size_t count,
                                                        const char *output,
                                                        const char *const *include_dirs,
                                                        size_t include_count,
                                                        const char *const *protected_outputs,
                                                        size_t protected_count);

/**
 * @brief Copies a staged object with atomic replacement of its destination.
 * @param source Existing staged object path.
 * @param output Destination object path.
 * @return Compiler status; diagnostics are written to standard error.
 */
CompilerStatus crunch_copy_object_safely(const char *source, const char *output);

#endif
