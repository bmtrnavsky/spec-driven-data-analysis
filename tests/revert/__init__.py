"""Whole-function reference reverts (SPEC-504ed55 §3).

A revert replaces one named function in a product module with a reference
implementation file, located BY FUNCTION NAME via the AST — never by line
substitution. A missing or ambiguous function name, a reference file that
does not define exactly that function, or a patched module that no longer
compiles reports INCOHERENT-REVERT instead of running probes against a
program that never existed.
"""
