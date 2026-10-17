"""Errors that report a mistake in how a command was called, or in what it was given.

The command line prints their message without a traceback; called from Python they are ordinary ValueErrors.
"""


class OperatorError(ValueError):
    """A command was given something it cannot use: a wrong option, a file of the wrong form, a missing package."""
