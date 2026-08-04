

"""Shared pytest fixtures.

`soc.config.get_settings` loads settings with `python-dotenv`, which writes the
values it reads into `os.environ`. Those writes outlive the test that triggered
them, and `load_dotenv` does not override variables that are already set, so one
test's `.env` file can silently win over a later test's. That makes any test
touching configuration order-dependent.

This module restores the environment and the cached settings around every test
so the suite stays order-independent.
"""

from __future__ import annotations

import os

import pytest

import soc.config


@pytest.fixture(autouse=True)
def isolate_environment():
    """Snapshot and restore os.environ and the settings cache around each test.

    Inputs:
        None.

    Outputs:
        None. Yields to the test, then restores the environment.
    """

    saved_environ = dict(os.environ)
    saved_settings = soc.config._cached_settings

    yield

    os.environ.clear()
    os.environ.update(saved_environ)
    soc.config._cached_settings = saved_settings
