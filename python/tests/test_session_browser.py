"""Tests for session and browser mode manifest parsing (v0.5.1)."""

from __future__ import annotations

import textwrap
import tempfile
import os

import pytest

from toolclad.manifest import (
    load_manifest,
    SessionDef,
    SessionCommandDef,
    BrowserDef,
    BrowserCommandDef,
    BrowserScopeDef,
)


def _write_tmp(content: str) -> str:
    """Write content to a temporary .clad.toml file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".clad.toml")
    with os.fdopen(fd, "w") as f:
        f.write(textwrap.dedent(content))
    return path


class TestSessionMode:
    def test_parse_session_manifest(self):
        path = _write_tmp("""\
            [tool]
            name = "psql_session"
            mode = "session"
            description = "PostgreSQL session"

            [session]
            startup_command = "psql -U user dbname"
            ready_pattern = "^dbname=> $"
            max_interactions = 50

            [session.commands.select]
            pattern = "^SELECT .+$"
            description = "Run a SELECT query"
            risk_tier = "low"

            [session.commands.drop]
            pattern = "^DROP .+$"
            description = "Drop a table"
            risk_tier = "high"
            human_approval = true

            [output]
            format = "text"

            [output.schema]
            type = "object"
        """)
        try:
            m = load_manifest(path)
            assert m.tool.name == "psql_session"
            assert m.session is not None
            assert m.session.startup_command == "psql -U user dbname"
            assert m.session.ready_pattern == "^dbname=> $"
            assert m.session.max_interactions == 50

            assert "select" in m.session.commands
            assert m.session.commands["select"].pattern == "^SELECT .+$"
            assert m.session.commands["select"].risk_tier == "low"

            assert "drop" in m.session.commands
            assert m.session.commands["drop"].human_approval is True
            assert m.session.commands["drop"].risk_tier == "high"

            assert m.output is not None
            assert m.output.format == "text"
            assert m.output.schema["type"] == "object"
        finally:
            os.unlink(path)

    def test_session_defaults(self):
        path = _write_tmp("""\
            [tool]
            name = "minimal_session"

            [session]
            startup_command = "bash"

            [output]
            format = "text"
        """)
        try:
            m = load_manifest(path)
            assert m.session is not None
            assert m.session.startup_timeout_seconds == 30
            assert m.session.idle_timeout_seconds == 300
            assert m.session.session_timeout_seconds == 1800
            assert m.session.max_interactions == 100
            assert m.session.interaction is None
            assert m.session.commands == {}
        finally:
            os.unlink(path)


class TestBrowserMode:
    def test_parse_browser_manifest(self):
        path = _write_tmp("""\
            [tool]
            name = "browser_session"
            mode = "browser"
            description = "Browser session"

            [browser]
            engine = "cdp"
            connect = "launch"
            extract_mode = "accessibility_tree"

            [browser.scope]
            allowed_domains = ["*.example.com"]

            [browser.commands.navigate]
            description = "Navigate to URL"
            risk_tier = "medium"

            [browser.commands.snapshot]
            description = "Get accessibility tree"
            risk_tier = "low"

            [output]
            format = "json"

            [output.schema]
            type = "object"
        """)
        try:
            m = load_manifest(path)
            assert m.tool.name == "browser_session"
            assert m.browser is not None
            assert m.browser.engine == "cdp"
            assert m.browser.connect == "launch"
            assert m.browser.extract_mode == "accessibility_tree"

            assert m.browser.scope is not None
            assert m.browser.scope.allowed_domains == ["*.example.com"]

            assert "navigate" in m.browser.commands
            assert m.browser.commands["navigate"].risk_tier == "medium"

            assert "snapshot" in m.browser.commands
            assert m.browser.commands["snapshot"].risk_tier == "low"

            assert m.output is not None
            assert m.output.format == "json"
        finally:
            os.unlink(path)

    def test_browser_defaults(self):
        path = _write_tmp("""\
            [tool]
            name = "minimal_browser"

            [browser]
            engine = "cdp"

            [output]
            format = "json"
        """)
        try:
            m = load_manifest(path)
            assert m.browser is not None
            assert m.browser.headless is True
            assert m.browser.connect == "launch"
            assert m.browser.extract_mode == "accessibility_tree"
            assert m.browser.startup_timeout_seconds == 10
            assert m.browser.session_timeout_seconds == 600
            assert m.browser.idle_timeout_seconds == 120
            assert m.browser.max_interactions == 200
            assert m.browser.scope is None
            assert m.browser.state is None
            assert m.browser.commands == {}
        finally:
            os.unlink(path)
