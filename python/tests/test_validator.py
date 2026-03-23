"""Tests for ToolClad argument type validation."""

from __future__ import annotations

import pytest

from toolclad.manifest import ArgDef
from toolclad.validator import ValidationError, validate_arg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _arg(type: str, **kwargs) -> ArgDef:  # noqa: A002
    """Create an ArgDef with the given type and optional overrides."""
    return ArgDef(name="test", type=type, **kwargs)


# ---------------------------------------------------------------------------
# string
# ---------------------------------------------------------------------------

class TestStringValidation:
    def test_valid_string(self):
        assert validate_arg(_arg("string"), "hello") == "hello"

    def test_string_with_pattern(self):
        ad = _arg("string", pattern=r"^[a-z]+$")
        assert validate_arg(ad, "abc") == "abc"

    def test_string_pattern_mismatch(self):
        ad = _arg("string", pattern=r"^[a-z]+$")
        with pytest.raises(ValidationError, match="does not match pattern"):
            validate_arg(ad, "ABC123")

    def test_string_injection_rejected(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_arg(_arg("string"), "hello; rm -rf /")


# ---------------------------------------------------------------------------
# integer
# ---------------------------------------------------------------------------

class TestIntegerValidation:
    def test_valid_integer(self):
        assert validate_arg(_arg("integer"), "42") == "42"

    def test_negative_integer(self):
        assert validate_arg(_arg("integer"), "-5") == "-5"

    def test_not_a_number(self):
        with pytest.raises(ValidationError, match="Expected integer"):
            validate_arg(_arg("integer"), "abc")

    def test_min_max_in_range(self):
        ad = _arg("integer", min=1, max=100)
        assert validate_arg(ad, "50") == "50"

    def test_below_min(self):
        ad = _arg("integer", min=1, max=100)
        with pytest.raises(ValidationError, match="below minimum"):
            validate_arg(ad, "0")

    def test_above_max(self):
        ad = _arg("integer", min=1, max=100)
        with pytest.raises(ValidationError, match="above maximum"):
            validate_arg(ad, "200")

    def test_clamp_below(self):
        ad = _arg("integer", min=1, max=100, clamp=True)
        assert validate_arg(ad, "-5") == "1"

    def test_clamp_above(self):
        ad = _arg("integer", min=1, max=100, clamp=True)
        assert validate_arg(ad, "999") == "100"


# ---------------------------------------------------------------------------
# port
# ---------------------------------------------------------------------------

class TestPortValidation:
    def test_valid_port(self):
        assert validate_arg(_arg("port"), "443") == "443"

    def test_port_zero(self):
        with pytest.raises(ValidationError, match="out of range"):
            validate_arg(_arg("port"), "0")

    def test_port_max(self):
        assert validate_arg(_arg("port"), "65535") == "65535"

    def test_port_out_of_range(self):
        with pytest.raises(ValidationError, match="out of range"):
            validate_arg(_arg("port"), "70000")

    def test_port_negative(self):
        with pytest.raises(ValidationError, match="out of range"):
            validate_arg(_arg("port"), "-1")

    def test_port_not_a_number(self):
        with pytest.raises(ValidationError, match="Expected port"):
            validate_arg(_arg("port"), "http")


# ---------------------------------------------------------------------------
# boolean
# ---------------------------------------------------------------------------

class TestBooleanValidation:
    def test_true(self):
        assert validate_arg(_arg("boolean"), "true") == "true"

    def test_false(self):
        assert validate_arg(_arg("boolean"), "false") == "false"

    def test_case_insensitive(self):
        assert validate_arg(_arg("boolean"), "True") == "true"
        assert validate_arg(_arg("boolean"), "FALSE") == "false"

    def test_invalid_boolean(self):
        with pytest.raises(ValidationError, match="Expected 'true' or 'false'"):
            validate_arg(_arg("boolean"), "yes")


# ---------------------------------------------------------------------------
# enum
# ---------------------------------------------------------------------------

class TestEnumValidation:
    def test_valid_enum(self):
        ad = _arg("enum", allowed=["ping", "service", "syn"])
        assert validate_arg(ad, "service") == "service"

    def test_invalid_enum(self):
        ad = _arg("enum", allowed=["ping", "service", "syn"])
        with pytest.raises(ValidationError, match="not in allowed"):
            validate_arg(ad, "aggressive")

    def test_enum_no_allowed_list(self):
        ad = _arg("enum")
        with pytest.raises(ValidationError, match="requires 'allowed' list"):
            validate_arg(ad, "anything")


# ---------------------------------------------------------------------------
# scope_target
# ---------------------------------------------------------------------------

class TestScopeTargetValidation:
    def test_valid_ip(self):
        assert validate_arg(_arg("scope_target"), "10.0.1.1") == "10.0.1.1"

    def test_valid_cidr(self):
        assert validate_arg(_arg("scope_target"), "10.0.1.0/24") == "10.0.1.0/24"

    def test_valid_hostname(self):
        assert validate_arg(_arg("scope_target"), "example.com") == "example.com"

    def test_wildcard_rejected(self):
        with pytest.raises(ValidationError, match="Wildcard"):
            validate_arg(_arg("scope_target"), "*.example.com")

    def test_injection_in_target(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_arg(_arg("scope_target"), "10.0.1.1; echo pwned")

    def test_invalid_target(self):
        # "!!!" contains shell metacharacter '!', so injection check fires first
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_arg(_arg("scope_target"), "not a valid target at all!!!")

    def test_invalid_target_no_metachar(self):
        with pytest.raises(ValidationError, match="Invalid scope target"):
            validate_arg(_arg("scope_target"), "not a valid target")


# ---------------------------------------------------------------------------
# url
# ---------------------------------------------------------------------------

class TestUrlValidation:
    def test_valid_http_url(self):
        ad = _arg("url")
        assert validate_arg(ad, "https://example.com/path") == "https://example.com/path"

    def test_scheme_restriction(self):
        ad = _arg("url", schemes=["https"])
        with pytest.raises(ValidationError, match="scheme"):
            validate_arg(ad, "http://example.com")

    def test_invalid_url(self):
        with pytest.raises(ValidationError, match="Invalid URL"):
            validate_arg(_arg("url"), "not-a-url")


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------

class TestPathValidation:
    def test_valid_relative_path(self):
        assert validate_arg(_arg("path"), "config/settings.toml") == "config/settings.toml"

    def test_absolute_path_rejected(self):
        with pytest.raises(ValidationError, match="relative"):
            validate_arg(_arg("path"), "/usr/share/wordlists/common.txt")

    def test_traversal_rejected(self):
        with pytest.raises(ValidationError, match="relative"):
            validate_arg(_arg("path"), "/etc/../../../etc/shadow")

    def test_relative_traversal_rejected(self):
        with pytest.raises(ValidationError, match="traversal"):
            validate_arg(_arg("path"), "config/../../etc/shadow")

    def test_injection_in_path(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_arg(_arg("path"), "tmp/$(whoami).txt")


# ---------------------------------------------------------------------------
# ip_address
# ---------------------------------------------------------------------------

class TestIpAddressValidation:
    def test_valid_ipv4(self):
        assert validate_arg(_arg("ip_address"), "192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert validate_arg(_arg("ip_address"), "::1") == "::1"

    def test_invalid_ip(self):
        with pytest.raises(ValidationError, match="Invalid IP address"):
            validate_arg(_arg("ip_address"), "999.999.999.999")


# ---------------------------------------------------------------------------
# cidr
# ---------------------------------------------------------------------------

class TestCidrValidation:
    def test_valid_cidr(self):
        assert validate_arg(_arg("cidr"), "10.0.0.0/8") == "10.0.0.0/8"

    def test_missing_slash(self):
        with pytest.raises(ValidationError, match="requires '/'"):
            validate_arg(_arg("cidr"), "10.0.0.1")

    def test_invalid_cidr(self):
        with pytest.raises(ValidationError, match="Invalid CIDR"):
            validate_arg(_arg("cidr"), "not/a/cidr")


# ---------------------------------------------------------------------------
# Injection sanitization
# ---------------------------------------------------------------------------

class TestInjectionSanitization:
    """Shell metacharacter rejection applies to string-based types."""

    @pytest.mark.parametrize("char", list(";|&$`(){}[]<>!"))
    def test_metacharacter_rejected_in_string(self, char):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_arg(_arg("string"), f"value{char}injection")

    def test_semicolon_in_scope_target(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_arg(_arg("scope_target"), "10.0.1.1;echo")

    def test_backtick_in_path(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_arg(_arg("path"), "/tmp/`whoami`")


# ---------------------------------------------------------------------------
# Unknown type
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# msf_options
# ---------------------------------------------------------------------------

class TestMsfOptionsValidation:
    def test_valid_options(self):
        assert validate_arg(_arg("msf_options"), "RHOSTS 10.0.1.1;RPORT 445") == "RHOSTS 10.0.1.1;RPORT 445"

    def test_invalid_key(self):
        with pytest.raises(ValidationError, match="invalid key"):
            validate_arg(_arg("msf_options"), "rhosts 10.0.1.1")

    def test_injection_in_value(self):
        with pytest.raises(ValidationError, match="disallowed"):
            validate_arg(_arg("msf_options"), "RHOSTS $(whoami)")

    def test_single_pair(self):
        assert validate_arg(_arg("msf_options"), "RHOSTS 10.0.1.1") == "RHOSTS 10.0.1.1"


# ---------------------------------------------------------------------------
# credential_file
# ---------------------------------------------------------------------------

class TestCredentialFileValidation:
    def test_absolute_rejected(self):
        with pytest.raises(ValidationError, match="relative"):
            validate_arg(_arg("credential_file"), "/etc/shadow")

    def test_traversal_rejected(self):
        with pytest.raises(ValidationError, match="traversal"):
            validate_arg(_arg("credential_file"), "../../../etc/passwd")

    def test_nonexistent(self):
        with pytest.raises(ValidationError, match="not found"):
            validate_arg(_arg("credential_file"), "nonexistent_file.txt")


# ---------------------------------------------------------------------------
# duration
# ---------------------------------------------------------------------------

class TestDurationValidation:
    def test_plain_seconds(self):
        assert validate_arg(_arg("duration"), "30") == "30"

    def test_minutes(self):
        assert validate_arg(_arg("duration"), "5m") == "5m"

    def test_hours(self):
        assert validate_arg(_arg("duration"), "2h") == "2h"

    def test_combined(self):
        assert validate_arg(_arg("duration"), "1h30m") == "1h30m"

    def test_milliseconds(self):
        assert validate_arg(_arg("duration"), "500ms") == "500ms"

    def test_invalid(self):
        with pytest.raises(ValidationError, match="Invalid duration"):
            validate_arg(_arg("duration"), "abc")


# ---------------------------------------------------------------------------
# regex_match
# ---------------------------------------------------------------------------

class TestRegexMatchValidation:
    def test_valid_match(self):
        ad = _arg("regex_match")
        ad.pattern = r"^\d{3}-\d{4}$"
        assert validate_arg(ad, "123-4567") == "123-4567"

    def test_no_match(self):
        ad = _arg("regex_match")
        ad.pattern = r"^\d{3}-\d{4}$"
        with pytest.raises(ValidationError, match="does not match"):
            validate_arg(ad, "abc")

    def test_missing_pattern(self):
        with pytest.raises(ValidationError, match="requires.*pattern"):
            validate_arg(_arg("regex_match"), "anything")


# ---------------------------------------------------------------------------
# Unknown type
# ---------------------------------------------------------------------------

class TestUnknownType:
    def test_unknown_type_raises(self):
        with pytest.raises(ValidationError, match="Unknown type"):
            validate_arg(_arg("foobar"), "anything")
