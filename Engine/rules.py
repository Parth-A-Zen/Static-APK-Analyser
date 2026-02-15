"""
Security Rules Module - Complete Production Version

Concrete implementations of security checks for OWASP Mobile Top 10 2024
Tuned against AndroGoat as reference vulnerable application.

Covers all major Android vulnerability categories:
- Information Storage (8 issues)
- Input Validation (3 issues)
- Component Exposure (4 issues)
- Network Communication (5 issues)
- Binary Protection & Environment Detection (4 issues)
- Cryptographic Issues (2+ issues)

Author: Generated for APK Security Analysis
License: MIT
Version: 5.0 - Complete AndroGoat Coverage
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Set, Dict, Tuple

from Analyser.Engine.base_rule import BaseRule
from Analyser.Engine.finding import Finding
from Analyser.Loader.scope_filter import AnalysisReadyAPK

logger = logging.getLogger(__name__)

# ============================================================================
# OWASP Category Constants
# ============================================================================
OWASP_M1 = "M1: Improper Credential Usage"
OWASP_M2 = "M2: Inadequate Supply Chain Security"
OWASP_M3 = "M3: Insecure Authentication/Authorization"
OWASP_M4 = "M4: Insufficient Input/Output Validation"
OWASP_M5 = "M5: Insecure Communication"
OWASP_M6 = "M6: Inadequate Privacy Controls"
OWASP_M7 = "M7: Insufficient Binary Protections"
OWASP_M8 = "M8: Security Misconfiguration"
OWASP_M9 = "M9: Insecure Data Storage"
OWASP_M10 = "M10: Insufficient Cryptography"


# ============================================================================
# RULE 1: Debuggable Enabled (Binary Protection)
# ============================================================================
class DebuggableEnabledRule(BaseRule):
    """
    Detect android:debuggable=true.
    
    AndroGoat vulnerability: Debug mode enabled allowing debugger attachment,
    memory inspection, execution modification, and security bypass.
    
    Category: Binary Protection & Environment Detection
    """

    @property
    def rule_id(self) -> str:
        return "DEBUGGABLE_ENABLED"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            if data.debuggable is True:
                finding = Finding(
                    title="Debuggable Application",
                    description=(
                        "The APK has android:debuggable=true. This allows attackers to "
                        "attach debuggers (JDWP), inspect memory, modify execution flow, "
                        "bypass security controls, and extract sensitive runtime data. "
                        "AndroGoat has this intentionally for testing. In production, this "
                        "exposes the entire application internals to any attacker with "
                        "physical or ADB access."
                    ),
                    owasp_category=OWASP_M7,
                    severity="High",
                    remediation=(
                        "Set android:debuggable=\"false\" for all production builds. "
                        "Use build variants to ensure debug is only enabled in development. "
                        "Verify with: aapt dump badging app.apk | grep debuggable"
                    ),
                    affected_component="AndroidManifest.xml",
                    evidence={"debuggable": True, "package": data.package_name},
                    rule_id=self.rule_id,
                )
                findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 2: Allow Backup Enabled (Insecure Data Storage)
# ============================================================================
class AllowBackupEnabledRule(BaseRule):
    """
    Detect allowBackup=true enabling data extraction via adb backup.
    
    AndroGoat vulnerability: Backup enabled, allowing full data extraction
    of SharedPreferences (users.xml, score.xml), databases, and files.
    
    Category: Binary Protection & Environment Detection
    """

    @property
    def rule_id(self) -> str:
        return "ALLOW_BACKUP_ENABLED"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            if data.allow_backup is True:
                finding = Finding(
                    title="Backup Allowed - Data Extraction Risk",
                    description=(
                        "The APK allows backup via 'adb backup'. Attackers with USB access "
                        "can extract SharedPreferences (users.xml with plaintext passwords, "
                        "score.xml), SQLite databases (aGoat), temporary files, and any "
                        "internal storage files. AndroGoat stores credentials that can be "
                        "fully extracted this way using: adb backup -apk -shared <package>"
                    ),
                    owasp_category=OWASP_M9,
                    severity="Medium",
                    remediation=(
                        "Set android:allowBackup=\"false\" in AndroidManifest.xml. "
                        "If backup functionality is needed, use android:fullBackupContent "
                        "to exclude sensitive files, or implement BackupAgent with encryption."
                    ),
                    affected_component="AndroidManifest.xml",
                    evidence={"allow_backup": True, "package": data.package_name},
                    rule_id=self.rule_id,
                )
                findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 3: Cleartext Traffic Allowed (Network Security)
# ============================================================================
class CleartextTrafficAllowedRule(BaseRule):
    """
    Detect cleartext HTTP traffic allowed.
    
    AndroGoat vulnerability: HTTP traffic permitted, enabling MITM attacks
    on all network communications.
    
    Category: Network Communication Vulnerabilities
    """

    @property
    def rule_id(self) -> str:
        return "CLEARTEXT_TRAFFIC_ALLOWED"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            if data.uses_cleartext_traffic is True:
                finding = Finding(
                    title="Cleartext (HTTP) Traffic Allowed",
                    description=(
                        "The app allows unencrypted HTTP traffic via "
                        "android:usesCleartextTraffic=\"true\". All network data including "
                        "credentials, tokens, and personal data can be intercepted by anyone "
                        "on the same network. AndroGoat demonstrates this vulnerability "
                        "allowing full MITM attacks on network communications."
                    ),
                    owasp_category=OWASP_M5,
                    severity="High",
                    remediation=(
                        "Set android:usesCleartextTraffic=\"false\" in AndroidManifest.xml. "
                        "Use HTTPS for all network communication. Implement a network "
                        "security config to enforce TLS. For API 28+ cleartext is blocked "
                        "by default unless explicitly allowed."
                    ),
                    affected_component="AndroidManifest.xml",
                    evidence={
                        "uses_cleartext_traffic": True,
                        "package": data.package_name,
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 4: Exported Components Without Permission (Component Exposure)
# ============================================================================
class ExportedComponentWithoutPermissionRule(BaseRule):
    """
    Detect unprotected exported components (activities, services, receivers, providers).
    
    AndroGoat vulnerability: 4+ exported components without permissions including
    unprotected activities, services, broadcast receivers, and content providers.
    
    Category: Component Exposure Vulnerabilities
    """

    @property
    def rule_id(self) -> str:
        return "EXPORTED_COMPONENT_NO_PERMISSION"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            for component in data.exported_components:
                if component.exported and not component.permission:
                    comp_type = component.type.lower()

                    # Detailed description per component type
                    type_risks = {
                        "activity": (
                            "Any app can launch this activity, potentially bypassing "
                            "authentication flows, accessing sensitive screens, or "
                            "injecting malicious intent extras."
                        ),
                        "service": (
                            "Any app can start or bind to this service, potentially "
                            "invoking privileged operations, exfiltrating data, or "
                            "causing denial of service."
                        ),
                        "receiver": (
                            "Any app can send broadcasts to this receiver, potentially "
                            "triggering sensitive operations, injecting data, or "
                            "causing unintended side effects."
                        ),
                        "provider": (
                            "Any app can query this content provider, potentially "
                            "reading sensitive database contents, modifying records, "
                            "or performing SQL injection attacks."
                        ),
                    }

                    risk_desc = type_risks.get(
                        comp_type,
                        "Any app can interact with this component without restrictions.",
                    )

                    # Provider is especially dangerous
                    severity = "Critical" if comp_type == "provider" else "High"

                    finding = Finding(
                        title=f"Unprotected Exported {component.type.title()}",
                        description=(
                            f"The {component.type} '{component.name}' is exported without "
                            f"permission protection. {risk_desc} "
                            f"AndroGoat has multiple such components for testing exploitation."
                        ),
                        owasp_category=OWASP_M8,
                        severity=severity,
                        remediation=(
                            f"Set android:exported=\"false\" if the {component.type} does not "
                            f"need to be accessed by other apps. If external access is required, "
                            f"add android:permission with a signature-level custom permission. "
                            f"For content providers, also set android:readPermission and "
                            f"android:writePermission."
                        ),
                        affected_component=component.name,
                        evidence={
                            "component_type": component.type,
                            "component_name": component.name,
                            "exported": True,
                            "permission": None,
                            "intent_filters": component.intent_filter_count,
                        },
                        rule_id=self.rule_id,
                    )
                    findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 5: Dangerous Permissions (Privacy Controls)
# ============================================================================
class DangerousPermissionDeclaredRule(BaseRule):
    """
    Detect dangerous permissions that access sensitive data/hardware.
    
    Category: Inadequate Privacy Controls
    """

    @property
    def rule_id(self) -> str:
        return "DANGEROUS_PERMISSION_DECLARED"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            high_risk_permissions = {
                "READ_SMS",
                "RECEIVE_SMS",
                "SEND_SMS",
                "READ_CALL_LOG",
                "WRITE_CALL_LOG",
                "RECORD_AUDIO",
                "CAMERA",
                "ACCESS_FINE_LOCATION",
                "ACCESS_COARSE_LOCATION",
                "ACCESS_BACKGROUND_LOCATION",
                "READ_CONTACTS",
                "WRITE_CONTACTS",
                "READ_EXTERNAL_STORAGE",
                "WRITE_EXTERNAL_STORAGE",
                "READ_PHONE_STATE",
                "READ_PHONE_NUMBERS",
                "PROCESS_OUTGOING_CALLS",
                "BODY_SENSORS",
                "ACTIVITY_RECOGNITION",
                "READ_CALENDAR",
                "WRITE_CALENDAR",
            }

            for permission in data.dangerous_permissions:
                perm_short = (
                    permission.split(".")[-1] if "." in permission else permission
                )
                is_high_risk = any(
                    hrp in perm_short.upper() for hrp in high_risk_permissions
                )

                finding = Finding(
                    title=f"Dangerous Permission: {perm_short}",
                    description=(
                        f"App requests dangerous permission '{permission}'. "
                        f"{'HIGH RISK - This permission grants access to highly sensitive '
                         'user data or device capabilities. ' if is_high_risk else ''}"
                        f"Verify this permission is strictly necessary for app functionality "
                        f"and handle it with runtime permission requests."
                    ),
                    owasp_category=OWASP_M6,
                    severity="High" if is_high_risk else "Medium",
                    remediation=(
                        "Remove unnecessary permissions following least-privilege principle. "
                        "Request at runtime (API 23+) with clear user explanation. "
                        "Document all permissions in privacy policy. Consider alternatives "
                        "that don't require dangerous permissions."
                    ),
                    affected_component="AndroidManifest.xml",
                    evidence={
                        "permission": permission,
                        "is_high_risk": is_high_risk,
                        "package": data.package_name,
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 6: Hardcoded Secrets - AGGRESSIVELY TUNED
# ============================================================================
class HardcodedSecretRule(BaseRule):
    """
    Detect hardcoded secrets: API keys, passwords, tokens, promo codes, credentials.
    
    AndroGoat contains: AWS access keys, promo codes, hardcoded credentials,
    hardcoded cryptographic keys, database passwords.
    
    Category: Information Storage - Hard coding issues
    
    TUNING: Aggressive blocklist with sensitivity to real API key patterns
    and AndroGoat-specific credential patterns.
    """

    FALSE_POSITIVE_BLOCKLIST = {
        # Kotlin/Android compiler artifacts
        r"\$this\$",
        r"\$i\$a\$",
        r"\$i\$f\$",
        r"_\$?u24lambda_",
        r"\$\$.*\$\$",
        r"_Kt\$",
        r"Lambda\$",
        r"Companion\$",
        r"\$.*\$\d+",
        r"^[_a-zA-Z][_a-zA-Z0-9]*\$$",
        r"_\$.*\$_",
        r"SavedStateHandle",
        r"ViewModel",
        # JSON/serialization
        r"^\{.*Landroid/",
        r"~~~\{",
        r"^\[L.*;\]$",
        # Generic non-secret patterns
        r"^[\n\r\t\s\-=~`]+$",
        r"^\d+$",
        r"^[^\w\s]{10,}$",
        # Framework references
        r"^R\$",
        r"^BuildConfig\$",
        r"^\$\$",
        r"^L[a-z/]+;$",
        r"^android\.",
        r"^androidx\.",
        r"^java\.",
        r"^kotlin\.",
        # Layout / resource references
        r"^res/",
        r"^@[a-z]+/",
        r"^content://",
    }

    # Security keywords - contextual signal for high-entropy strings
    SECURITY_KEYWORDS = {
        "key",
        "secret",
        "token",
        "password",
        "pass",
        "pwd",
        "credential",
        "auth",
        "api",
        "apikey",
        "api_key",
        "aws",
        "firebase",
        "google",
        "promo",
        "code",
        "bearer",
        "access",
        "private",
        "signature",
        "encrypt",
        "decrypt",
        "cipher",
        "hmac",
        # AndroGoat specific
        "goat",
        "admin",
        "user",
        "database",
        "db_pass",
        "master",
        "connection",
    }

    # Known API key patterns with auto-detect capability
    KNOWN_API_PATTERNS = {
        "AWS Access Key": (r"\bAKIA[0-9A-Z]{16}\b", True, "Critical"),
        "AWS Secret Key": (
            r"(?i)(?:aws.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]",
            False,
            "Critical",
        ),
        "Google API Key": (r"\bAIza[0-9A-Za-z\-_]{35}\b", True, "Critical"),
        "GitHub Token": (r"\bghp_[0-9a-zA-Z]{36}\b", True, "Critical"),
        "GitHub OAuth": (r"\bgho_[0-9a-zA-Z]{36}\b", True, "Critical"),
        "Stripe Live Key": (r"\bsk_live_[0-9a-zA-Z]{24,}\b", True, "Critical"),
        "Stripe Publishable": (
            r"\bpk_live_[0-9a-zA-Z]{24,}\b",
            True,
            "High",
        ),
        "Firebase Server Key": (
            r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",
            True,
            "Critical",
        ),
        "Slack Token": (r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b", True, "Critical"),
        "Twilio API Key": (r"\bSK[0-9a-fA-F]{32}\b", True, "High"),
        "SendGrid API Key": (r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b", True, "Critical"),
        "Heroku API Key": (
            r"(?i)heroku.{0,20}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            False,
            "High",
        ),
        "Generic Bearer Token": (
            r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]{20,}",
            True,
            "High",
        ),
        "Private Key Header": (
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            True,
            "Critical",
        ),
        "Base64 Encoded Key (long)": (
            r"(?i)(?:key|secret|token|password)\s*[=:]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?",
            False,
            "High",
        ),
    }

    # Password assignment patterns (catches hardcoded credentials)
    PASSWORD_PATTERNS = [
        r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\'][^"\']{4,}["\']',
        r'(?i)(?:password|passwd|pwd|pass)\s*=\s*["\'][^"\']{4,}["\']',
        r"(?i)setPassword\s*\(\s*[\"'][^\"']{4,}[\"']",
        r'(?i)(?:db_pass|dbpass|db_password)\s*[=:]\s*["\'][^"\']+["\']',
        r'(?i)(?:username|user)\s*[=:]\s*["\'][^"\']{3,}["\'].*(?:password|pwd|pass)\s*[=:]\s*["\'][^"\']+["\']',
    ]

    @property
    def rule_id(self) -> str:
        return "HARDCODED_SECRET"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen_values: Set[str] = set()

        try:
            for string in data.strings:
                # Quick length filter - lowered for promo codes and short passwords
                if len(string.value) < 8:
                    continue

                value_key = string.value[:100]
                if value_key in seen_values:
                    continue

                # Check all detection methods
                detection = self._detect_secret(string)
                if detection is None:
                    continue

                pattern_name, severity = detection

                # Confidence gate
                if hasattr(string, "confidence") and string.confidence < 0.4:
                    continue

                seen_values.add(value_key)

                finding = Finding(
                    title=f"Hardcoded Secret Detected: {pattern_name}",
                    description=(
                        f"Potential hardcoded secret found. "
                        f"Detection: {pattern_name}. "
                        f"Length: {string.length}, "
                        f"Entropy: {round(string.entropy, 2) if string.entropy else 'N/A'}. "
                        f"AndroGoat contains hardcoded AWS keys, promo codes, database "
                        f"passwords, and plaintext credentials in source code."
                    ),
                    owasp_category=OWASP_M1,
                    severity=severity,
                    remediation=(
                        "Remove all hardcoded secrets from source code. "
                        "Use Android Keystore for cryptographic keys. "
                        "Fetch API keys and tokens from a secure backend at runtime. "
                        "Use environment variables or encrypted config files for build-time secrets. "
                        "Rotate any exposed credentials immediately."
                    ),
                    affected_component=string.dex_file,
                    evidence={
                        "value": (
                            string.value[:80] + "..."
                            if len(string.value) > 80
                            else string.value
                        ),
                        "length": string.length,
                        "entropy": (
                            round(string.entropy, 2) if string.entropy else None
                        ),
                        "pattern": pattern_name,
                        "confidence": (
                            round(string.confidence, 2)
                            if hasattr(string, "confidence")
                            else None
                        ),
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings

    def _detect_secret(self, string) -> Optional[Tuple[str, str]]:
        """
        Multi-layered secret detection. Returns (pattern_name, severity) or None.
        """
        value = string.value

        # Blocklist check first
        for pattern in self.FALSE_POSITIVE_BLOCKLIST:
            if re.search(pattern, value, re.IGNORECASE):
                return None

        # Layer 1: Known API key patterns (highest confidence)
        for pattern_name, (regex, high_confidence, severity) in self.KNOWN_API_PATTERNS.items():
            match = re.search(regex, value)
            if match:
                if high_confidence:
                    return (pattern_name, severity)
                # Low confidence patterns need security context
                if self._has_security_context(value):
                    return (pattern_name, severity)

        # Layer 2: Hardcoded password patterns
        for pwd_pattern in self.PASSWORD_PATTERNS:
            if re.search(pwd_pattern, value):
                return ("Hardcoded Password/Credential", "Critical")

        # Layer 3: High entropy strings with security context
        if (
            string.is_high_entropy
            and string.entropy
            and string.entropy > 4.0
            and len(value) >= 16
        ):
            if self._has_security_context(value) and self._has_mixed_case_and_numbers(value):
                return ("High Entropy Secret", "High")

        # Layer 4: Scope filter pre-classified
        if hasattr(string, "looks_like_api_key") and string.looks_like_api_key:
            if self._has_security_context(value) or len(value) >= 32:
                return ("Potential API Key", "High")

        # Layer 5: Promo code / activation key patterns
        if self._looks_like_promo_or_activation(value):
            return ("Hardcoded Promo/Activation Code", "Medium")

        return None

    def _has_security_context(self, value: str) -> bool:
        """Check for security-relevant keywords in the string or surrounding context."""
        value_lower = value.lower()
        return any(kw in value_lower for kw in self.SECURITY_KEYWORDS)

    @staticmethod
    def _has_mixed_case_and_numbers(value: str) -> bool:
        """Check mixed character types indicating a generated secret."""
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        return sum([has_upper, has_lower, has_digit]) >= 2

    @staticmethod
    def _looks_like_promo_or_activation(value: str) -> bool:
        """Detect promo codes, activation keys, license keys."""
        # Pattern: XXXX-XXXX-XXXX or similar segmented keys
        if re.match(r"^[A-Z0-9]{4,6}(-[A-Z0-9]{4,6}){2,}$", value):
            return True
        # Pattern: promo/coupon/discount + alphanumeric
        if re.search(r"(?i)(promo|coupon|discount|activate|license|serial)\s*[=:]\s*\S+", value):
            return True
        return False


# ============================================================================
# RULE 7: Weak Cryptography
# ============================================================================
class WeakCryptoAlgorithmRule(BaseRule):
    """
    Detect weak/broken cryptographic algorithms.
    
    AndroGoat uses: ECB mode, DES, weak hashing (MD5, SHA1),
    RSA without proper padding, hardcoded crypto keys.
    
    Category: Cryptographic Issues - Broken Cryptography
    """

    WEAK_ALGORITHMS = {
        "ECB": (
            "ECB mode leaks patterns in ciphertext - identical plaintext blocks "
            "produce identical ciphertext blocks, revealing data structure"
        ),
        "DES": "DES uses 56-bit keys, breakable in hours with modern hardware",
        "3DES": "Triple DES (3DES/TDEA) is deprecated by NIST as of 2023",
        "DESEDE": "DESede (Triple DES) is deprecated by NIST as of 2023",
        "MD5": "MD5 has known collision attacks, unsuitable for any security use",
        "SHA1": "SHA-1 has demonstrated collision attacks (SHAttered, 2017)",
        "SHA-1": "SHA-1 has demonstrated collision attacks (SHAttered, 2017)",
        "RC4": "RC4 has systematic biases making it cryptographically broken",
        "RC2": "RC2 has known weaknesses and short effective key lengths",
        "ARCFOUR": "ARCFOUR (RC4) has systematic biases and is broken",
        "BLOWFISH": "Blowfish uses 64-bit blocks vulnerable to birthday attacks",
        "RSA/NONE/NOPADDING": "RSA without padding is deterministic and insecure",
        "RSA/ECB/NOPADDING": "RSA without padding is deterministic and insecure",
        "RSA/ECB": "RSA with ECB label (Java default) lacks proper padding",
        "AES/ECB": "AES with ECB mode leaks plaintext patterns",
        "PBKDF1": "PBKDF1 is obsolete, use PBKDF2 or Argon2",
    }

    # Weak key size detection
    WEAK_KEY_SIZES = {
        "RSA": 1024,   # Minimum should be 2048
        "AES": 64,     # Minimum should be 128
        "DH": 1024,    # Minimum should be 2048
    }

    @property
    def rule_id(self) -> str:
        return "WEAK_CRYPTO_ALGORITHM"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            for crypto_api in data.crypto_apis:
                for param in crypto_api.parameters:
                    param_upper = param.upper()

                    for algo, reason in self.WEAK_ALGORITHMS.items():
                        if algo.upper() in param_upper:
                            key = f"{algo}|{crypto_api.api_called}"
                            if key in seen:
                                continue
                            seen.add(key)

                            # Higher severity for encryption vs hashing
                            severity = "High"
                            if algo in ("MD5", "SHA1", "SHA-1"):
                                severity = "Medium"
                            if "ECB" in algo and "AES" in param_upper:
                                severity = "High"  # AES/ECB is especially bad
                            if algo in ("DES", "RC4", "ARCFOUR"):
                                severity = "Critical"

                            finding = Finding(
                                title=f"Weak Cryptography: {algo}",
                                description=(
                                    f"Detected use of weak algorithm '{algo}'. {reason}. "
                                    f"AndroGoat intentionally uses broken cryptography "
                                    f"to demonstrate the risk."
                                ),
                                owasp_category=OWASP_M10,
                                severity=severity,
                                remediation=(
                                    "Use AES-256-GCM for symmetric encryption. "
                                    "Use SHA-256 or SHA-3 for hashing. "
                                    "Use RSA-2048+ with OAEP padding or ECDSA for asymmetric. "
                                    "Use PBKDF2 (100k+ iterations) or Argon2 for password hashing."
                                ),
                                affected_component=crypto_api.api_called,
                                evidence={
                                    "api": crypto_api.api_called,
                                    "parameters": crypto_api.parameters,
                                    "algorithm": algo,
                                },
                                rule_id=self.rule_id,
                            )
                            findings.append(finding)
                            break  # One finding per param

            # Check for weak key sizes in KeyGenerator/KeyPairGenerator
            findings.extend(self._check_weak_key_sizes(data, seen))

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings

    def _check_weak_key_sizes(
        self, data: AnalysisReadyAPK, seen: Set[str]
    ) -> List[Finding]:
        """Detect weak key sizes in key generation APIs."""
        findings = []
        try:
            for crypto_api in data.crypto_apis:
                api_lower = crypto_api.api_called.lower()
                if "keygenerator" in api_lower or "keypairgenerator" in api_lower:
                    for param in crypto_api.parameters:
                        # Look for numeric key sizes
                        size_match = re.search(r"\b(\d{2,4})\b", param)
                        if size_match:
                            size = int(size_match.group(1))
                            for algo, min_size in self.WEAK_KEY_SIZES.items():
                                if algo.lower() in api_lower or algo.lower() in param.lower():
                                    if size <= min_size:
                                        key = f"WEAK_KEY_{algo}_{size}"
                                        if key in seen:
                                            continue
                                        seen.add(key)
                                        findings.append(
                                            Finding(
                                                title=f"Weak Key Size: {algo} {size}-bit",
                                                description=(
                                                    f"{algo} key size of {size} bits is insufficient. "
                                                    f"Minimum recommended: {min_size * 2} bits."
                                                ),
                                                owasp_category=OWASP_M10,
                                                severity="High",
                                                remediation=f"Use {algo} with at least {min_size * 2}-bit keys.",
                                                affected_component=crypto_api.api_called,
                                                evidence={
                                                    "algorithm": algo,
                                                    "key_size": size,
                                                    "minimum_recommended": min_size * 2,
                                                },
                                                rule_id=self.rule_id,
                                            )
                                        )
        except Exception:
            pass
        return findings


# ============================================================================
# RULE 8: WebView JavaScript Enabled
# ============================================================================
class WebViewJavaScriptEnabledRule(BaseRule):
    """
    Detect WebView with JavaScript enabled.
    
    AndroGoat vulnerability: WebView vulnerabilities including XSS attacks
    through JavaScript-enabled WebViews loading untrusted content.
    
    Category: Input Validation - Cross-Site Scripting (XSS)
    """

    @property
    def rule_id(self) -> str:
        return "WEBVIEW_JAVASCRIPT_ENABLED"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            for webview_api in data.webview_apis:
                if "setJavaScriptEnabled" in webview_api.api_called:
                    if webview_api.method_signature in seen:
                        continue
                    seen.add(webview_api.method_signature)

                    enabled = self._is_javascript_enabled(
                        webview_api.method_signature
                    )

                    if enabled is True:
                        severity = "High"
                        desc = (
                            "JavaScript explicitly enabled in WebView (true). "
                            "This enables XSS attacks if the WebView loads any "
                            "untrusted or user-controlled content."
                        )
                    elif enabled is False:
                        continue  # JS disabled, no finding
                    else:
                        severity = "Medium"
                        desc = (
                            "setJavaScriptEnabled called with indeterminate parameter. "
                            "Verify JavaScript is not enabled for untrusted content."
                        )

                    finding = Finding(
                        title="WebView JavaScript Enabled - XSS Risk",
                        description=(
                            f"{desc} AndroGoat demonstrates XSS vulnerabilities "
                            f"in WebViews where user input is reflected without sanitization."
                        ),
                        owasp_category=OWASP_M4,
                        severity=severity,
                        remediation=(
                            "Disable JavaScript unless strictly necessary. "
                            "If needed, implement Content Security Policy (CSP). "
                            "Sanitize all user input before rendering in WebView. "
                            "Use WebViewClient.shouldOverrideUrlLoading() to validate URLs."
                        ),
                        affected_component=webview_api.api_called,
                        evidence={
                            "api": webview_api.api_called,
                            "js_enabled": enabled,
                        },
                        rule_id=self.rule_id,
                    )
                    findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings

    @staticmethod
    def _is_javascript_enabled(sig: str) -> Optional[bool]:
        """Determine if JavaScript is enabled from method signature."""
        if re.search(r"\btrue\b", sig.lower()):
            return True
        if re.search(r"\bfalse\b", sig.lower()):
            return False
        if re.search(r"const[^,]*,\s*0x1\b", sig):
            return True
        if re.search(r"const[^,]*,\s*0x0\b", sig):
            return False
        return None


# ============================================================================
# RULE 9: SQL Injection Risk
# ============================================================================
class SQLInjectionRiskRule(BaseRule):
    """
    Detect SQL injection vulnerabilities.
    
    AndroGoat vulnerability: SQL injection in database queries where user input
    is concatenated directly into SQL strings without parameterization.
    
    Category: Input Validation - SQL Injection
    """

    SQL_KEYWORDS = [
        r"\bSELECT\s+",
        r"\bINSERT\s+INTO\b",
        r"\bUPDATE\s+\w+\s+SET\b",
        r"\bDELETE\s+FROM\b",
        r"\bCREATE\s+TABLE\b",
        r"\bDROP\s+TABLE\b",
        r"\bWHERE\s+",
        r"\bUNION\s+",
        r"\bORDER\s+BY\b",
        r"\bGROUP\s+BY\b",
        r"\bHAVING\s+",
        r"\bALTER\s+TABLE\b",
    ]

    RAW_QUERY_METHODS = {
        "rawQuery",
        "execSQL",
        "rawQueryWithFactory",
        "compileStatement",
    }

    CONTENT_RESOLVER_METHODS = {
        "query",
        "delete",
        "update",
    }

    @property
    def rule_id(self) -> str:
        return "SQL_INJECTION_RISK"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen_strings: Set[str] = set()
        seen_apis: Set[str] = set()

        try:
            # Type 1: SQL strings with concatenation indicators
            for string in data.strings:
                if len(string.value) < 10:
                    continue
                value_key = string.value[:80]
                if value_key in seen_strings:
                    continue

                upper = string.value.upper()

                # Must have SQL keyword
                has_sql = any(re.search(p, upper) for p in self.SQL_KEYWORDS)
                if not has_sql:
                    continue

                # Skip JSON/serialization artifacts
                if self._is_json_like(string.value):
                    continue

                # Check for dangerous concatenation patterns
                concat_indicators = self._get_concat_indicators(string.value)
                if concat_indicators:
                    seen_strings.add(value_key)

                    finding = Finding(
                        title="SQL Injection Risk - String Concatenation",
                        description=(
                            "SQL query constructed with string concatenation detected. "
                            "User input may flow into the query without sanitization, "
                            "enabling SQL injection attacks (data theft, modification, "
                            "authentication bypass). AndroGoat demonstrates this with "
                            "login bypass and data extraction."
                        ),
                        owasp_category=OWASP_M4,
                        severity="High",
                        remediation=(
                            "Use parameterized queries with '?' placeholders and selection "
                            "args array. Example: db.rawQuery(\"SELECT * FROM users WHERE "
                            "name=?\", new String[]{userInput}). Never concatenate user "
                            "input into SQL strings."
                        ),
                        affected_component=string.dex_file,
                        evidence={
                            "sql_fragment": string.value[:150],
                            "concat_indicators": concat_indicators,
                        },
                        rule_id=self.rule_id,
                    )
                    findings.append(finding)

            # Type 2: Raw query method usage
            for api in data.storage_apis:
                api_name = api.api_called.split(".")[-1] if "." in api.api_called else api.api_called
                if api_name in self.RAW_QUERY_METHODS:
                    if api.method_signature in seen_apis:
                        continue
                    seen_apis.add(api.method_signature)

                    finding = Finding(
                        title=f"Raw SQL Query Method: {api_name}",
                        description=(
                            f"App uses {api.api_called} which executes raw SQL. "
                            f"If parameters are not properly bound, this is vulnerable "
                            f"to SQL injection."
                        ),
                        owasp_category=OWASP_M4,
                        severity="Medium",
                        remediation=(
                            "Always use the selection args parameter for user input. "
                            "Prefer ContentProvider or Room DAO over raw queries. "
                            "Audit all rawQuery/execSQL calls for injection."
                        ),
                        affected_component=api.api_called,
                        evidence={
                            "api": api.api_called,
                            "signature": api.method_signature,
                        },
                        rule_id=self.rule_id,
                    )
                    findings.append(finding)

            # Type 3: ContentResolver with potential injection
            for api in data.storage_apis:
                api_name = api.api_called.split(".")[-1] if "." in api.api_called else api.api_called
                if api_name in self.CONTENT_RESOLVER_METHODS and "ContentResolver" in api.api_called:
                    if api.method_signature in seen_apis:
                        continue
                    seen_apis.add(api.method_signature)

                    finding = Finding(
                        title=f"ContentResolver Query - Potential Injection",
                        description=(
                            f"App uses ContentResolver.{api_name}(). If the selection "
                            f"parameter includes unsanitized user input, this is vulnerable "
                            f"to injection attacks on content providers."
                        ),
                        owasp_category=OWASP_M4,
                        severity="Medium",
                        remediation=(
                            "Use selection args (selectionArgs parameter) instead of "
                            "concatenating values into the selection string."
                        ),
                        affected_component=api.api_called,
                        evidence={"api": api.api_called},
                        rule_id=self.rule_id,
                    )
                    findings.append(finding)

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings

    @staticmethod
    def _is_json_like(value: str) -> bool:
        """Detect JSON/serialization to avoid false positives."""
        if value.startswith("{") and "Landroid/" in value:
            return True
        if value.startswith("~~~{"):
            return True
        if value.startswith("[L") and value.endswith(";]"):
            return True
        special = sum(1 for c in value if c in '{}[]":,')
        if len(value) > 0 and special > len(value) * 0.25:
            return True
        return False

    @staticmethod
    def _get_concat_indicators(value: str) -> List[str]:
        """Detect concatenation patterns that indicate dynamic SQL construction."""
        indicators = []
        if " + " in value:
            indicators.append("string_plus_concat")
        if " || " in value:
            indicators.append("sql_concat_operator")
        if re.search(r"%[sd]", value):
            indicators.append("format_string")
        if "append" in value.lower():
            indicators.append("string_builder_append")
        if re.search(r"\$\{", value):
            indicators.append("string_template")
        if re.search(r"'\s*\+\s*", value):
            indicators.append("quoted_concat")
        return indicators


# ============================================================================
# RULE 10: Insecure Logging
# ============================================================================
class InsecureLoggingRule(BaseRule):
    """
    Detect insecure logging of sensitive data.
    
    AndroGoat vulnerability: Credentials and sensitive information written
    to system logs accessible via logcat by any app (pre-Android 4.1)
    or via ADB.
    
    Category: Information Storage - Insecure Logging
    """

    SENSITIVE_KEYWORDS = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "credential",
        "auth",
        "bearer",
        "session",
        "cookie",
        "ssn",
        "credit",
        "cvv",
        "pin",
        "api_key",
        "apikey",
        "private_key",
        "encryption",
        # AndroGoat specific
        "login",
        "user",
        "admin",
        "key",
        "otp",
        "mfa",
    }

    LOG_METHODS = {
        "Log.d",
        "Log.v",
        "Log.i",
        "Log.w",
        "Log.e",
        "Log.wtf",
        "println",
        "print",
        "System.out",
        "System.err",
        "Logger.",
        "Timber.",
    }

    @property
    def rule_id(self) -> str:
        return "INSECURE_LOGGING"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[tuple] = set()

        try:
            for string in data.strings:
                value_lower = string.value.lower()

                # Check for log method reference
                has_log = any(log in string.value for log in self.LOG_METHODS)
                if not has_log:
                    continue

                # Check for sensitive keywords
                sensitive = [kw for kw in self.SENSITIVE_KEYWORDS if kw in value_lower]
                if not sensitive:
                    continue

                key = (tuple(sorted(sensitive[:3])), string.value[:80])
                if key in seen:
                    continue
                seen.add(key)

                # Higher severity for credential-related logging
                severity = "Medium"
                if any(kw in sensitive for kw in ("password", "passwd", "pwd", "secret", "token", "credential")):
                    severity = "High"

                finding = Finding(
                    title="Insecure Logging of Sensitive Data",
                    description=(
                        f"Log statement may expose sensitive data to logcat. "
                        f"Sensitive keywords detected: {', '.join(sensitive[:5])}. "
                        f"AndroGoat logs credentials accessible via: adb logcat | grep <tag>. "
                        f"Any app with READ_LOGS permission (or ADB access) can read these."
                    ),
                    owasp_category=OWASP_M9,
                    severity=severity,
                    remediation=(
                        "Remove all sensitive data from log statements. "
                        "Use ProGuard/R8 to strip Log.d/Log.v calls in release builds. "
                        "Implement a custom logger that redacts sensitive fields. "
                        "Never log passwords, tokens, PII, or financial data."
                    ),
                    affected_component=string.dex_file,
                    evidence={
                        "log_fragment": string.value[:150],
                        "sensitive_keywords": sensitive[:5],
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 11: Dynamic Code Loading
# ============================================================================
class DynamicCodeLoadingRule(BaseRule):
    """
    Detect dynamic code loading (DexClassLoader, PathClassLoader, etc.).
    
    Category: Binary Protection
    """

    @property
    def rule_id(self) -> str:
        return "DYNAMIC_CODE_LOADING"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            if data.dynamic_code_apis:
                apis_used = list(set(api.api_called for api in data.dynamic_code_apis))

                finding = Finding(
                    title="Dynamic Code Loading Detected",
                    description=(
                        f"App loads code dynamically ({len(data.dynamic_code_apis)} call sites). "
                        f"APIs: {', '.join(apis_used[:5])}. "
                        f"Dynamic code loading can bypass static analysis, load malicious "
                        f"payloads at runtime, and evade app store scanning."
                    ),
                    owasp_category=OWASP_M7,
                    severity="Medium",
                    remediation=(
                        "Verify code integrity/signatures before loading. "
                        "Load only from trusted sources (never from SD card or network without "
                        "verification). Avoid DexClassLoader if possible. "
                        "Use Google Play Feature Delivery for modular code."
                    ),
                    affected_component="Dynamic Code Loading",
                    evidence={
                        "call_count": len(data.dynamic_code_apis),
                        "apis": apis_used[:10],
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 12: Network Security Config Issues
# ============================================================================
class InsecureNetworkSecurityConfigRule(BaseRule):
    """
    Detect network security configuration issues.
    
    AndroGoat vulnerability: Misconfigured network security config allowing
    cleartext traffic, missing certificate pinning, and custom trust anchors.
    
    Category: Network Communication - Misconfigured Network Security Config
    """

    @property
    def rule_id(self) -> str:
        return "INSECURE_NETWORK_CONFIG"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            if not data.network_security_config:
                # No network security config at all - report if app targets API < 28
                if hasattr(data, "target_sdk") and data.target_sdk and data.target_sdk < 28:
                    findings.append(
                        Finding(
                            title="Missing Network Security Config (Pre-API 28)",
                            description=(
                                "No network_security_config.xml found and app targets "
                                f"SDK {data.target_sdk} (< 28). Cleartext traffic is allowed "
                                "by default on older API levels."
                            ),
                            owasp_category=OWASP_M5,
                            severity="Medium",
                            remediation=(
                                "Add a network_security_config.xml that explicitly disables "
                                "cleartext traffic and implements certificate pinning."
                            ),
                            affected_component="AndroidManifest.xml",
                            evidence={"target_sdk": data.target_sdk},
                            rule_id=self.rule_id,
                        )
                    )
                return findings

            try:
                root = ET.fromstring(data.network_security_config)
            except ET.ParseError as e:
                self._log_error(f"XML parse error: {str(e)}")
                return findings

            # Check cleartext traffic permissions
            findings.extend(self._check_cleartext(root))

            # Check certificate pinning
            pin_finding = self._check_pinning(root)
            if pin_finding:
                findings.append(pin_finding)

            # Check trust anchors
            findings.extend(self._check_trust_anchors(root))

            # Check expired pin sets
            findings.extend(self._check_pin_expiration(root))

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings

    def _check_cleartext(self, root: ET.Element) -> List[Finding]:
        """Check for cleartext traffic permissions."""
        findings = []

        # Base config
        base = root.find(".//base-config")
        if base is not None:
            if base.get("cleartextTrafficPermitted", "").lower() == "true":
                findings.append(
                    Finding(
                        title="Network Config Allows Cleartext Globally",
                        description=(
                            "Base config permits HTTP for all domains. All network "
                            "traffic can be intercepted without TLS protection."
                        ),
                        owasp_category=OWASP_M5,
                        severity="Critical",
                        remediation='Set cleartextTrafficPermitted="false" in base-config.',
                        affected_component="network_security_config.xml",
                        evidence={"type": "base-config", "cleartext": True},
                        rule_id=self.rule_id,
                    )
                )

        # Domain-specific configs
        for domain_config in root.findall(".//domain-config"):
            if (
                domain_config.get("cleartextTrafficPermitted", "").lower()
                == "true"
            ):
                domains = [
                    d.text
                    for d in domain_config.findall(".//domain")
                    if d.text
                ]
                findings.append(
                    Finding(
                        title="Network Config Allows Cleartext for Specific Domains",
                        description=(
                            f"HTTP traffic allowed for domains: {', '.join(domains[:5])}. "
                            f"Traffic to these domains can be intercepted."
                        ),
                        owasp_category=OWASP_M5,
                        severity="High",
                        remediation=(
                            "Remove cleartextTrafficPermitted or set to false. "
                            "Use HTTPS for all domains."
                        ),
                        affected_component="network_security_config.xml",
                        evidence={"domains": domains},
                        rule_id=self.rule_id,
                    )
                )

        return findings

    def _check_pinning(self, root: ET.Element) -> Optional[Finding]:
        """Check for missing certificate pinning."""
        pin_sets = root.findall(".//pin-set")
        domain_configs = root.findall(".//domain-config")

        if domain_configs and not pin_sets:
            return Finding(
                title="Missing Certificate Pinning",
                description=(
                    "Network security config defines domain configurations but no "
                    "certificate pinning (pin-set). Without pinning, MITM attacks "
                    "using rogue CA certificates are possible. AndroGoat demonstrates "
                    "this weakness with both OkHttp3 and native implementations."
                ),
                owasp_category=OWASP_M5,
                severity="Medium",
                remediation=(
                    "Implement <pin-set> with at least one backup pin for each domain. "
                    "Pin the public key hash (SPKI) of intermediate or leaf certificates. "
                    "Set appropriate expiration dates and have a rotation plan."
                ),
                affected_component="network_security_config.xml",
                evidence={
                    "domain_configs": len(domain_configs),
                    "pin_sets": 0,
                },
                rule_id=self.rule_id,
            )
        return None

    def _check_trust_anchors(self, root: ET.Element) -> List[Finding]:
        """Check for user-installed certificate trust (allows proxy interception)."""
        findings = []

        for trust_anchors in root.findall(".//trust-anchors"):
            for cert in trust_anchors.findall(".//certificates"):
                src = cert.get("src", "")
                if src == "user":
                    findings.append(
                        Finding(
                            title="User Certificates Trusted",
                            description=(
                                "Network config trusts user-installed certificates. "
                                "This allows proxy tools (Burp, mitmproxy) to intercept "
                                "all HTTPS traffic without certificate pinning bypass."
                            ),
                            owasp_category=OWASP_M5,
                            severity="Medium",
                            remediation=(
                                "Remove user certificate trust for production builds. "
                                "Only trust system certificates: <certificates src=\"system\" />"
                            ),
                            affected_component="network_security_config.xml",
                            evidence={"trust_src": "user"},
                            rule_id=self.rule_id,
                        )
                    )

        return findings

    def _check_pin_expiration(self, root: ET.Element) -> List[Finding]:
        """Check for pin sets without expiration (maintenance risk)."""
        findings = []
        for pin_set in root.findall(".//pin-set"):
            expiration = pin_set.get("expiration")
            if not expiration:
                findings.append(
                    Finding(
                        title="Certificate Pin Without Expiration",
                        description=(
                            "Pin-set has no expiration date. If the pinned certificate "
                            "rotates, the app will fail to connect without an update."
                        ),
                        owasp_category=OWASP_M5,
                        severity="Low",
                        remediation=(
                            "Add expiration attribute to pin-set and include backup pins. "
                            "Plan certificate rotation strategy."
                        ),
                        affected_component="network_security_config.xml",
                        evidence={"expiration": None},
                        rule_id=self.rule_id,
                    )
                )
        return findings


# ============================================================================
# RULE 13: Static IV in Cryptography
# ============================================================================
class StaticIVRule(BaseRule):
    """
    Detect hardcoded/static Initialization Vectors in crypto operations.
    
    AndroGoat vulnerability: Hardcoded cryptographic keys and static IVs
    making encryption deterministic and vulnerable.
    
    Category: Cryptographic Issues
    """

    @property
    def rule_id(self) -> str:
        return "STATIC_IV"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            for api in data.crypto_apis:
                if "IvParameterSpec" not in api.api_called:
                    continue

                key = f"{api.api_called}|{api.method_signature}"
                if key in seen:
                    continue

                for param in api.parameters:
                    if self._is_hardcoded_iv(param):
                        seen.add(key)

                        finding = Finding(
                            title="Static/Hardcoded Initialization Vector (IV)",
                            description=(
                                "Hardcoded IV detected in IvParameterSpec construction. "
                                "Reusing IVs with the same key allows attackers to detect "
                                "repeated plaintexts (CBC mode) or completely break "
                                "confidentiality (CTR/GCM modes). AndroGoat uses static "
                                "IVs intentionally to demonstrate this weakness."
                            ),
                            owasp_category=OWASP_M10,
                            severity="High",
                            remediation=(
                                "Generate a fresh random IV with SecureRandom for every "
                                "encryption operation. Prepend the IV to the ciphertext "
                                "for transmission. Never hardcode or reuse IVs."
                            ),
                            affected_component=api.api_called,
                            evidence={
                                "api": api.api_called,
                                "parameter_hint": param[:60],
                            },
                            rule_id=self.rule_id,
                        )
                        findings.append(finding)
                        break
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings

    @staticmethod
    def _is_hardcoded_iv(value: str) -> bool:
        """Check if value looks like a hardcoded IV."""
        if len(value) < 8:
            return False

        # Hex string (16+ hex chars for 8+ byte IV)
        if re.match(r"^[0-9a-fA-F]{16,}$", value):
            return True

        # Base64 encoded (16+ chars)
        if re.match(r"^[A-Za-z0-9+/]{12,}={0,2}$", value):
            if len(value) % 4 == 0 or value.endswith("="):
                return True

        # Hex notation array: 0x01, 0x02, ...
        if re.search(r"(0x[0-9a-fA-F]{2}[,\s]*){4,}", value):
            return True

        # Byte array literal: {1, 2, 3, ...}
        if re.match(r"^\{(\s*-?\d+\s*,?)+\}$", value):
            return True

        # Repeating/all-zero pattern
        if re.match(r"^(00|0)+$", value) and len(value) >= 16:
            return True

        # Short readable string used as IV (common mistake)
        if re.match(r"^[a-zA-Z0-9]{16,}$", value) and not " " in value:
            # Could be a hardcoded string used as IV like "1234567890123456"
            if re.match(r"^(\d)\1*$", value) or re.match(r"^(0123456789)+", value):
                return True

        return False


# ============================================================================
# RULE 14: Insecure SharedPreferences Storage
# ============================================================================
class InsecureSharedPreferencesRule(BaseRule):
    """
    Detect SharedPreferences usage for sensitive data storage.
    
    AndroGoat vulnerability:
    - Part 1: Plaintext credentials stored in users.xml
    - Part 2: Game scores stored insecurely in score.xml
    
    Category: Information Storage - SharedPreferences
    """

    SENSITIVE_PREF_NAMES = {
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "credential",
        "auth",
        "session",
        "cookie",
        "user",
        "login",
        "key",
        "pin",
        "otp",
        "score",   # AndroGoat score.xml
        "users",   # AndroGoat users.xml
    }

    @property
    def rule_id(self) -> str:
        return "INSECURE_SHARED_PREFERENCES"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        sp_detected = False

        try:
            # Check storage APIs for SharedPreferences
            for api in data.storage_apis:
                if "SharedPreferences" in api.api_called:
                    if api.method_signature in seen:
                        continue
                    seen.add(api.method_signature)

                    if not sp_detected:
                        sp_detected = True
                        finding = Finding(
                            title="SharedPreferences Used for Data Storage",
                            description=(
                                "App uses SharedPreferences which stores data as plaintext XML "
                                "in /data/data/<package>/shared_prefs/. If storing sensitive data "
                                "(passwords, tokens, PII), it is vulnerable to extraction via "
                                "adb backup, root access, or device theft. "
                                "AndroGoat stores plaintext credentials in users.xml and "
                                "game scores in score.xml, both extractable."
                            ),
                            owasp_category=OWASP_M9,
                            severity="Medium",
                            remediation=(
                                "Use EncryptedSharedPreferences from Jetpack Security library. "
                                "Never store plaintext passwords or tokens. "
                                "Example: EncryptedSharedPreferences.create(context, filename, "
                                "masterKey, AES256_SIV, AES256_GCM)"
                            ),
                            affected_component=api.api_called,
                            evidence={"api": api.api_called},
                            rule_id=self.rule_id,
                        )
                        findings.append(finding)

                    # Check for sensitive preference names in parameters
                    for param in api.parameters if hasattr(api, "parameters") else []:
                        param_lower = param.lower()
                        matched_sensitive = [
                            kw for kw in self.SENSITIVE_PREF_NAMES if kw in param_lower
                        ]
                        if matched_sensitive:
                            pref_key = f"sensitive_pref_{param[:40]}"
                            if pref_key not in seen:
                                seen.add(pref_key)
                                findings.append(
                                    Finding(
                                        title=f"Sensitive Data in SharedPreferences: {param[:40]}",
                                        description=(
                                            f"SharedPreferences key/file name contains sensitive "
                                            f"keyword(s): {', '.join(matched_sensitive)}. "
                                            f"This data is stored in plaintext XML."
                                        ),
                                        owasp_category=OWASP_M9,
                                        severity="High",
                                        remediation=(
                                            "Use EncryptedSharedPreferences or Android Keystore "
                                            "to protect this sensitive data."
                                        ),
                                        affected_component=api.api_called,
                                        evidence={
                                            "preference_key": param[:60],
                                            "sensitive_keywords": matched_sensitive,
                                        },
                                        rule_id=self.rule_id,
                                    )
                                )

            # Also check strings for SharedPreferences file names
            if not sp_detected:
                for string in data.strings:
                    if "getSharedPreferences" in string.value or "SharedPreferences" in string.value:
                        findings.append(
                            Finding(
                                title="SharedPreferences Reference Detected",
                                description=(
                                    "Reference to SharedPreferences found in code. "
                                    "Verify no sensitive data is stored in plaintext."
                                ),
                                owasp_category=OWASP_M9,
                                severity="Low",
                                remediation="Use EncryptedSharedPreferences for sensitive data.",
                                affected_component=string.dex_file,
                                evidence={"reference": string.value[:100]},
                                rule_id=self.rule_id,
                            )
                        )
                        break

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 15: Insecure File Storage (Temp Files, SD Card, External Storage)
# ============================================================================
class InsecureFileStorageRule(BaseRule):
    """
    Detect insecure file I/O patterns.
    
    AndroGoat vulnerabilities:
    - Temp Files: Credentials stored in temporary files
    - SD Card: Files on external storage accessible to all apps
    
    Category: Information Storage - Temp Files & SD Card
    """

    EXTERNAL_STORAGE_APIS = [
        "getExternalStorageDirectory",
        "getExternalFilesDir",
        "getExternalCacheDir",
        "getExternalStoragePublicDirectory",
        "Environment.getExternalStorageDirectory",
    ]

    TEMP_FILE_APIS = [
        "createTempFile",
        "File.createTempFile",
        ".tmp",
        ".temp",
    ]

    INTERNAL_WRITE_APIS = [
        "FileOutputStream",
        "FileWriter",
        "openFileOutput",
        "BufferedWriter",
        "OutputStreamWriter",
    ]

    @property
    def rule_id(self) -> str:
        return "INSECURE_FILE_STORAGE"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            for api in data.storage_apis:
                api_call = api.api_called

                # External storage (SD card) - HIGH RISK
                if any(ext_api in api_call for ext_api in self.EXTERNAL_STORAGE_APIS):
                    if api.method_signature not in seen:
                        seen.add(api.method_signature)
                        findings.append(
                            Finding(
                                title="External Storage (SD Card) Usage",
                                description=(
                                    "App writes to external/SD card storage. Files on external "
                                    "storage are world-readable (pre-Android 10) and accessible "
                                    "to any app with READ_EXTERNAL_STORAGE permission. "
                                    "AndroGoat demonstrates storing sensitive files on SD card."
                                ),
                                owasp_category=OWASP_M9,
                                severity="High",
                                remediation=(
                                    "Use internal storage (getFilesDir()) with MODE_PRIVATE. "
                                    "If external storage is needed, encrypt all files. "
                                    "On Android 10+, use Scoped Storage."
                                ),
                                affected_component=api_call,
                                evidence={"api": api_call, "type": "external_storage"},
                                rule_id=self.rule_id,
                            )
                        )

                # Temp file creation
                if any(temp_api in api_call for temp_api in self.TEMP_FILE_APIS):
                    if api.method_signature not in seen:
                        seen.add(api.method_signature)
                        findings.append(
                            Finding(
                                title="Temporary File Creation",
                                description=(
                                    "App creates temporary files. If sensitive data (credentials, "
                                    "tokens, PII) is written to temp files, it may persist on "
                                    "disk and be recoverable. AndroGoat stores credentials "
                                    "in temporary files."
                                ),
                                owasp_category=OWASP_M9,
                                severity="Medium",
                                remediation=(
                                    "Avoid writing sensitive data to temp files. "
                                    "If necessary, encrypt the content and delete immediately "
                                    "after use with file.delete(). Use getCacheDir() for "
                                    "app-private temporary storage."
                                ),
                                affected_component=api_call,
                                evidence={"api": api_call, "type": "temp_file"},
                                rule_id=self.rule_id,
                            )
                        )

                # Internal file write (lower risk but worth noting)
                if any(write_api in api_call for write_api in self.INTERNAL_WRITE_APIS):
                    if api.method_signature not in seen:
                        seen.add(api.method_signature)
                        # Check for MODE_WORLD_READABLE/WRITABLE
                        has_world = any(
                            "MODE_WORLD" in p
                            for p in (api.parameters if hasattr(api, "parameters") else [])
                        )
                        if has_world:
                            findings.append(
                                Finding(
                                    title="World-Readable/Writable File",
                                    description=(
                                        "File created with MODE_WORLD_READABLE or "
                                        "MODE_WORLD_WRITABLE. Any app can access this file."
                                    ),
                                    owasp_category=OWASP_M9,
                                    severity="Critical",
                                    remediation="Use MODE_PRIVATE. Share via ContentProvider/FileProvider.",
                                    affected_component=api_call,
                                    evidence={"api": api_call, "mode": "WORLD_ACCESSIBLE"},
                                    rule_id=self.rule_id,
                                )
                            )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 16: Root/Emulator Detection (Binary Protection)
# ============================================================================
class WeakRootDetectionRule(BaseRule):
    """
    Detect root/emulator detection code and assess its strength.
    
    AndroGoat vulnerabilities:
    - Root Detection: Weak or bypassable root checks
    - Emulator Detection: Bypassable using Frida/objection
    
    Category: Binary Protection & Environment Detection
    """

    ROOT_INDICATORS = [
        "su",
        "Superuser",
        "supersu",
        "magisk",
        "root",
        "rooted",
        "which su",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/system/app/Superuser",
        "com.topjohnwu.magisk",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "RootBeer",
        "isRooted",
        "checkRoot",
        "detectRoot",
    ]

    EMULATOR_INDICATORS = [
        "emulator",
        "generic",
        "goldfish",
        "sdk_gphone",
        "Build.FINGERPRINT",
        "Build.MODEL",
        "Build.MANUFACTURER",
        "Build.BRAND",
        "Build.DEVICE",
        "Build.PRODUCT",
        "Build.HARDWARE",
        "google_sdk",
        "Genymotion",
        "Andy",
        "nox",
        "bluestacks",
        "isEmulator",
        "detectEmulator",
    ]

    @property
    def rule_id(self) -> str:
        return "WEAK_ROOT_EMULATOR_DETECTION"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        root_detected = False
        emulator_detected = False
        root_indicators_found: List[str] = []
        emulator_indicators_found: List[str] = []

        try:
            for string in data.strings:
                value_lower = string.value.lower()

                # Collect root detection indicators
                if not root_detected:
                    for ind in self.ROOT_INDICATORS:
                        if ind.lower() in value_lower:
                            root_indicators_found.append(ind)
                            if len(root_indicators_found) >= 3:
                                root_detected = True
                                break

                # Collect emulator detection indicators
                if not emulator_detected:
                    for ind in self.EMULATOR_INDICATORS:
                        if ind.lower() in value_lower:
                            emulator_indicators_found.append(ind)
                            if len(emulator_indicators_found) >= 3:
                                emulator_detected = True
                                break

                # Also detect single strong indicators
                if not root_detected and any(
                    strong in value_lower
                    for strong in ["/system/bin/su", "/system/xbin/su", "isrooted", "checkroot"]
                ):
                    root_detected = True
                    if not root_indicators_found:
                        root_indicators_found.append(string.value[:60])

                if not emulator_detected and any(
                    strong in value_lower
                    for strong in ["isemulator", "detectemulator", "goldfish"]
                ):
                    emulator_detected = True
                    if not emulator_indicators_found:
                        emulator_indicators_found.append(string.value[:60])

                if root_detected and emulator_detected:
                    break

            if root_detected:
                # Assess strength based on number of checks
                strength = "weak" if len(root_indicators_found) < 5 else "moderate"
                findings.append(
                    Finding(
                        title="Root Detection Implemented (Bypassable)",
                        description=(
                            f"App implements root detection with {strength} coverage "
                            f"({len(root_indicators_found)} indicators found). "
                            f"AndroGoat's root detection is bypassable with Frida: "
                            f"frida -U -l bypass-root.js <package>. "
                            f"Client-side root detection alone is insufficient."
                        ),
                        owasp_category=OWASP_M7,
                        severity="Low",
                        remediation=(
                            "Use multiple detection methods (file checks, binary checks, "
                            "property checks, mounted partitions). Implement server-side "
                            "device attestation (SafetyNet/Play Integrity API). "
                            "Use anti-tampering libraries (e.g., RootBeer with native checks). "
                            "Never rely solely on client-side detection."
                        ),
                        affected_component="Root Detection",
                        evidence={
                            "indicators_found": list(set(root_indicators_found))[:10],
                            "strength": strength,
                        },
                        rule_id=self.rule_id,
                    )
                )

            if emulator_detected:
                strength = "weak" if len(emulator_indicators_found) < 5 else "moderate"
                findings.append(
                    Finding(
                        title="Emulator Detection Implemented (Bypassable)",
                        description=(
                            f"App implements emulator detection with {strength} coverage "
                            f"({len(emulator_indicators_found)} indicators found). "
                            f"AndroGoat's emulator detection is bypassable with Frida/objection. "
                            f"Build property checks alone are trivially spoofed."
                        ),
                        owasp_category=OWASP_M7,
                        severity="Low",
                        remediation=(
                            "Combine multiple detection techniques: hardware sensors, "
                            "battery status, telephony, Bluetooth, camera, accelerometer. "
                            "Use Play Integrity API for server-side attestation. "
                            "Don't rely solely on Build properties."
                        ),
                        affected_component="Emulator Detection",
                        evidence={
                            "indicators_found": list(set(emulator_indicators_found))[:10],
                            "strength": strength,
                        },
                        rule_id=self.rule_id,
                    )
                )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 17: Insecure WebView Configuration
# ============================================================================
class InsecureWebViewConfigRule(BaseRule):
    """
    Detect insecure WebView configurations beyond JavaScript.
    
    AndroGoat vulnerability: Multiple WebView vulnerabilities including
    JavaScript interface exposure, file access, and XSS.
    
    Category: Input Validation - XSS and Binary Protection
    """

    @property
    def rule_id(self) -> str:
        return "INSECURE_WEBVIEW_CONFIG"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            dangerous_methods = {
                "setAllowFileAccess": {
                    "desc": "Allows the WebView to access file:// URLs, enabling local file reading",
                    "severity": "Medium",
                    "remediation": "Set setAllowFileAccess(false). Use WebViewAssetLoader instead.",
                },
                "setAllowFileAccessFromFileURLs": {
                    "desc": "Allows JavaScript in file:// URLs to access other file:// resources (SOP bypass)",
                    "severity": "High",
                    "remediation": "Set setAllowFileAccessFromFileURLs(false). Disabled by default on API 16+.",
                },
                "setAllowUniversalAccessFromFileURLs": {
                    "desc": "Allows JavaScript in file:// URLs to access any origin (complete SOP bypass)",
                    "severity": "Critical",
                    "remediation": "Set setAllowUniversalAccessFromFileURLs(false). Never enable this.",
                },
                "addJavascriptInterface": {
                    "desc": (
                        "Exposes Java/Kotlin object methods to JavaScript. On API < 17, "
                        "ALL public methods (including getClass()) are accessible, enabling "
                        "arbitrary code execution via reflection"
                    ),
                    "severity": "High",
                    "remediation": (
                        "Use WebMessageChannel (postMessage) instead. "
                        "If unavoidable, target API 17+ and annotate methods with @JavascriptInterface. "
                        "Validate all input from JavaScript."
                    ),
                },
                "setAllowContentAccess": {
                    "desc": "Allows WebView to access content:// URLs, potentially reading content provider data",
                    "severity": "Medium",
                    "remediation": "Set setAllowContentAccess(false) unless content:// access is required.",
                },
                "setWebContentsDebuggingEnabled": {
                    "desc": "Enables Chrome DevTools remote debugging for all WebViews in the app",
                    "severity": "High",
                    "remediation": "Only enable in debug builds: if (BuildConfig.DEBUG) { ... }",
                },
            }

            for api in data.webview_apis:
                for method, config in dangerous_methods.items():
                    if method in api.api_called:
                        if api.method_signature in seen:
                            continue
                        seen.add(api.method_signature)

                        finding = Finding(
                            title=f"Insecure WebView: {method}",
                            description=(
                                f"{config['desc']}. "
                                f"AndroGoat demonstrates WebView vulnerabilities including "
                                f"XSS and JavaScript bridge exploitation."
                            ),
                            owasp_category=OWASP_M4 if "javascript" in method.lower() else OWASP_M7,
                            severity=config["severity"],
                            remediation=config["remediation"],
                            affected_component=api.api_called,
                            evidence={
                                "api": api.api_called,
                                "method": method,
                            },
                            rule_id=self.rule_id,
                        )
                        findings.append(finding)

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 18: Path Traversal Risk
# ============================================================================
class PathTraversalRiskRule(BaseRule):
    """
    Detect potential path traversal vulnerabilities.
    
    AndroGoat vulnerability: Path traversal using ../ sequences to access
    files outside intended directories.
    
    Category: Input Validation - Path Traversal
    """

    @property
    def rule_id(self) -> str:
        return "PATH_TRAVERSAL_RISK"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            # Type 1: Explicit path traversal patterns in strings
            for string in data.strings:
                value = string.value

                if len(value) < 3 or value in seen:
                    continue

                # Direct traversal patterns
                has_traversal = False
                if "../" in value or "..\\" in value:
                    if "/" in value or "\\" in value:
                        has_traversal = True

                # Path manipulation with user input indicators
                if not has_traversal and re.search(
                    r"(?i)(getParameter|getExtra|getIntent|getInput).*(?:File|Path|Dir)", value
                ):
                    has_traversal = True

                if has_traversal:
                    seen.add(value)
                    finding = Finding(
                        title="Potential Path Traversal Risk",
                        description=(
                            f"Path traversal pattern detected: '{value[:80]}'. "
                            f"If user input influences file paths without validation, "
                            f"attackers can read/write files outside intended directories "
                            f"(e.g., ../../../../etc/passwd). AndroGoat demonstrates this "
                            f"vulnerability with directory traversal attacks."
                        ),
                        owasp_category=OWASP_M4,
                        severity="High" if "../" in value else "Medium",
                        remediation=(
                            "Validate and sanitize all file paths. "
                            "Use File.getCanonicalPath() and verify it starts with the "
                            "expected base directory. Reject paths containing '../'. "
                            "Use an allowlist of permitted filenames when possible."
                        ),
                        affected_component=string.dex_file,
                        evidence={"path_fragment": value[:100]},
                        rule_id=self.rule_id,
                    )
                    findings.append(finding)

                    if len(findings) >= 5:
                        break

            # Type 2: File APIs without path validation
            for api in data.storage_apis:
                if "File(" in api.api_called or "new File" in api.api_called:
                    # Check if there's concatenation with user input
                    for param in api.parameters if hasattr(api, "parameters") else []:
                        if "+" in param or "concat" in param.lower():
                            key = f"file_concat_{api.method_signature}"
                            if key not in seen:
                                seen.add(key)
                                findings.append(
                                    Finding(
                                        title="File Path Concatenation - Traversal Risk",
                                        description=(
                                            "File object created with string concatenation. "
                                            "If the concatenated part comes from user input, "
                                            "this is vulnerable to path traversal."
                                        ),
                                        owasp_category=OWASP_M4,
                                        severity="Medium",
                                        remediation=(
                                            "Use File.getCanonicalPath() to resolve the path "
                                            "and verify it stays within the intended directory."
                                        ),
                                        affected_component=api.api_called,
                                        evidence={"api": api.api_called, "param": param[:60]},
                                        rule_id=self.rule_id,
                                    )
                                )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 19: Insecure SQLite Database Storage
# ============================================================================
class InsecureSQLiteDatabaseRule(BaseRule):
    """
    Detect insecure SQLite database usage.
    
    AndroGoat vulnerability: Plaintext data stored in aGoat SQLite database
    accessible via adb backup or root access.
    
    Category: Information Storage - SQLite
    """

    @property
    def rule_id(self) -> str:
        return "INSECURE_SQLITE_DATABASE"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            sqlite_apis = [
                "SQLiteDatabase",
                "SQLiteOpenHelper",
                "openOrCreateDatabase",
                "getWritableDatabase",
                "getReadableDatabase",
            ]

            db_detected = False
            for api in data.storage_apis:
                if any(sqlite_api in api.api_called for sqlite_api in sqlite_apis):
                    if api.method_signature in seen:
                        continue
                    seen.add(api.method_signature)

                    if not db_detected:
                        db_detected = True
                        findings.append(
                            Finding(
                                title="Unencrypted SQLite Database Usage",
                                description=(
                                    "App uses SQLite database for data storage. SQLite databases "
                                    "are stored as unencrypted files in /data/data/<package>/databases/. "
                                    "Sensitive data (credentials, PII, financial info) is readable "
                                    "via adb backup, root access, or device forensics. "
                                    "AndroGoat stores plaintext data in the 'aGoat' database."
                                ),
                                owasp_category=OWASP_M9,
                                severity="Medium",
                                remediation=(
                                    "Use SQLCipher for database encryption. "
                                    "Alternatively, use Room with encrypted storage. "
                                    "Hash or encrypt sensitive columns at minimum. "
                                    "Never store plaintext passwords in databases."
                                ),
                                affected_component=api.api_called,
                                evidence={"api": api.api_called},
                                rule_id=self.rule_id,
                            )
                        )

            # Check for database names in strings
            for string in data.strings:
                if re.search(r"(?i)\.db$|\.sqlite$|\.database$", string.value):
                    db_name = string.value.strip()
                    if len(db_name) < 50 and db_name not in seen:
                        seen.add(db_name)
                        findings.append(
                            Finding(
                                title=f"Database File Reference: {db_name[:40]}",
                                description=(
                                    f"Database file '{db_name}' referenced in code. "
                                    f"Verify sensitive data is encrypted at rest."
                                ),
                                owasp_category=OWASP_M9,
                                severity="Low",
                                remediation="Encrypt the database using SQLCipher.",
                                affected_component=string.dex_file,
                                evidence={"database_name": db_name},
                                rule_id=self.rule_id,
                            )
                        )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 20: Keyboard Cache / Input Type Issues
# ============================================================================
class KeyboardCacheRule(BaseRule):
    """
    Detect keyboard cache vulnerability for sensitive input fields.
    
    AndroGoat vulnerability: Sensitive data cached by keyboard
    (autocomplete/autocorrect not disabled for password fields).
    
    Category: Information Storage - Keyboard Cache
    """

    @property
    def rule_id(self) -> str:
        return "KEYBOARD_CACHE"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            # Check for input type patterns in strings and layout references
            keyboard_indicators = []

            for string in data.strings:
                value_lower = string.value.lower()

                # Look for EditText/input handling without InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                if any(
                    kw in value_lower
                    for kw in [
                        "edittext",
                        "textinputedittext",
                        "inputtype",
                        "setinputtype",
                    ]
                ):
                    # Check if password/sensitive field without proper flags
                    if any(
                        sensitive in value_lower
                        for sensitive in ["password", "passwd", "pin", "ssn", "credit", "cvv"]
                    ):
                        if "no_suggestions" not in value_lower and "textnosuggestions" not in value_lower:
                            keyboard_indicators.append(string.value[:80])

                # Also detect autocomplete/autocorrect settings
                if "setautocorrect" in value_lower or "textautocorrect" in value_lower:
                    keyboard_indicators.append(string.value[:80])

            # Check for XML layout patterns
            for string in data.strings:
                if "android:inputType" in string.value:
                    if "textPassword" not in string.value and any(
                        kw in string.value.lower()
                        for kw in ["password", "pin", "secret"]
                    ):
                        keyboard_indicators.append(string.value[:80])

            if keyboard_indicators:
                findings.append(
                    Finding(
                        title="Keyboard Cache Risk for Sensitive Input",
                        description=(
                            "Sensitive input fields may have keyboard caching/autocomplete "
                            "enabled. The keyboard stores typed words in a user dictionary "
                            "file accessible to other apps or via backup extraction. "
                            "AndroGoat demonstrates this vulnerability with password fields "
                            "that don't disable keyboard learning."
                        ),
                        owasp_category=OWASP_M9,
                        severity="Medium",
                        remediation=(
                            "For sensitive fields, set inputType to: "
                            "InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD | "
                            "InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS. "
                            "In XML: android:inputType=\"textPassword|textNoSuggestions\". "
                            "Consider using android:importantForAutofill=\"no\" on API 26+."
                        ),
                        affected_component="Input Fields",
                        evidence={
                            "indicators": keyboard_indicators[:5],
                            "count": len(keyboard_indicators),
                        },
                        rule_id=self.rule_id,
                    )
                )
            else:
                # If we can't definitively detect, still flag if the app handles passwords
                password_handling = False
                for string in data.strings:
                    if any(
                        kw in string.value.lower()
                        for kw in ["password", "passwd", "pwd", "login"]
                    ):
                        password_handling = True
                        break

                if password_handling:
                    findings.append(
                        Finding(
                            title="Keyboard Cache - Manual Review Needed",
                            description=(
                                "App handles password/credential input. Verify that all "
                                "sensitive input fields have keyboard caching disabled. "
                                "Static analysis cannot fully verify input type configuration."
                            ),
                            owasp_category=OWASP_M9,
                            severity="Low",
                            remediation=(
                                "Ensure all password/sensitive fields use "
                                "InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS and "
                                "InputType.TYPE_TEXT_VARIATION_PASSWORD."
                            ),
                            affected_component="Input Fields",
                            evidence={"manual_review": True},
                            rule_id=self.rule_id,
                        )
                    )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 21: HTTPS Certificate Validation Bypass
# ============================================================================
class CertificateValidationBypassRule(BaseRule):
    """
    Detect HTTPS certificate validation bypass (TrustAllCerts, empty TrustManagers).
    
    AndroGoat vulnerability: HTTPS with no validation - trusts all certificates,
    allowing MITM attacks even on HTTPS connections.
    
    Category: Network Communication - HTTPS with no validation
    """

    TRUST_ALL_INDICATORS = [
        "TrustAllCerts",
        "AllowAllHostnameVerifier",
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "NullHostnameVerifier",
        "AcceptAllHostnameVerifier",
        "TrustAllManager",
        "InsecureTrustManager",
        "X509TrustManager",  # When implementing custom (often insecure)
        "checkServerTrusted",  # Empty implementation indicator
        "checkClientTrusted",  # Empty implementation indicator
        "SSLCertificateSocketFactory",
        "setHostnameVerifier",
        "HttpsURLConnection.setDefaultHostnameVerifier",
        "VERIFY_NONE",
    ]

    OKHTTP_BYPASS_INDICATORS = [
        "sslSocketFactory",
        "hostnameVerifier",
        "OkHttpClient.Builder",
        "TrustManagerFactory",
        "X509Certificate",
    ]

    @property
    def rule_id(self) -> str:
        return "CERTIFICATE_VALIDATION_BYPASS"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            # Check strings for trust-all patterns
            for string in data.strings:
                value_lower = string.value.lower()

                for indicator in self.TRUST_ALL_INDICATORS:
                    if indicator.lower() in value_lower:
                        key = indicator.lower()
                        if key in seen:
                            continue
                        seen.add(key)

                        severity = "Critical"
                        if indicator in ("X509TrustManager", "checkServerTrusted", "checkClientTrusted"):
                            severity = "High"  # Might be legitimate custom implementation

                        findings.append(
                            Finding(
                                title=f"Certificate Validation Bypass: {indicator}",
                                description=(
                                    f"Detected '{indicator}' which may disable SSL/TLS certificate "
                                    f"validation. This allows man-in-the-middle attacks on HTTPS "
                                    f"connections - attackers can intercept, read, and modify all "
                                    f"encrypted traffic. AndroGoat trusts all certificates to "
                                    f"demonstrate this vulnerability."
                                ),
                                owasp_category=OWASP_M5,
                                severity=severity,
                                remediation=(
                                    "Remove custom TrustManager implementations that accept all "
                                    "certificates. Use the platform default TrustManager. "
                                    "Implement certificate pinning for sensitive connections. "
                                    "Never ship trust-all code to production."
                                ),
                                affected_component=string.dex_file,
                                evidence={
                                    "indicator": indicator,
                                    "context": string.value[:100],
                                },
                                rule_id=self.rule_id,
                            )
                        )
                        break  # One finding per string

            # Check for OkHttp custom SSL configuration
            okhttp_ssl_detected = False
            for string in data.strings:
                if not okhttp_ssl_detected:
                    value_lower = string.value.lower()
                    okhttp_count = sum(
                        1
                        for ind in self.OKHTTP_BYPASS_INDICATORS
                        if ind.lower() in value_lower
                    )
                    if okhttp_count >= 2:
                        okhttp_ssl_detected = True
                        findings.append(
                            Finding(
                                title="OkHttp Custom SSL Configuration",
                                description=(
                                    "OkHttp client with custom SSL socket factory and/or hostname "
                                    "verifier detected. If implementing trust-all behavior, this "
                                    "completely disables HTTPS security. AndroGoat demonstrates "
                                    "OkHttp3 certificate bypass."
                                ),
                                owasp_category=OWASP_M5,
                                severity="High",
                                remediation=(
                                    "Use CertificatePinner with OkHttp for pinning. "
                                    "Remove custom SSLSocketFactory that trusts all certificates. "
                                    "Use OkHttp's built-in certificate pinning: "
                                    "CertificatePinner.Builder().add(hostname, pin).build()"
                                ),
                                affected_component="OkHttp Configuration",
                                evidence={"okhttp_ssl_indicators": okhttp_count},
                                rule_id=self.rule_id,
                            )
                        )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 22: Custom URL Scheme / Deep Link Vulnerability
# ============================================================================
class CustomURLSchemeRule(BaseRule):
    """
    Detect custom URL scheme (deep link) handling vulnerabilities.
    
    AndroGoat vulnerability: Custom URL scheme handling that may allow
    unauthorized actions via crafted deep links.
    
    Category: Network Communication - Custom URL Scheme
    """

    @property
    def rule_id(self) -> str:
        return "CUSTOM_URL_SCHEME"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            # Check exported components for intent filters with custom schemes
            for component in data.exported_components:
                if component.intent_filter_count > 0 and component.exported:
                    # Check for deep link / custom scheme indicators
                    comp_name_lower = component.name.lower()

                    if any(
                        kw in comp_name_lower
                        for kw in ["deeplink", "deep_link", "link", "scheme", "url", "intent", "redirect"]
                    ):
                        findings.append(
                            Finding(
                                title=f"Deep Link Handler: {component.name}",
                                description=(
                                    f"Exported activity '{component.name}' appears to handle "
                                    f"deep links/custom URL schemes with {component.intent_filter_count} "
                                    f"intent filter(s). Without proper input validation, attackers "
                                    f"can craft malicious URLs to bypass authentication, inject "
                                    f"data, or trigger unintended actions. AndroGoat demonstrates "
                                    f"custom URL scheme vulnerabilities."
                                ),
                                owasp_category=OWASP_M5,
                                severity="Medium",
                                remediation=(
                                    "Validate all intent data received from deep links. "
                                    "Use App Links (HTTPS-verified) instead of custom schemes. "
                                    "Implement intent validation in onNewIntent(). "
                                    "Never trust URL parameters for authentication decisions."
                                ),
                                affected_component=component.name,
                                evidence={
                                    "component": component.name,
                                    "exported": True,
                                    "intent_filters": component.intent_filter_count,
                                },
                                rule_id=self.rule_id,
                            )
                        )

            # Check strings for custom scheme definitions
            scheme_patterns = [
                r"(?i)<data\s+android:scheme\s*=\s*[\"']([^\"']+)[\"']",
                r"(?i)scheme\s*[=:]\s*[\"']([a-z][a-z0-9+.\-]*)[\"']",
            ]

            seen_schemes: Set[str] = set()
            for string in data.strings:
                for pattern in scheme_patterns:
                    match = re.search(pattern, string.value)
                    if match:
                        scheme = match.group(1)
                        if scheme not in seen_schemes and scheme not in ("http", "https", "tel", "mailto", "geo"):
                            seen_schemes.add(scheme)
                            findings.append(
                                Finding(
                                    title=f"Custom URL Scheme Registered: {scheme}://",
                                    description=(
                                        f"App registers custom URL scheme '{scheme}://'. "
                                        f"Custom schemes lack origin verification unlike App Links. "
                                        f"Any app can invoke this scheme to trigger app behavior."
                                    ),
                                    owasp_category=OWASP_M5,
                                    severity="Medium",
                                    remediation=(
                                        "Migrate to Android App Links with domain verification. "
                                        "Validate all parameters from deep link intents. "
                                        "Add user confirmation for sensitive actions triggered by deep links."
                                    ),
                                    affected_component="AndroidManifest.xml",
                                    evidence={"scheme": scheme},
                                    rule_id=self.rule_id,
                                )
                            )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 23: Hardcoded Cryptographic Key
# ============================================================================
class HardcodedCryptoKeyRule(BaseRule):
    """
    Detect hardcoded cryptographic keys in crypto API calls.
    
    AndroGoat vulnerability: Hardcoded encryption/decryption keys
    making all cryptographic operations breakable.
    
    Category: Cryptographic Issues - Hardcoded cryptographic keys
    """

    @property
    def rule_id(self) -> str:
        return "HARDCODED_CRYPTO_KEY"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            key_construction_apis = [
                "SecretKeySpec",
                "PBEKeySpec",
                "DESedeKeySpec",
                "DESKeySpec",
                "SecretKey",
            ]

            for api in data.crypto_apis:
                if not any(key_api in api.api_called for key_api in key_construction_apis):
                    continue

                key = f"{api.api_called}|{api.method_signature}"
                if key in seen:
                    continue

                for param in api.parameters:
                    if self._is_hardcoded_key(param):
                        seen.add(key)
                        findings.append(
                            Finding(
                                title="Hardcoded Cryptographic Key",
                                description=(
                                    f"Cryptographic key appears to be hardcoded in "
                                    f"{api.api_called}. Hardcoded keys can be extracted "
                                    f"by decompiling the APK, making all encryption "
                                    f"operations using this key completely breakable. "
                                    f"AndroGoat uses hardcoded keys intentionally to "
                                    f"demonstrate this critical vulnerability."
                                ),
                                owasp_category=OWASP_M10,
                                severity="Critical",
                                remediation=(
                                    "Generate keys using Android Keystore system. "
                                    "Derive keys from user input using PBKDF2 with high "
                                    "iteration count. Fetch keys from secure backend. "
                                    "Never embed keys in source code or resources."
                                ),
                                affected_component=api.api_called,
                                evidence={
                                    "api": api.api_called,
                                    "parameter_hint": param[:40] + "..." if len(param) > 40 else param,
                                },
                                rule_id=self.rule_id,
                            )
                        )
                        break

            # Check for key derivation with weak parameters
            for api in data.crypto_apis:
                if "PBEKeySpec" in api.api_called:
                    for param in api.parameters:
                        # Check for low iteration count
                        iter_match = re.search(r"\b(\d{1,4})\b", param)
                        if iter_match:
                            iterations = int(iter_match.group(1))
                            if 0 < iterations < 10000:
                                iter_key = f"weak_pbkdf2_{api.method_signature}"
                                if iter_key not in seen:
                                    seen.add(iter_key)
                                    findings.append(
                                        Finding(
                                            title=f"Weak PBKDF2 Iteration Count: {iterations}",
                                            description=(
                                                f"PBEKeySpec uses only {iterations} iterations. "
                                                f"OWASP recommends minimum 600,000 iterations for "
                                                f"PBKDF2-HMAC-SHA256 as of 2023."
                                            ),
                                            owasp_category=OWASP_M10,
                                            severity="High",
                                            remediation=(
                                                "Use at least 600,000 iterations for PBKDF2-HMAC-SHA256 "
                                                "or migrate to Argon2."
                                            ),
                                            affected_component=api.api_called,
                                            evidence={
                                                "iterations": iterations,
                                                "recommended": "600000+",
                                            },
                                            rule_id=self.rule_id,
                                        )
                                    )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings

    @staticmethod
    def _is_hardcoded_key(value: str) -> bool:
        """Check if a parameter looks like a hardcoded key."""
        if len(value) < 8:
            return False

        # Hex string key (16, 24, 32 bytes = 32, 48, 64 hex chars)
        if re.match(r"^[0-9a-fA-F]{16,}$", value):
            return True

        # Base64 key
        if re.match(r"^[A-Za-z0-9+/]{12,}={0,2}$", value):
            if len(value) % 4 == 0 or value.endswith("="):
                return True

        # Quoted string key
        if re.match(r'^["\'].*["\']$', value) and len(value) > 10:
            return True

        # Byte array
        if re.match(r"^\{(\s*-?\d+\s*,?)+\}$", value):
            return True

        # String literal used as key
        if re.match(r"^[a-zA-Z0-9!@#$%^&*()]{16,}$", value):
            return True

        # Hex notation
        if re.search(r"(0x[0-9a-fA-F]{2}[,\s]*){8,}", value):
            return True

        return False


# ============================================================================
# RULE 24: Insecure Random Number Generator
# ============================================================================
class InsecureRandomRule(BaseRule):
    """
    Detect use of java.util.Random instead of SecureRandom for security purposes.
    
    java.util.Random is a PRNG that is predictable and not suitable for
    cryptographic operations, token generation, or security-sensitive contexts.
    
    Category: Cryptographic Issues
    """

    @property
    def rule_id(self) -> str:
        return "INSECURE_RANDOM"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            for api in data.crypto_apis:
                api_lower = api.api_called.lower()

                # Detect java.util.Random usage (not SecureRandom)
                if "java.util.random" in api_lower or (
                    "random" in api_lower and "securerandom" not in api_lower
                ):
                    # Check if used in security context
                    sig_lower = api.method_signature.lower() if api.method_signature else ""
                    security_context = any(
                        kw in sig_lower
                        for kw in [
                            "token",
                            "key",
                            "nonce",
                            "iv",
                            "salt",
                            "session",
                            "otp",
                            "password",
                            "auth",
                            "crypto",
                            "encrypt",
                            "random",
                        ]
                    )

                    key = f"insecure_random_{api.method_signature}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            Finding(
                                title="Insecure Random Number Generator",
                                description=(
                                    f"java.util.Random detected{' in security context' if security_context else ''}. "
                                    f"java.util.Random uses a linear congruential generator that is "
                                    f"predictable. An attacker who observes a few outputs can predict "
                                    f"all future values."
                                ),
                                owasp_category=OWASP_M10,
                                severity="High" if security_context else "Medium",
                                remediation=(
                                    "Use java.security.SecureRandom for all security-sensitive "
                                    "random number generation (tokens, keys, IVs, nonces, salts, "
                                    "session IDs, OTPs)."
                                ),
                                affected_component=api.api_called,
                                evidence={
                                    "api": api.api_called,
                                    "security_context": security_context,
                                },
                                rule_id=self.rule_id,
                            )
                        )

            # Also check strings for Random() constructor
            for string in data.strings:
                if "new Random()" in string.value or "Random()" in string.value:
                    if "SecureRandom" not in string.value:
                        str_key = f"random_ctor_{string.value[:40]}"
                        if str_key not in seen:
                            seen.add(str_key)
                            findings.append(
                                Finding(
                                    title="java.util.Random Constructor Used",
                                    description=(
                                        "new Random() creates a predictable PRNG. "
                                        "Replace with SecureRandom for security purposes."
                                    ),
                                    owasp_category=OWASP_M10,
                                    severity="Medium",
                                    remediation="Use new SecureRandom() instead.",
                                    affected_component=string.dex_file,
                                    evidence={"reference": string.value[:80]},
                                    rule_id=self.rule_id,
                                )
                            )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 25: Missing Certificate Pinning (OkHttp/Network)
# ============================================================================
class MissingCertificatePinningRule(BaseRule):
    """
    Detect missing certificate pinning in network libraries.
    
    AndroGoat vulnerability: Missing certificate pinning in both OkHttp3
    and native HTTPS implementations.
    
    Category: Network Communication - Missing Certificate Pinning
    """

    @property
    def rule_id(self) -> str:
        return "MISSING_CERTIFICATE_PINNING"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            has_okhttp = False
            has_pinning = False
            has_network_calls = False

            for string in data.strings:
                value_lower = string.value.lower()

                # Detect OkHttp usage
                if "okhttp" in value_lower or "okhttpclient" in value_lower:
                    has_okhttp = True

                # Detect certificate pinning implementation
                if any(
                    pin_kw in value_lower
                    for pin_kw in [
                        "certificatepinner",
                        "certificate_pinner",
                        "pin-set",
                        "pinset",
                        "sha256/",  # Pin hash format
                        "sha-256",
                    ]
                ):
                    has_pinning = True

                # Detect network calls
                if any(
                    net_kw in value_lower
                    for net_kw in [
                        "httpsurlconnection",
                        "httpclient",
                        "urlconnection",
                        "retrofit",
                        "volley",
                    ]
                ):
                    has_network_calls = True

            if has_okhttp and not has_pinning:
                findings.append(
                    Finding(
                        title="OkHttp Without Certificate Pinning",
                        description=(
                            "App uses OkHttp for network requests but no "
                            "CertificatePinner implementation was detected. Without pinning, "
                            "MITM attacks using rogue CA certificates succeed even with HTTPS. "
                            "AndroGoat demonstrates this with OkHttp3."
                        ),
                        owasp_category=OWASP_M5,
                        severity="Medium",
                        remediation=(
                            "Add CertificatePinner to OkHttpClient.Builder: "
                            "CertificatePinner.Builder().add(\"domain.com\", "
                            "\"sha256/AAAA...\").build(). Include backup pins. "
                            "Test with a proxy to verify pinning works."
                        ),
                        affected_component="OkHttp Client",
                        evidence={"okhttp_detected": True, "pinning_detected": False},
                        rule_id=self.rule_id,
                    )
                )

            if has_network_calls and not has_pinning and not has_okhttp:
                findings.append(
                    Finding(
                        title="HTTPS Without Certificate Pinning",
                        description=(
                            "App makes HTTPS requests but no certificate pinning was "
                            "detected. Without pinning, compromised or rogue CAs can issue "
                            "fraudulent certificates for MITM attacks."
                        ),
                        owasp_category=OWASP_M5,
                        severity="Medium",
                        remediation=(
                            "Implement certificate pinning via network_security_config.xml "
                            "or in code using TrustManager with pinned certificates."
                        ),
                        affected_component="Network Communication",
                        evidence={
                            "network_calls_detected": True,
                            "pinning_detected": False,
                        },
                        rule_id=self.rule_id,
                    )
                )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 26: Clipboard Data Leakage
# ============================================================================
class ClipboardDataLeakageRule(BaseRule):
    """
    Detect clipboard usage that may leak sensitive data.
    
    On Android < 10, all apps can read clipboard content. Sensitive data
    (passwords, tokens) copied to clipboard is accessible to malicious apps.
    
    Category: Information Storage
    """

    @property
    def rule_id(self) -> str:
        return "CLIPBOARD_DATA_LEAKAGE"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            clipboard_apis = [
                "ClipboardManager",
                "ClipData",
                "setPrimaryClip",
                "getPrimaryClip",
                "getText",  # Deprecated clipboard access
            ]

            for api in data.storage_apis:
                if any(clip_api in api.api_called for clip_api in clipboard_apis):
                    if api.method_signature not in seen:
                        seen.add(api.method_signature)

                        is_write = any(
                            w in api.api_called for w in ["setPrimaryClip", "setText"]
                        )

                        findings.append(
                            Finding(
                                title=f"Clipboard {'Write' if is_write else 'Read'} Detected",
                                description=(
                                    f"App {'copies data to' if is_write else 'reads from'} clipboard. "
                                    f"On Android < 10 (API 29), all apps can read clipboard content. "
                                    f"If sensitive data (passwords, tokens, PII) is copied, it is "
                                    f"accessible to any app on the device."
                                ),
                                owasp_category=OWASP_M9,
                                severity="Medium" if is_write else "Low",
                                remediation=(
                                    "Avoid copying sensitive data to clipboard. "
                                    "If necessary, use ClipDescription.EXTRA_IS_SENSITIVE (API 33+). "
                                    "Clear clipboard after a timeout. Warn users about clipboard risks."
                                ),
                                affected_component=api.api_called,
                                evidence={
                                    "api": api.api_called,
                                    "operation": "write" if is_write else "read",
                                },
                                rule_id=self.rule_id,
                            )
                        )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 27: Insecure Broadcast (sendBroadcast without permission)
# ============================================================================
class InsecureBroadcastRule(BaseRule):
    """
    Detect insecure broadcast sending without permissions.
    
    sendBroadcast() without a permission allows any app to receive the intent,
    potentially leaking sensitive data or enabling intent spoofing.
    
    Category: Component Exposure
    """

    @property
    def rule_id(self) -> str:
        return "INSECURE_BROADCAST"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()

        try:
            broadcast_apis = [
                "sendBroadcast",
                "sendOrderedBroadcast",
                "sendStickyBroadcast",
            ]

            for string in data.strings:
                for api_name in broadcast_apis:
                    if api_name in string.value:
                        key = f"{api_name}_{string.value[:50]}"
                        if key not in seen:
                            seen.add(key)

                            is_sticky = "Sticky" in api_name
                            severity = "High" if is_sticky else "Medium"

                            findings.append(
                                Finding(
                                    title=f"Insecure Broadcast: {api_name}",
                                    description=(
                                        f"App calls {api_name}() which sends a broadcast "
                                        f"receivable by any app on the device. "
                                        f"{'Sticky broadcasts persist and are even more dangerous. ' if is_sticky else ''}"
                                        f"Sensitive data in the intent extras is exposed."
                                    ),
                                    owasp_category=OWASP_M8,
                                    severity=severity,
                                    remediation=(
                                        "Use LocalBroadcastManager for app-internal broadcasts. "
                                        "Add permission parameter to sendBroadcast(). "
                                        "Use explicit intents instead of implicit broadcasts."
                                    ),
                                    affected_component=string.dex_file,
                                    evidence={
                                        "api": api_name,
                                        "context": string.value[:80],
                                    },
                                    rule_id=self.rule_id,
                                )
                            )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 28: Tapjacking / Screen Overlay Attack
# ============================================================================
class TapjackingRule(BaseRule):
    """
    Detect vulnerability to tapjacking (screen overlay) attacks.
    
    If filterTouchesWhenObscured is not set, the app is vulnerable to
    clickjacking where a malicious overlay captures user taps.
    
    Category: Binary Protection
    """

    @property
    def rule_id(self) -> str:
        return "TAPJACKING_VULNERABILITY"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            has_filter_touches = False

            for string in data.strings:
                if "filterTouchesWhenObscured" in string.value:
                    has_filter_touches = True
                    break
                if "FLAG_WINDOW_IS_OBSCURED" in string.value:
                    has_filter_touches = True
                    break

            if not has_filter_touches:
                # Check if app has sensitive UI (login, payment, etc.)
                has_sensitive_ui = False
                for string in data.strings:
                    if any(
                        kw in string.value.lower()
                        for kw in ["login", "password", "payment", "transfer", "confirm", "authorize"]
                    ):
                        has_sensitive_ui = True
                        break

                if has_sensitive_ui:
                    findings.append(
                        Finding(
                            title="Tapjacking (Screen Overlay) Vulnerability",
                            description=(
                                "App has sensitive UI elements but does not appear to set "
                                "filterTouchesWhenObscured or check FLAG_WINDOW_IS_OBSCURED. "
                                "A malicious app can draw an overlay to trick users into "
                                "tapping on sensitive buttons (grant permissions, confirm "
                                "transactions, enter credentials)."
                            ),
                            owasp_category=OWASP_M7,
                            severity="Medium",
                            remediation=(
                                "Set android:filterTouchesWhenObscured=\"true\" on sensitive views. "
                                "Check MotionEvent.FLAG_WINDOW_IS_OBSCURED in onTouchEvent(). "
                                "Use FLAG_SECURE for sensitive screens."
                            ),
                            affected_component="UI Security",
                            evidence={"filter_touches_detected": False, "sensitive_ui": True},
                            rule_id=self.rule_id,
                        )
                    )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 29: Missing Code Obfuscation
# ============================================================================
class MissingObfuscationRule(BaseRule):
    """
    Detect missing code obfuscation (ProGuard/R8).
    
    Unobfuscated code allows easy reverse engineering to extract secrets,
    understand business logic, and find vulnerabilities.
    
    Category: Binary Protection
    """

    @property
    def rule_id(self) -> str:
        return "MISSING_OBFUSCATION"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            # Heuristic: Check for long descriptive class/method names
            # Obfuscated code has short names like a.b.c, a(), b()
            long_name_count = 0
            short_name_count = 0
            total_checked = 0

            for string in data.strings:
                # Look for class references
                if re.match(r"^L[a-z]+/[a-z]+/[A-Z][a-zA-Z]+;$", string.value):
                    total_checked += 1
                    parts = string.value.split("/")
                    last_part = parts[-1].rstrip(";")
                    if len(last_part) > 3:
                        long_name_count += 1
                    else:
                        short_name_count += 1

                if total_checked >= 100:
                    break

            if total_checked >= 20:
                obfuscation_ratio = short_name_count / total_checked
                if obfuscation_ratio < 0.3:  # Less than 30% short names
                    findings.append(
                        Finding(
                            title="Missing/Weak Code Obfuscation",
                            description=(
                                f"Code appears unobfuscated or weakly obfuscated. "
                                f"Analysis of {total_checked} class references shows "
                                f"{long_name_count} descriptive names vs {short_name_count} "
                                f"obfuscated names ({obfuscation_ratio:.0%} obfuscation). "
                                f"Unobfuscated code is trivially reverse-engineered."
                            ),
                            owasp_category=OWASP_M7,
                            severity="Medium",
                            remediation=(
                                "Enable R8/ProGuard minification and obfuscation. "
                                "In build.gradle: minifyEnabled true, shrinkResources true. "
                                "Test thoroughly after enabling. Consider DexGuard for "
                                "additional protection."
                            ),
                            affected_component="Application Code",
                            evidence={
                                "classes_checked": total_checked,
                                "long_names": long_name_count,
                                "short_names": short_name_count,
                                "obfuscation_ratio": round(obfuscation_ratio, 2),
                            },
                            rule_id=self.rule_id,
                        )
                    )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 30: Unprotected Content Provider
# ============================================================================
class UnprotectedContentProviderRule(BaseRule):
    """
    Detect unprotected content providers that may leak data.
    
    AndroGoat vulnerability: Unprotected content providers allowing
    unauthorized data access.
    
    Category: Component Exposure - Content Providers
    """

    @property
    def rule_id(self) -> str:
        return "UNPROTECTED_CONTENT_PROVIDER"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            for component in data.exported_components:
                if component.type == "provider" and component.exported:
                    has_read_perm = bool(
                        hasattr(component, "read_permission") and component.read_permission
                    )
                    has_write_perm = bool(
                        hasattr(component, "write_permission") and component.write_permission
                    )
                    has_perm = bool(component.permission) or (has_read_perm and has_write_perm)

                    if not has_perm:
                        findings.append(
                            Finding(
                                title=f"Unprotected Content Provider: {component.name}",
                                description=(
                                    f"Content provider '{component.name}' is exported without "
                                    f"read/write permission protection. Any app can query, "
                                    f"insert, update, or delete data. This may expose sensitive "
                                    f"database contents, enable SQL injection via content "
                                    f"provider URIs, or allow data manipulation."
                                ),
                                owasp_category=OWASP_M8,
                                severity="Critical",
                                remediation=(
                                    "Add android:readPermission and android:writePermission "
                                    "with signature-level custom permissions. "
                                    "Set android:exported=\"false\" if not needed externally. "
                                    "Use android:grantUriPermissions with care. "
                                    "Implement proper input validation in query() and other methods."
                                ),
                                affected_component=component.name,
                                evidence={
                                    "component_name": component.name,
                                    "exported": True,
                                    "permission": component.permission,
                                    "read_permission": getattr(component, "read_permission", None),
                                    "write_permission": getattr(component, "write_permission", None),
                                },
                                rule_id=self.rule_id,
                            )
                        )

            # Also check for content:// URI patterns in strings
            for string in data.strings:
                if re.match(r"^content://[a-z][a-z0-9.]+/", string.value):
                    uri = string.value[:100]
                    findings.append(
                        Finding(
                            title=f"Content Provider URI Defined",
                            description=(
                                f"Content URI '{uri}' found. Verify the provider requires "
                                f"proper permissions and validates all query parameters."
                            ),
                            owasp_category=OWASP_M8,
                            severity="Low",
                            remediation="Ensure the content provider has permission restrictions.",
                            affected_component=string.dex_file,
                            evidence={"uri": uri},
                            rule_id=self.rule_id,
                        )
                    )
                    break  # Report once

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 31: Task Affinity / Activity Hijacking
# ============================================================================
class TaskAffinityHijackingRule(BaseRule):
    """
    Detect task affinity configurations that enable activity hijacking.
    
    A malicious app with the same taskAffinity can hijack the task stack,
    presenting phishing UIs or intercepting sensitive data.
    
    Category: Security Misconfiguration
    """

    @property
    def rule_id(self) -> str:
        return "TASK_AFFINITY_HIJACKING"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            # Check for non-empty taskAffinity or default affinity on sensitive activities
            for string in data.strings:
                if "taskAffinity" in string.value:
                    # If taskAffinity is explicitly set, check if it's empty
                    if re.search(r'taskAffinity\s*=\s*["\'][^"\']+["\']', string.value):
                        findings.append(
                            Finding(
                                title="Task Affinity Set - Hijacking Risk",
                                description=(
                                    "An activity has a non-empty taskAffinity. A malicious app "
                                    "can set the same taskAffinity to hijack the app's task, "
                                    "placing a phishing activity on top of the legitimate app."
                                ),
                                owasp_category=OWASP_M8,
                                severity="Medium",
                                remediation=(
                                    "Set android:taskAffinity=\"\" for all activities to prevent "
                                    "task hijacking. Set android:launchMode=\"singleTask\" for "
                                    "sensitive activities."
                                ),
                                affected_component="AndroidManifest.xml",
                                evidence={"reference": string.value[:80]},
                                rule_id=self.rule_id,
                            )
                        )
                        break

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 32: FLAG_SECURE Missing on Sensitive Screens
# ============================================================================
class MissingFlagSecureRule(BaseRule):
    """
    Detect missing FLAG_SECURE on sensitive screens.
    
    Without FLAG_SECURE, sensitive screens can be captured via screenshots,
    screen recording, or recent apps thumbnail.
    
    Category: Information Storage
    """

    @property
    def rule_id(self) -> str:
        return "MISSING_FLAG_SECURE"

    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []

        try:
            has_flag_secure = False
            has_sensitive_screen = False

            for string in data.strings:
                if "FLAG_SECURE" in string.value or "setFlags" in string.value:
                    has_flag_secure = True

                if any(
                    kw in string.value.lower()
                    for kw in ["loginactivity", "paymentactivity", "passwordactivity", "authactivity"]
                ):
                    has_sensitive_screen = True

            if has_sensitive_screen and not has_flag_secure:
                findings.append(
                    Finding(
                        title="Missing FLAG_SECURE on Sensitive Screens",
                        description=(
                            "App appears to have sensitive screens (login, payment) but "
                            "does not use WindowManager.LayoutParams.FLAG_SECURE. "
                            "Screen content can be captured via screenshots, screen recording, "
                            "or the recent apps thumbnail."
                        ),
                        owasp_category=OWASP_M9,
                        severity="Low",
                        remediation=(
                            "Add FLAG_SECURE to sensitive activities: "
                            "getWindow().setFlags(FLAG_SECURE, FLAG_SECURE) in onCreate()."
                        ),
                        affected_component="Sensitive Activities",
                        evidence={
                            "flag_secure_found": False,
                            "sensitive_screens_detected": True,
                        },
                        rule_id=self.rule_id,
                    )
                )

        except Exception as e:
            self._log_error(f"Exception: {str(e)}")

        self._log_finding(len(findings))
        return findings


# ============================================================================
# REGISTRY: All rules for engine consumption
# ============================================================================

ALL_RULES = [
    # Binary Protection & Environment Detection (Rules 1, 2, 16, 29)
    DebuggableEnabledRule,
    AllowBackupEnabledRule,
    WeakRootDetectionRule,
    MissingObfuscationRule,
    
    # Network Communication (Rules 3, 12, 21, 22, 25)
    CleartextTrafficAllowedRule,
    InsecureNetworkSecurityConfigRule,
    CertificateValidationBypassRule,
    CustomURLSchemeRule,
    MissingCertificatePinningRule,
    
    # Component Exposure (Rules 4, 27, 30, 31)
    ExportedComponentWithoutPermissionRule,
    InsecureBroadcastRule,
    UnprotectedContentProviderRule,
    TaskAffinityHijackingRule,
    
    # Privacy Controls (Rule 5)
    DangerousPermissionDeclaredRule,
    
    # Credential / Secret Storage (Rules 6, 23)
    HardcodedSecretRule,
    HardcodedCryptoKeyRule,
    
    # Cryptographic Issues (Rules 7, 13, 24)
    WeakCryptoAlgorithmRule,
    StaticIVRule,
    InsecureRandomRule,
    
    # WebView / Input Validation (Rules 8, 9, 17, 18)
    WebViewJavaScriptEnabledRule,
    SQLInjectionRiskRule,
    InsecureWebViewConfigRule,
    PathTraversalRiskRule,
    
    # Data Storage (Rules 10, 14, 15, 19, 20, 26, 28, 32)
    InsecureLoggingRule,
    InsecureSharedPreferencesRule,
    InsecureFileStorageRule,
    InsecureSQLiteDatabaseRule,
    KeyboardCacheRule,
    ClipboardDataLeakageRule,
    TapjackingRule,
    MissingFlagSecureRule,
]