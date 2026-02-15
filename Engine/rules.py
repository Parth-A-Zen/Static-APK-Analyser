"""
Security Rules Module

Concrete implementations of security checks for OWASP Mobile Top 10 2024.

Each rule checks for specific security issues in the APK analysis data.
Rules are designed to be extensible and maintainable.

Author: Generated for APK Security Analysis
License: MIT
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from Analyser.Engine.base_rule import BaseRule
from Engine.finding import Finding
from Loader.scope_filter import AnalysisReadyAPK

logger = logging.getLogger(__name__)


# ============================================================================
# RULE 1: Debuggable Enabled
# ============================================================================

class DebuggeableEnabledRule(BaseRule):
    """
    Check if the APK has debugging enabled.
    
    Debuggable APKs can be easily reverse-engineered and manipulated at runtime,
    allowing attackers to bypass security measures.
    
    OWASP: M7: Insufficient Binary Protections
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
                        "The APK has android:debuggable set to true in the manifest. "
                        "This allows attackers to easily attach debuggers, inspect memory, "
                        "modify code execution, and bypass security controls at runtime."
                    ),
                    owasp_category="M7: Insufficient Binary Protections",
                    severity="High",
                    remediation=(
                        "Set android:debuggable=\"false\" in the <application> tag of "
                        "AndroidManifest.xml for all release builds. This should only be "
                        "enabled during development."
                    ),
                    affected_component="AndroidManifest.xml <application>",
                    evidence={
                        "debuggable": True,
                        "package": data.package_name
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 2: Allow Backup Enabled
# ============================================================================

class AllowBackupEnabledRule(BaseRule):
    """
    Check if backup of app data is allowed.
    
    When allowBackup is enabled, users can extract app data via adb backup,
    potentially exposing sensitive information.
    
    OWASP: M9: Insecure Data Storage
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
                    title="Backup Allowed",
                    description=(
                        "The APK allows backup of application data via 'adb backup'. "
                        "Attackers can extract sensitive data from the device without "
                        "requiring the app to be running or permissions to be granted."
                    ),
                    owasp_category="M9: Insecure Data Storage",
                    severity="Medium",
                    remediation=(
                        "Set android:allowBackup=\"false\" in the <application> tag of "
                        "AndroidManifest.xml. If backup is needed, implement custom backup "
                        "agent and exclude sensitive data using fullBackupContent."
                    ),
                    affected_component="AndroidManifest.xml <application>",
                    evidence={
                        "allow_backup": True,
                        "package": data.package_name
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 3: Cleartext Traffic Allowed
# ============================================================================

class CleartextTrafficAllowedRule(BaseRule):
    """
    Check if cleartext (unencrypted) traffic is permitted.
    
    Allowing cleartext traffic enables man-in-the-middle (MITM) attacks where
    network communication can be intercepted and modified.
    
    OWASP: M5: Insecure Communication
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
                    title="Cleartext Traffic Allowed",
                    description=(
                        "The APK allows unencrypted (HTTP) traffic. This permits attackers "
                        "to intercept, read, and modify network communications using "
                        "man-in-the-middle (MITM) attacks."
                    ),
                    owasp_category="M5: Insecure Communication",
                    severity="High",
                    remediation=(
                        "Set android:usesCleartextTraffic=\"false\" in the <application> tag. "
                        "Ensure all network communication uses HTTPS/TLS. Use a network security "
                        "config file to enforce HTTPS for all domains."
                    ),
                    affected_component="AndroidManifest.xml <application>",
                    evidence={
                        "uses_cleartext_traffic": True,
                        "package": data.package_name
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 4: Exported Component Without Permission
# ============================================================================

class ExportedComponentWithoutPermissionRule(BaseRule):
    """
    Check for exported components without protection.
    
    Exported components can be accessed by other apps. Without permission
    protection, any app can start, bind to, or access the component.
    
    OWASP: M8: Security Misconfiguration
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
                    finding = Finding(
                        title="Unprotected Exported Component",
                        description=(
                            f"The {component.type} '{component.name}' is exported but not "
                            "protected by any permission. Any app on the device can access it, "
                            "potentially leading to privilege escalation or data exposure."
                        ),
                        owasp_category="M8: Security Misconfiguration",
                        severity="High",
                        remediation=(
                            f"Either set exported=\"false\" if the {component.type} is not needed "
                            "by other apps, or add a custom permission to protect it. For system "
                            "components, implement proper input validation."
                        ),
                        affected_component=component.name,
                        evidence={
                            "component_type": component.type,
                            "component_name": component.name,
                            "exported": True,
                            "permission": None,
                            "intent_filters": component.intent_filter_count
                        },
                        rule_id=self.rule_id
                    )
                    findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 5: Dangerous Permission Declared
# ============================================================================

class DangerousPermissionDeclaredRule(BaseRule):
    """
    Check for dangerous permissions in the manifest.
    
    Dangerous permissions provide access to sensitive user data or hardware.
    The app should only request permissions it actually needs.
    
    OWASP: M1: Improper Credential Usage
    """
    
    @property
    def rule_id(self) -> str:
        return "DANGEROUS_PERMISSION_DECLARED"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            for permission in data.dangerous_permissions:
                # Extract short permission name for display
                perm_short = permission.split('.')[-1] if '.' in permission else permission
                
                finding = Finding(
                    title=f"Dangerous Permission Declared: {perm_short}",
                    description=(
                        f"The app requests the dangerous permission '{permission}'. "
                        "This permission provides access to sensitive user data or hardware. "
                        "Verify the app actually needs this permission."
                    ),
                    owasp_category="M1: Improper Credential Usage",
                    severity="Medium",
                    remediation=(
                        "Remove unnecessary permissions from the manifest. Only request dangerous "
                        "permissions if truly required, and request them at runtime (Android 6.0+). "
                        "Explain why the permission is needed in the app's store listing."
                    ),
                    affected_component=f"AndroidManifest.xml permission",
                    evidence={
                        "permission": permission,
                        "package": data.package_name
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 6: Hardcoded API Key or Secret
# ============================================================================

class HardcodedSecretRule(BaseRule):
    """
    Check for hardcoded API keys and secrets in the APK.
    
    Secrets hardcoded in the APK are easily extractable and can be used to
    compromise backend services or user accounts.
    
    OWASP: M1: Improper Credential Usage
    """
    
    @property
    def rule_id(self) -> str:
        return "HARDCODED_SECRET"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            for string in data.strings:
                # Check for high-entropy strings or API-key-like patterns
                if string.looks_like_api_key or (
                    string.is_high_entropy and len(string.value) >= 20
                ):
                    # Filter out common false positives
                    if not self._is_false_positive(string.value):
                        finding = Finding(
                            title="Potential Hardcoded Secret",
                            description=(
                                f"A high-entropy string of length {string.length} was found in the APK. "
                                "This may be a hardcoded API key, encryption key, or other secret. "
                                "Secrets should never be embedded in the app code."
                            ),
                            owasp_category="M1: Improper Credential Usage",
                            severity="Critical",
                            remediation=(
                                "Move all secrets to a secure backend service. Use Android Keystore "
                                "for storing cryptographic keys. Implement dynamic secret delivery "
                                "from your backend. Never commit secrets to version control."
                            ),
                            affected_component=string.dex_file,
                            evidence={
                                "value": string.value,
                                "length": string.length,
                                "entropy": round(string.entropy, 2) if string.entropy else None,
                                "pattern_matched": string.pattern_matched,
                                "dex_file": string.dex_file
                            },
                            rule_id=self.rule_id
                        )
                        findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings
    
    @staticmethod
    def _is_false_positive(value: str) -> bool:
        """Filter out known false positives."""
        false_positive_patterns = [
            r'^[a-f0-9]{32}$',  # Generic hex strings
            r'^[A-Z0-9]{16,}$',  # All caps (often field names)
            r'Lorem ipsum',  # Test data
        ]
        
        for pattern in false_positive_patterns:
            if re.match(pattern, value):
                return True
        
        return False


# ============================================================================
# RULE 7: Weak Cryptographic Algorithm
# ============================================================================

class WeakCryptoAlgorithmRule(BaseRule):
    """
    Check for weak or broken cryptographic algorithms.
    
    Using weak algorithms (ECB mode, DES, MD5, SHA1) makes encrypted data
    vulnerable to cryptanalysis and known-plaintext attacks.
    
    OWASP: M10: Insufficient Cryptography
    """
    
    # Weak algorithms and patterns
    WEAK_ALGORITHMS = {
        'ECB': 'ECB mode is deterministic and leaks patterns',
        'DES': 'DES is broken and should not be used',
        'MD5': 'MD5 is cryptographically broken',
        'SHA1': 'SHA1 is cryptographically broken',
        'RSA/None/NoPadding': 'RSA without padding is vulnerable',
        'RC4': 'RC4 stream cipher has known biases',
        'Blowfish': 'Blowfish has small block size (64-bit)',
    }
    
    @property
    def rule_id(self) -> str:
        return "WEAK_CRYPTO_ALGORITHM"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            for crypto_api in data.crypto_apis:
                # Check algorithm in parameters
                for param in crypto_api.parameters:
                    for weak_algo, reason in self.WEAK_ALGORITHMS.items():
                        if weak_algo.upper() in param.upper():
                            finding = Finding(
                                title=f"Weak Cryptographic Algorithm: {weak_algo}",
                                description=(
                                    f"The {weak_algo} algorithm was found in use. {reason}. "
                                    "Using weak cryptography puts sensitive data at risk."
                                ),
                                owasp_category="M10: Insufficient Cryptography",
                                severity="High",
                                remediation=(
                                    "Use strong algorithms: AES for encryption (with GCM mode), "
                                    "SHA-256+ for hashing, ECDSA for signatures. "
                                    "Avoid ECB mode; use CBC or GCM. Use proper key sizes "
                                    "(at least 128 bits for symmetric, 256 bits for asymmetric)."
                                ),
                                affected_component=crypto_api.api_called,
                                evidence={
                                    "api_called": crypto_api.api_called,
                                    "parameters": crypto_api.parameters,
                                    "weak_algorithm": weak_algo,
                                    "reason": reason,
                                    "dex_file": crypto_api.dex_file
                                },
                                rule_id=self.rule_id
                            )
                            findings.append(finding)
                            break  # Only report once per API call
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 8: WebView JavaScript Enabled
# ============================================================================

class WebViewJavaScriptEnabledRule(BaseRule):
    """
    Check if WebView JavaScript is enabled.
    
    JavaScript in WebViews can access Java methods via javascript bridges,
    potentially leading to code injection and XSS attacks.
    
    OWASP: M7: Insufficient Binary Protections
    """
    
    @property
    def rule_id(self) -> str:
        return "WEBVIEW_JAVASCRIPT_ENABLED"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            for webview_api in data.webview_apis:
                if 'setJavaScriptEnabled' in webview_api.api_called:
                    finding = Finding(
                        title="WebView JavaScript Enabled",
                        description=(
                            "The app enables JavaScript in WebView. This allows script injection "
                            "attacks and can expose Java methods to JavaScript code if "
                            "addJavascriptInterface is used unsafely."
                        ),
                        owasp_category="M7: Insufficient Binary Protections",
                        severity="High",
                        remediation=(
                            "Only enable JavaScript if absolutely necessary and for trusted content. "
                            "Never load untrusted HTML/JavaScript. Use Content Security Policy headers. "
                            "Avoid addJavascriptInterface; use WebMessageChannel instead (Android 6.0+)."
                        ),
                        affected_component=webview_api.api_called,
                        evidence={
                            "api_called": webview_api.api_called,
                            "method_signature": webview_api.method_signature,
                            "dex_file": webview_api.dex_file
                        },
                        rule_id=self.rule_id
                    )
                    findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 9: Dynamic Code Loading
# ============================================================================

class DynamicCodeLoadingRule(BaseRule):
    """
    Check for dynamic code loading mechanisms.
    
    Loading code dynamically from dex files or other sources bypasses
    static analysis and enables runtime code injection attacks.
    
    OWASP: M7: Insufficient Binary Protections
    """
    
    @property
    def rule_id(self) -> str:
        return "DYNAMIC_CODE_LOADING"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            if data.dynamic_code_apis:
                # Report once if any dynamic code loading is found
                finding = Finding(
                    title="Dynamic Code Loading Detected",
                    description=(
                        f"The app loads code dynamically using {len(data.dynamic_code_apis)} API call(s). "
                        "Dynamic code loading can bypass static analysis, enable runtime injection "
                        "attacks, and make code flow difficult to understand and verify."
                    ),
                    owasp_category="M7: Insufficient Binary Protections",
                    severity="Medium",
                    remediation=(
                        "Avoid dynamic code loading if possible. If required, verify code integrity "
                        "and authenticity before loading. Cryptographically sign loaded code. "
                        "Implement strict code review and testing for dynamic code paths."
                    ),
                    affected_component="Dynamic Code Loading",
                    evidence={
                        "dynamic_code_apis_count": len(data.dynamic_code_apis),
                        "apis_used": [api.api_called for api in data.dynamic_code_apis]
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 10: SQL Injection Risk
# ============================================================================

class SQLInjectionRiskRule(BaseRule):
    """
    Check for potential SQL injection vulnerabilities.
    
    SQL strings built via concatenation with variables can be exploited
    to extract or modify database contents.
    
    OWASP: M4: Insufficient Input/Output Validation
    """
    
    @property
    def rule_id(self) -> str:
        return "SQL_INJECTION_RISK"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            sql_patterns = [
                r'SELECT\s+\*?\s+FROM',
                r'INSERT\s+INTO',
                r'UPDATE\s+\w+\s+SET',
                r'DELETE\s+FROM',
            ]
            
            for string in data.strings:
                # Check if string contains SQL keywords
                string_upper = string.value.upper()
                has_sql = any(re.search(p, string_upper) for p in sql_patterns)
                
                # Check for concatenation patterns (simplified heuristic)
                has_concat = ' + ' in string.value or ' || ' in string.value
                
                if has_sql and has_concat:
                    finding = Finding(
                        title="Potential SQL Injection Vulnerability",
                        description=(
                            "A SQL statement was found with apparent string concatenation. "
                            "This pattern suggests user input may be concatenated into SQL queries, "
                            "which can lead to SQL injection attacks."
                        ),
                        owasp_category="M4: Insufficient Input/Output Validation",
                        severity="High",
                        remediation=(
                            "Always use parameterized queries (prepared statements) instead of "
                            "string concatenation. Use the '?' placeholder in SQL and bind parameters. "
                            "Consider using an ORM or database abstraction layer. "
                            "Implement strict input validation as defense-in-depth."
                        ),
                        affected_component=string.dex_file,
                        evidence={
                            "sql_string": string.value,
                            "dex_file": string.dex_file,
                            "pattern": "SQL with concatenation"
                        },
                        rule_id=self.rule_id
                    )
                    findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 11: Insecure Network Security Config
# ============================================================================

class InsecureNetworkSecurityConfigRule(BaseRule):
    """
    Check network security config for insecure settings.
    
    Network security config can permit cleartext traffic or fail to implement
    certificate pinning, allowing MITM attacks.
    
    OWASP: M5: Insecure Communication
    """
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_NETWORK_CONFIG"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            if data.network_security_config:
                # Parse the XML
                try:
                    root = ET.fromstring(data.network_security_config)
                except Exception as e:
                    self._log_error(f"Failed to parse network security config: {str(e)}")
                    return findings
                
                # Check for cleartext traffic
                for domain_config in root.findall('.//domain-config'):
                    cleartext = domain_config.get('cleartextTrafficPermitted')
                    if cleartext and cleartext.lower() == 'true':
                        finding = Finding(
                            title="Network Security Config Allows Cleartext Traffic",
                            description=(
                                "The network security config permits cleartext (HTTP) traffic "
                                "for certain domains. This allows MITM attacks."
                            ),
                            owasp_category="M5: Insecure Communication",
                            severity="High",
                            remediation=(
                                "Set cleartextTrafficPermitted to 'false' for all domains. "
                                "Implement domain-config with pin-set for certificate pinning. "
                                "Ensure all backend communication uses HTTPS."
                            ),
                            affected_component="network_security_config",
                            evidence={
                                "issue": "cleartext_traffic_permitted",
                                "config_type": "domain_config"
                            },
                            rule_id=self.rule_id
                        )
                        findings.append(finding)
                
                # Check for missing pinning (optional check)
                pin_sets = root.findall('.//pin-set')
                if not pin_sets:
                    # This is informational, not necessarily a finding
                    pass
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 12: Static IV in Cryptography
# ============================================================================

class StaticIVRule(BaseRule):
    """
    Check for static or hardcoded IVs in cryptographic operations.
    
    Reusing the same IV for multiple encryptions with the same key
    leaks information and violates cryptographic best practices.
    
    OWASP: M10: Insufficient Cryptography
    """
    
    @property
    def rule_id(self) -> str:
        return "STATIC_IV"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            for crypto_api in data.crypto_apis:
                # Look for IvParameterSpec
                if 'IvParameterSpec' in crypto_api.api_called:
                    for param in crypto_api.parameters:
                        # Check if parameter looks like a hardcoded value
                        # (hex string, base64, or literal bytes)
                        if self._looks_like_hardcoded(param):
                            finding = Finding(
                                title="Static IV in Cryptographic Operation",
                                description=(
                                    "A hardcoded or static initialization vector (IV) was found. "
                                    "Using the same IV with the same key leaks information and "
                                    "violates cryptographic principles. Each encryption must use "
                                    "a unique IV."
                                ),
                                owasp_category="M10: Insufficient Cryptography",
                                severity="Critical",
                                remediation=(
                                    "Generate a new random IV for each encryption operation. "
                                    "Use SecureRandom to generate IVs. Never hardcode IVs. "
                                    "Transmit the IV with the ciphertext (IVs don't need to be secret). "
                                    "Use authenticated encryption modes like AES-GCM."
                                ),
                                affected_component=crypto_api.api_called,
                                evidence={
                                    "api_called": crypto_api.api_called,
                                    "parameter": param,
                                    "dex_file": crypto_api.dex_file
                                },
                                rule_id=self.rule_id
                            )
                            findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings
    
    @staticmethod
    def _looks_like_hardcoded(value: str) -> bool:
        """Check if a value looks like a hardcoded IV."""
        # Hex string pattern
        if re.match(r'^[0-9a-fA-F]{16,}$', value):
            return True
        
        # Base64 pattern (rough)
        if re.match(r'^[A-Za-z0-9+/=]{16,}$', value):
            return True
        
        # Literal hex notation
        if re.match(r'^(0x[0-9a-fA-F]{2})+$', value):
            return True
        
        return False