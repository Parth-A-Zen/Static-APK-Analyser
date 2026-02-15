"""
Security Rules Module - Rewritten for AnalysisReadyAPK v2.3

Fully optimized to use structured data from scope_filter with confidence scores,
pre-categorized APIs, and intelligent filtering to minimize false positives.

Author: APK Security Analysis Engine
License: MIT
Version: 7.0 - Structured Data Optimized
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Set, Optional, Tuple, Dict, Any
from dataclasses import dataclass

from Analyser.Engine.base_rule import BaseRule
from Analyser.Engine.finding import Finding
from Analyser.Loader.scope_filter import AnalysisReadyAPK

logger = logging.getLogger(__name__)


# ============================================================================
# OWASP Mobile Top 10 2024 Constants
# ============================================================================

OWASP_M1 = "M1: Improper Credential Usage"
OWASP_M4 = "M4: Insufficient Input/Output Validation"
OWASP_M5 = "M5: Insecure Communication"
OWASP_M6 = "M6: Inadequate Privacy Controls"
OWASP_M7 = "M7: Insufficient Binary Protections"
OWASP_M8 = "M8: Security Misconfiguration"
OWASP_M9 = "M9: Insecure Data Storage"
OWASP_M10 = "M10: Insufficient Cryptography"

# ============================================================================
# RULE 1: Hardcoded Secrets - Structured Data Optimized
# ============================================================================

class HardcodedSecretRule(BaseRule):
    """
    Detect hardcoded secrets using pre-computed confidence scores from scope_filter.
    
    Leverages:
    - data.strings with confidence field (0.0-1.0)
    - pattern_matched field (provider-specific patterns)
    - entropy and looks_like_api_key flags
    
    Threshold: confidence >= 0.5 for provider-specific, >= 0.6 for generic
    """
    
    # Confidence thresholds
    MIN_CONFIDENCE_PROVIDER = 0.5  # AWS, Google, Stripe etc.
    MIN_CONFIDENCE_GENERIC = 0.6   # High entropy with keywords
    MIN_CONFIDENCE_LOW = 0.4       # Promo codes, weak patterns
    
    # Security keywords for context validation
    SECURITY_KEYWORDS = {
        "key", "secret", "token", "password", "pass", "pwd", "credential",
        "auth", "api", "apikey", "api_key", "aws", "firebase", "google",
        "promo", "bearer", "private", "signature", "encrypt", "decrypt"
    }
    
    @property
    def rule_id(self) -> str:
        return "HARDCODED_SECRET"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if there are security-relevant strings."""
        return len(data.strings) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen_values: Set[str] = set()
        
        try:
            for string in data.strings:
                # Skip short strings
                if string.length < 8:
                    continue
                
                # Deduplicate by value prefix
                value_key = string.value[:100]
                if value_key in seen_values:
                    continue
                
                # Skip if noise (already filtered by scope_filter, but double-check)
                if self.is_noise(string.dex_file):
                    continue
                
                # Determine severity and threshold based on pattern
                severity, threshold = self._determine_severity_and_threshold(string)
                
                # Apply confidence threshold
                if string.confidence < threshold:
                    continue
                
                # Additional validation for generic patterns
                if string.confidence < 0.7 and not self._has_security_context(string.value):
                    continue
                
                seen_values.add(value_key)
                
                # Build finding
                pattern_desc = string.pattern_matched or "High Entropy Secret"
                
                finding = Finding(
                    title=f"Hardcoded Secret Detected: {pattern_desc}",
                    description=(
                        f"Potential hardcoded secret found with {string.confidence:.0%} confidence. "
                        f"Pattern: {string.pattern_matched or 'Generic'}. "
                        f"Length: {string.length}, Entropy: {string.entropy:.2f if string.entropy else 0:.2f}. "
                        f"Hardcoded secrets in source code can be extracted by decompiling the APK."
                    ),
                    owasp_category=OWASP_M1,
                    severity=severity,
                    remediation=(
                        "Remove all hardcoded secrets from source code. "
                        "Use Android Keystore for cryptographic keys. "
                        "Fetch API keys from secure backend at runtime. "
                        "Rotate any exposed credentials immediately."
                    ),
                    affected_component=string.dex_file,
                    evidence={
                        "value_preview": string.value[:80] + ("..." if len(string.value) > 80 else ""),
                        "length": string.length,
                        "entropy": round(string.entropy, 2) if string.entropy else None,
                        "pattern": string.pattern_matched,
                        "confidence": round(string.confidence, 2),
                        "looks_like_api_key": string.looks_like_api_key,
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
                
                # Limit findings to avoid spam
                if len(findings) >= 20:
                    break
                    
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings
    
    def _determine_severity_and_threshold(self, string) -> Tuple[str, float]:
        """
        Determine severity and confidence threshold based on pattern type.
        
        Returns: (severity, min_confidence_threshold)
        """
        pattern = string.pattern_matched or ""
        
        # Provider-specific patterns (AWS, Google, GitHub, Stripe, etc.)
        if any(provider in pattern.lower() for provider in 
               ["aws", "google", "github", "stripe", "slack", "firebase", "twilio"]):
            return ("Critical", self.MIN_CONFIDENCE_PROVIDER)
        
        # Private keys
        if "private" in pattern.lower() and "key" in pattern.lower():
            return ("Critical", self.MIN_CONFIDENCE_PROVIDER)
        
        # Generic API keys with high confidence
        if "api key" in pattern.lower() or string.looks_like_api_key:
            return ("High", self.MIN_CONFIDENCE_GENERIC)
        
        # Passwords and credentials
        if any(kw in pattern.lower() for kw in ["password", "credential", "token"]):
            return ("High", self.MIN_CONFIDENCE_GENERIC)
        
        # Promo codes and activation keys (lower severity)
        if any(kw in pattern.lower() for kw in ["promo", "activation", "license"]):
            return ("Medium", self.MIN_CONFIDENCE_LOW)
        
        # Default: high entropy secret
        return ("High", self.MIN_CONFIDENCE_GENERIC)
    
    def _has_security_context(self, value: str) -> bool:
        """Check if string contains security-relevant keywords."""
        value_lower = value.lower()
        return any(kw in value_lower for kw in self.SECURITY_KEYWORDS)


# ============================================================================
# RULE 2: Weak Cryptography - Structured API Analysis
# ============================================================================

class WeakCryptoAlgorithmRule(BaseRule):
    """
    Detect weak cryptographic algorithms using data.crypto_apis with parameters.
    
    Leverages:
    - data.crypto_apis (CryptoAPI objects with parameters list)
    - data.crypto_weak_apis (pre-filtered weak crypto)
    """
    
    WEAK_ALGORITHMS = {
        "ECB": ("Critical", "ECB mode leaks plaintext patterns"),
        "DES": ("Critical", "DES uses 56-bit keys, breakable in hours"),
        "3DES": ("High", "Triple DES deprecated by NIST as of 2023"),
        "DESEDE": ("High", "DESede (Triple DES) deprecated by NIST"),
        "MD5": ("Medium", "MD5 has known collision attacks"),
        "SHA1": ("Medium", "SHA-1 has demonstrated collision attacks"),
        "SHA-1": ("Medium", "SHA-1 has demonstrated collision attacks"),
        "RC4": ("Critical", "RC4 has systematic biases and is broken"),
        "RC2": ("High", "RC2 has known weaknesses"),
        "ARCFOUR": ("Critical", "ARCFOUR (RC4) is cryptographically broken"),
        "BLOWFISH": ("Medium", "Blowfish uses 64-bit blocks vulnerable to birthday attacks"),
        "NOPADDING": ("High", "No padding makes encryption deterministic"),
        "PBKDF1": ("High", "PBKDF1 is obsolete, use PBKDF2 or Argon2"),
    }
    
    # Weak key sizes
    MIN_KEY_SIZES = {
        "RSA": 2048,
        "AES": 128,
        "DH": 2048,
    }
    
    @property
    def rule_id(self) -> str:
        return "WEAK_CRYPTO_ALGORITHM"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if crypto APIs are used."""
        return len(data.crypto_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            # Check all crypto APIs for weak algorithms in parameters
            for crypto_api in data.crypto_apis:
                # Skip third-party library calls
                if self.is_noise(crypto_api.dex_file):
                    continue
                
                # Check each parameter for weak algorithms
                for param in crypto_api.parameters:
                    param_upper = param.upper()
                    
                    for algo, (severity, reason) in self.WEAK_ALGORITHMS.items():
                        if algo.upper() in param_upper:
                            # Create unique key
                            key = f"{algo}|{crypto_api.api_called}"
                            if key in seen:
                                continue
                            seen.add(key)
                            
                            # Special case: AES/ECB is especially critical
                            if algo == "ECB" and "AES" in param_upper:
                                severity = "Critical"
                                reason = "AES-ECB mode leaks plaintext patterns - especially dangerous"
                            
                            finding = Finding(
                                title=f"Weak Cryptography: {algo}",
                                description=(
                                    f"Detected use of weak algorithm '{algo}'. {reason}. "
                                    f"Algorithm found in parameter: {param}"
                                ),
                                owasp_category=OWASP_M10,
                                severity=severity,
                                remediation=(
                                    "Use AES-256-GCM for symmetric encryption. "
                                    "Use SHA-256 or SHA-3 for hashing. "
                                    "Use RSA-2048+ with OAEP padding or ECDSA for asymmetric. "
                                    "Use PBKDF2 (600k+ iterations) or Argon2 for password hashing."
                                ),
                                affected_component=crypto_api.api_called,
                                evidence={
                                    "api": crypto_api.api_called,
                                    "parameter": param,
                                    "algorithm": algo,
                                    "dex_file": crypto_api.dex_file,
                                },
                                rule_id=self.rule_id,
                            )
                            findings.append(finding)
                            break  # One finding per parameter
            
            # Check for weak key sizes
            findings.extend(self._check_weak_key_sizes(data, seen))
            
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings
    
    def _check_weak_key_sizes(self, data: AnalysisReadyAPK, seen: Set[str]) -> List[Finding]:
        """Check for weak key sizes in key generation APIs."""
        findings = []
        
        try:
            for crypto_api in data.crypto_apis:
                api_lower = crypto_api.api_called.lower()
                
                # Only check key generation APIs
                if not any(kw in api_lower for kw in ["keygenerator", "keypairgenerator", "keyspec"]):
                    continue
                
                for param in crypto_api.parameters:
                    # Extract numeric key size
                    size_match = re.search(r'\b(\d{2,4})\b', param)
                    if not size_match:
                        continue
                    
                    size = int(size_match.group(1))
                    
                    # Check against minimum sizes
                    for algo, min_size in self.MIN_KEY_SIZES.items():
                        if algo.lower() in api_lower or algo.lower() in param.lower():
                            if size < min_size:
                                key = f"WEAK_KEY_{algo}_{size}"
                                if key in seen:
                                    continue
                                seen.add(key)
                                
                                findings.append(
                                    Finding(
                                        title=f"Weak Key Size: {algo} {size}-bit",
                                        description=(
                                            f"{algo} key size of {size} bits is insufficient. "
                                            f"Minimum recommended: {min_size} bits."
                                        ),
                                        owasp_category=OWASP_M10,
                                        severity="High",
                                        remediation=f"Use {algo} with at least {min_size}-bit keys.",
                                        affected_component=crypto_api.api_called,
                                        evidence={
                                            "algorithm": algo,
                                            "key_size": size,
                                            "minimum_recommended": min_size,
                                            "parameter": param,
                                        },
                                        rule_id=self.rule_id,
                                    )
                                )
        except Exception:
            pass
        
        return findings


# ============================================================================
# RULE 3: WebView JavaScript Enabled
# ============================================================================

class WebViewJavaScriptEnabledRule(BaseRule):
    """
    Detect WebView with JavaScript enabled using data.webview_apis.
    
    Leverages:
    - data.webview_apis (pre-filtered WebView configuration APIs)
    """
    
    @property
    def rule_id(self) -> str:
        return "WEBVIEW_JAVASCRIPT_ENABLED"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if WebView APIs are used."""
        return len(data.webview_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            for webview_api in data.webview_apis:
                # Only check setJavaScriptEnabled calls
                if "setJavaScriptEnabled" not in webview_api.api_called:
                    continue
                
                # Skip third-party libraries
                if self.is_noise(webview_api.dex_file):
                    continue
                
                # Deduplicate
                if webview_api.method_signature in seen:
                    continue
                seen.add(webview_api.method_signature)
                
                # Determine if JS is enabled from method signature
                enabled = self._is_javascript_enabled(webview_api.method_signature)
                
                if enabled is True:
                    severity = "High"
                    desc = "JavaScript explicitly enabled in WebView (true)"
                elif enabled is False:
                    # JS disabled, no finding
                    continue
                else:
                    severity = "Medium"
                    desc = "setJavaScriptEnabled called with indeterminate parameter"
                
                finding = Finding(
                    title="WebView JavaScript Enabled - XSS Risk",
                    description=(
                        f"{desc}. This enables XSS attacks if the WebView loads any "
                        f"untrusted or user-controlled content."
                    ),
                    owasp_category=OWASP_M4,
                    severity=severity,
                    remediation=(
                        "Disable JavaScript unless strictly necessary. "
                        "Implement Content Security Policy (CSP). "
                        "Sanitize all user input. "
                        "Use WebViewClient.shouldOverrideUrlLoading() to validate URLs."
                    ),
                    affected_component=webview_api.api_called,
                    evidence={
                        "api": webview_api.api_called,
                        "js_enabled": enabled,
                        "dex_file": webview_api.dex_file,
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
        sig_lower = sig.lower()
        
        # Check for explicit true/false
        if re.search(r'\btrue\b', sig_lower):
            return True
        if re.search(r'\bfalse\b', sig_lower):
            return False
        
        # Check for const values (0x1 = true, 0x0 = false)
        if re.search(r'const[^,]*,\s*0x1\b', sig):
            return True
        if re.search(r'const[^,]*,\s*0x0\b', sig):
            return False
        
        return None


# ============================================================================
# RULE 4: SQL Injection Risk
# ============================================================================

class SQLInjectionRiskRule(BaseRule):
    """
    Detect SQL injection vulnerabilities using data.sql_apis and data.storage_apis.
    
    Leverages:
    - data.sql_apis (source-sink correlation)
    - data.storage_apis (rawQuery, execSQL methods)
    - data.strings (SQL query strings with concatenation)
    """
    
    SQL_KEYWORDS = [
        r'\bSELECT\s+', r'\bINSERT\s+INTO\b', r'\bUPDATE\s+\w+\s+SET\b',
        r'\bDELETE\s+FROM\b', r'\bCREATE\s+TABLE\b', r'\bWHERE\s+',
    ]
    
    RAW_QUERY_METHODS = {"rawQuery", "execSQL", "rawQueryWithFactory", "compileStatement"}
    
    @property
    def rule_id(self) -> str:
        return "SQL_INJECTION_RISK"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if SQL APIs are used."""
        return len(data.sql_apis) > 0 or len(data.storage_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen_strings: Set[str] = set()
        seen_apis: Set[str] = set()
        
        try:
            # Type 1: SQL strings with concatenation indicators
            for string in data.strings:
                if string.length < 10:
                    continue
                
                value_key = string.value[:80]
                if value_key in seen_strings:
                    continue
                
                # Skip if noise
                if self.is_noise(string.dex_file):
                    continue
                
                upper = string.value.upper()
                
                # Must have SQL keyword
                has_sql = any(re.search(p, upper) for p in self.SQL_KEYWORDS)
                if not has_sql:
                    continue
                
                # Check for concatenation indicators
                concat_indicators = self._get_concat_indicators(string.value)
                if not concat_indicators:
                    continue
                
                seen_strings.add(value_key)
                
                finding = Finding(
                    title="SQL Injection Risk - String Concatenation",
                    description=(
                        "SQL query constructed with string concatenation. "
                        "User input may flow into the query without sanitization, "
                        "enabling SQL injection attacks."
                    ),
                    owasp_category=OWASP_M4,
                    severity="High",
                    remediation=(
                        "Use parameterized queries with '?' placeholders and selection args array. "
                        "Example: db.rawQuery(\"SELECT * FROM users WHERE name=?\", new String[]{userInput})"
                    ),
                    affected_component=string.dex_file,
                    evidence={
                        "sql_fragment": string.value[:150],
                        "concat_indicators": concat_indicators,
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
                
                # Limit SQL string findings
                if len(findings) >= 10:
                    break
            
            # Type 2: Raw query method usage from storage_apis
            for api in data.storage_apis:
                api_name = api.api_called.split(".")[-1] if "." in api.api_called else api.api_called
                
                if api_name in self.RAW_QUERY_METHODS:
                    if api.method_signature in seen_apis:
                        continue
                    seen_apis.add(api.method_signature)
                    
                    # Skip third-party
                    if self.is_noise(api.dex_file):
                        continue
                    
                    finding = Finding(
                        title=f"Raw SQL Query Method: {api_name}",
                        description=(
                            f"App uses {api.api_called} which executes raw SQL. "
                            f"If parameters are not properly bound, this is vulnerable to SQL injection."
                        ),
                        owasp_category=OWASP_M4,
                        severity="Medium",
                        remediation=(
                            "Always use selection args parameter for user input. "
                            "Prefer ContentProvider or Room DAO over raw queries."
                        ),
                        affected_component=api.api_called,
                        evidence={
                            "api": api.api_called,
                            "dex_file": api.dex_file,
                        },
                        rule_id=self.rule_id,
                    )
                    findings.append(finding)
            
            # Type 3: Use data.sql_apis (source-sink correlation)
            for api in data.sql_apis:
                if api.method_signature in seen_apis:
                    continue
                seen_apis.add(api.method_signature)
                
                # Skip third-party
                if self.is_noise(api.dex_file):
                    continue
                
                finding = Finding(
                    title="SQL Sink API - Injection Risk",
                    description=(
                        f"SQL sink API detected: {api.api_called}. "
                        f"This API is flagged by source-sink analysis as a potential injection point."
                    ),
                    owasp_category=OWASP_M4,
                    severity="Medium",
                    remediation="Validate all input and use parameterized queries.",
                    affected_component=api.api_called,
                    evidence={
                        "api": api.api_called,
                        "category": api.category,
                        "dex_file": api.dex_file,
                    },
                    rule_id=self.rule_id,
                )
                findings.append(finding)
                
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings
    
    @staticmethod
    def _get_concat_indicators(value: str) -> List[str]:
        """Detect concatenation patterns."""
        indicators = []
        if " + " in value:
            indicators.append("string_plus_concat")
        if " || " in value:
            indicators.append("sql_concat_operator")
        if re.search(r'%[sd]', value):
            indicators.append("format_string")
        if "append" in value.lower():
            indicators.append("string_builder_append")
        if re.search(r'\$\{', value):
            indicators.append("string_template")
        return indicators


# ============================================================================
# RULE 5: Insecure Logging
# ============================================================================

class InsecureLoggingRule(BaseRule):
    """
    Detect insecure logging using data.strings for log method references.
    
    Leverages:
    - data.strings with log method and sensitive keyword detection
    """
    
    SENSITIVE_KEYWORDS = {
        "password", "passwd", "pwd", "secret", "token", "credential",
        "auth", "bearer", "session", "cookie", "ssn", "credit", "cvv",
        "pin", "api_key", "apikey", "private_key", "otp", "mfa",
    }
    
    LOG_METHODS = {
        "Log.d", "Log.v", "Log.i", "Log.w", "Log.e", "Log.wtf",
        "println", "System.out", "System.err", "Logger.", "Timber.",
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
                # Skip if noise
                if self.is_noise(string.dex_file):
                    continue
                
                value_lower = string.value.lower()
                
                # Must have log method reference
                has_log = any(log in string.value for log in self.LOG_METHODS)
                if not has_log:
                    continue
                
                # Must have sensitive keywords
                sensitive = [kw for kw in self.SENSITIVE_KEYWORDS if kw in value_lower]
                if not sensitive:
                    continue
                
                # Deduplicate by sensitive keywords + value prefix
                key = (tuple(sorted(sensitive[:3])), string.value[:80])
                if key in seen:
                    continue
                seen.add(key)
                
                # Higher severity for credential logging
                severity = "Medium"
                if any(kw in sensitive for kw in ["password", "passwd", "pwd", "secret", "token", "credential"]):
                    severity = "High"
                
                finding = Finding(
                    title="Insecure Logging of Sensitive Data",
                    description=(
                        f"Log statement may expose sensitive data to logcat. "
                        f"Sensitive keywords: {', '.join(sensitive[:5])}. "
                        f"Any app with READ_LOGS permission or ADB access can read these."
                    ),
                    owasp_category=OWASP_M9,
                    severity=severity,
                    remediation=(
                        "Remove all sensitive data from log statements. "
                        "Use ProGuard/R8 to strip Log.d/Log.v in release builds. "
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
                
                # Limit findings
                if len(findings) >= 15:
                    break
                    
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 6: Dynamic Code Loading
# ============================================================================

class DynamicCodeLoadingRule(BaseRule):
    """
    Detect dynamic code loading using data.dynamic_code_apis.
    
    Leverages:
    - data.dynamic_code_apis (pre-filtered DexClassLoader, PathClassLoader, etc.)
    """
    
    @property
    def rule_id(self) -> str:
        return "DYNAMIC_CODE_LOADING"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if dynamic code loading APIs are used."""
        return len(data.dynamic_code_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            if data.dynamic_code_apis:
                # Get unique APIs
                apis_used = list(set(api.api_called for api in data.dynamic_code_apis 
                                   if not self.is_noise(api.dex_file)))
                
                if apis_used:
                    finding = Finding(
                        title="Dynamic Code Loading Detected",
                        description=(
                            f"App loads code dynamically ({len(data.dynamic_code_apis)} call sites). "
                            f"APIs: {', '.join(apis_used[:5])}. "
                            f"Dynamic code loading can bypass static analysis and load malicious payloads."
                        ),
                        owasp_category=OWASP_M7,
                        severity="Medium",
                        remediation=(
                            "Verify code integrity/signatures before loading. "
                            "Load only from trusted sources. "
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
# RULE 7: Network Security Config Issues
# ============================================================================

class InsecureNetworkSecurityConfigRule(BaseRule):
    """
    Analyze network_security_config.xml using data.network_security_config.
    
    Leverages:
    - data.network_security_config (raw XML string)
    - data.uses_cleartext_traffic (boolean flag)
    """
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_NETWORK_CONFIG"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Check if config exists
            if not data.network_security_config:
                # No config - check target SDK
                target_sdk = int(data.target_sdk_version) if data.target_sdk_version and data.target_sdk_version.isdigit() else 0
                if target_sdk > 0 and target_sdk < 28:
                    findings.append(
                        Finding(
                            title="Missing Network Security Config (Pre-API 28)",
                            description=(
                                f"No network_security_config.xml and app targets SDK {target_sdk} (< 28). "
                                f"Cleartext traffic is allowed by default on older API levels."
                            ),
                            owasp_category=OWASP_M5,
                            severity="Medium",
                            remediation="Add network_security_config.xml to disable cleartext traffic.",
                            affected_component="AndroidManifest.xml",
                            evidence={"target_sdk": target_sdk},
                            rule_id=self.rule_id,
                        )
                    )
                return findings
            
            # Parse XML
            try:
                root = ET.fromstring(data.network_security_config)
            except ET.ParseError as e:
                self._log_error(f"XML parse error: {str(e)}")
                return findings
            
            # Check cleartext traffic
            findings.extend(self._check_cleartext(root))
            
            # Check certificate pinning
            pin_finding = self._check_pinning(root)
            if pin_finding:
                findings.append(pin_finding)
            
            # Check trust anchors
            findings.extend(self._check_trust_anchors(root))
            
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
                        description="Base config permits HTTP for all domains.",
                        owasp_category=OWASP_M5,
                        severity="Critical",
                        remediation='Set cleartextTrafficPermitted="false".',
                        affected_component="network_security_config.xml",
                        evidence={"type": "base-config", "cleartext": True},
                        rule_id=self.rule_id,
                    )
                )
        
        # Domain-specific configs
        for domain_config in root.findall(".//domain-config"):
            if domain_config.get("cleartextTrafficPermitted", "").lower() == "true":
                domains = [d.text for d in domain_config.findall(".//domain") if d.text]
                findings.append(
                    Finding(
                        title="Cleartext Allowed for Specific Domains",
                        description=f"HTTP allowed for: {', '.join(domains[:5])}",
                        owasp_category=OWASP_M5,
                        severity="High",
                        remediation="Use HTTPS for all domains.",
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
                description="Network config defines domains but no certificate pinning.",
                owasp_category=OWASP_M5,
                severity="Medium",
                remediation="Implement <pin-set> with backup pins.",
                affected_component="network_security_config.xml",
                evidence={"domain_configs": len(domain_configs), "pin_sets": 0},
                rule_id=self.rule_id,
            )
        return None
    
    def _check_trust_anchors(self, root: ET.Element) -> List[Finding]:
        """Check for user-installed certificate trust."""
        findings = []
        
        for trust_anchors in root.findall(".//trust-anchors"):
            for cert in trust_anchors.findall(".//certificates"):
                if cert.get("src", "") == "user":
                    findings.append(
                        Finding(
                            title="User Certificates Trusted",
                            description="Network config trusts user-installed certificates (proxy interception).",
                            owasp_category=OWASP_M5,
                            severity="Medium",
                            remediation="Remove user certificate trust for production.",
                            affected_component="network_security_config.xml",
                            evidence={"trust_src": "user"},
                            rule_id=self.rule_id,
                        )
                    )
        
        return findings


# ============================================================================
# RULE 8: Static IV in Cryptography
# ============================================================================

class StaticIVRule(BaseRule):
    """
    Detect hardcoded IVs using data.crypto_apis with parameters.
    
    Leverages:
    - data.crypto_apis filtered for IvParameterSpec
    - Parameter analysis for hardcoded values
    """
    
    @property
    def rule_id(self) -> str:
        return "STATIC_IV"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if crypto APIs are used."""
        return len(data.crypto_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            for api in data.crypto_apis:
                # Only check IvParameterSpec calls
                if "IvParameterSpec" not in api.api_called:
                    continue
                
                # Skip third-party
                if self.is_noise(api.dex_file):
                    continue
                
                # Check parameters for hardcoded IV
                for param in api.parameters:
                    if self._is_hardcoded_iv(param):
                        key = f"{api.api_called}|{api.method_signature}"
                        if key in seen:
                            continue
                        seen.add(key)
                        
                        finding = Finding(
                            title="Static/Hardcoded Initialization Vector (IV)",
                            description=(
                                "Hardcoded IV detected. Reusing IVs with the same key allows "
                                "attackers to detect repeated plaintexts or break confidentiality."
                            ),
                            owasp_category=OWASP_M10,
                            severity="High",
                            remediation=(
                                "Generate a fresh random IV with SecureRandom for every encryption. "
                                "Prepend IV to ciphertext. Never reuse IVs."
                            ),
                            affected_component=api.api_called,
                            evidence={
                                "api": api.api_called,
                                "parameter_hint": param[:60],
                                "dex_file": api.dex_file,
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
        if re.match(r'^[0-9a-fA-F]{16,}$', value):
            return True
        
        # Base64 encoded
        if re.match(r'^[A-Za-z0-9+/]{12,}={0,2}$', value):
            if len(value) % 4 == 0 or value.endswith("="):
                return True
        
        # Hex array notation
        if re.search(r'(0x[0-9a-fA-F]{2}[,\s]*){4,}', value):
            return True
        
        # Byte array literal
        if re.match(r'^\{(\s*-?\d+\s*,?)+\}$', value):
            return True
        
        # All zeros
        if re.match(r'^(00|0)+$', value) and len(value) >= 16:
            return True
        
        return False


# ============================================================================
# RULE 9: Insecure SharedPreferences Storage
# ============================================================================

class InsecureSharedPreferencesRule(BaseRule):
    """
    Detect SharedPreferences usage using data.storage_apis.
    
    Leverages:
    - data.storage_apis filtered for SharedPreferences methods
    """
    
    SENSITIVE_PREF_KEYWORDS = {
        "password", "passwd", "pwd", "token", "secret", "credential",
        "auth", "session", "cookie", "user", "login", "key", "pin",
        "otp", "score", "users",
    }
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_SHARED_PREFERENCES"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if storage APIs are used."""
        return len(data.storage_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        sp_detected = False
        
        try:
            for api in data.storage_apis:
                # Only check SharedPreferences APIs
                if "SharedPreferences" not in api.api_called:
                    continue
                
                # Skip third-party
                if self.is_noise(api.dex_file):
                    continue
                
                # Check for EncryptedSharedPreferences (secure alternative)
                if "EncryptedSharedPreferences" in api.api_called:
                    continue  # This is secure, skip
                
                if api.method_signature in seen:
                    continue
                seen.add(api.method_signature)
                
                # General SharedPreferences finding
                if not sp_detected:
                    sp_detected = True
                    findings.append(
                        Finding(
                            title="SharedPreferences Used for Data Storage",
                            description=(
                                "App uses SharedPreferences which stores data as plaintext XML. "
                                "Vulnerable to extraction via adb backup, root access, or device theft."
                            ),
                            owasp_category=OWASP_M9,
                            severity="Medium",
                            remediation="Use EncryptedSharedPreferences from Jetpack Security library.",
                            affected_component=api.api_called,
                            evidence={"api": api.api_called, "dex_file": api.dex_file},
                            rule_id=self.rule_id,
                        )
                    )
            
            # Check strings for sensitive preference names
            for string in data.strings:
                if self.is_noise(string.dex_file):
                    continue
                
                # Check for SharedPreferences method calls with sensitive keywords
                if "getSharedPreferences" in string.value or "SharedPreferences" in string.value:
                    value_lower = string.value.lower()
                    matched = [kw for kw in self.SENSITIVE_PREF_KEYWORDS if kw in value_lower]
                    
                    if matched:
                        key = f"sensitive_pref_{string.value[:40]}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                Finding(
                                    title=f"Sensitive Data in SharedPreferences",
                                    description=(
                                        f"SharedPreferences with sensitive keyword(s): {', '.join(matched)}. "
                                        f"This data is stored in plaintext XML."
                                    ),
                                    owasp_category=OWASP_M9,
                                    severity="High",
                                    remediation="Use EncryptedSharedPreferences or Android Keystore.",
                                    affected_component=string.dex_file,
                                    evidence={
                                        "reference": string.value[:100],
                                        "sensitive_keywords": matched,
                                    },
                                    rule_id=self.rule_id,
                                )
                            )
                            
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 10: Insecure File Storage
# ============================================================================

class InsecureFileStorageRule(BaseRule):
    """
    Detect insecure file I/O using data.storage_apis and data.file_write_apis.
    
    Leverages:
    - data.file_write_apis (sink APIs for file writes)
    - data.storage_apis (external storage, temp files)
    """
    
    EXTERNAL_STORAGE_APIS = [
        "getExternalStorageDirectory",
        "getExternalFilesDir",
        "getExternalCacheDir",
        "getExternalStoragePublicDirectory",
        "Environment.getExternalStorageDirectory",
    ]
    
    TEMP_FILE_APIS = ["createTempFile", "File.createTempFile", ".tmp", ".temp"]
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_FILE_STORAGE"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if file I/O APIs are used."""
        return len(data.storage_apis) > 0 or len(data.file_write_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            # Check storage_apis for external storage and temp files
            for api in data.storage_apis:
                if self.is_noise(api.dex_file):
                    continue
                
                api_call = api.api_called
                
                # External storage
                if any(ext_api in api_call for ext_api in self.EXTERNAL_STORAGE_APIS):
                    if api.method_signature not in seen:
                        seen.add(api.method_signature)
                        findings.append(
                            Finding(
                                title="External Storage (SD Card) Usage",
                                description=(
                                    "App writes to external/SD card storage. "
                                    "Files are world-readable and accessible to any app."
                                ),
                                owasp_category=OWASP_M9,
                                severity="High",
                                remediation="Use internal storage (getFilesDir()) with MODE_PRIVATE.",
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
                                    "App creates temporary files. "
                                    "Sensitive data may persist on disk and be recoverable."
                                ),
                                owasp_category=OWASP_M9,
                                severity="Medium",
                                remediation=(
                                    "Avoid writing sensitive data to temp files. "
                                    "Encrypt content and delete immediately after use."
                                ),
                                affected_component=api_call,
                                evidence={"api": api_call, "type": "temp_file"},
                                rule_id=self.rule_id,
                            )
                        )
            
            # Check file_write_apis (sink APIs)
            for api in data.file_write_apis:
                if self.is_noise(api.dex_file):
                    continue
                
                if api.method_signature in seen:
                    continue
                seen.add(api.method_signature)
                
                findings.append(
                    Finding(
                        title="File Write Sink API",
                        description=(
                            f"File write sink API detected: {api.api_called}. "
                            f"Flagged by source-sink analysis."
                        ),
                        owasp_category=OWASP_M9,
                        severity="Low",
                        remediation="Ensure sensitive data is encrypted before writing to files.",
                        affected_component=api.api_called,
                        evidence={"api": api.api_called, "category": api.category},
                        rule_id=self.rule_id,
                    )
                )
                
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 11: Root/Emulator Detection
# ============================================================================

class WeakRootDetectionRule(BaseRule):
    """
    Detect root/emulator detection code using data.strings.
    
    Leverages:
    - data.strings for detection indicators
    """
    
    ROOT_INDICATORS = [
        "su", "Superuser", "supersu", "magisk", "root", "rooted",
        "/system/xbin/su", "/system/bin/su", "/sbin/su",
        "com.topjohnwu.magisk", "isRooted", "checkRoot", "detectRoot",
    ]
    
    EMULATOR_INDICATORS = [
        "emulator", "generic", "goldfish", "sdk_gphone",
        "Build.FINGERPRINT", "Build.MODEL", "Genymotion",
        "isEmulator", "detectEmulator",
    ]
    
    @property
    def rule_id(self) -> str:
        return "WEAK_ROOT_EMULATOR_DETECTION"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        root_detected = False
        emulator_detected = False
        root_count = 0
        emulator_count = 0
        
        try:
            for string in data.strings:
                if self.is_noise(string.dex_file):
                    continue
                
                value_lower = string.value.lower()
                
                # Count root indicators
                if not root_detected:
                    for ind in self.ROOT_INDICATORS:
                        if ind.lower() in value_lower:
                            root_count += 1
                            if root_count >= 3:
                                root_detected = True
                                break
                
                # Count emulator indicators
                if not emulator_detected:
                    for ind in self.EMULATOR_INDICATORS:
                        if ind.lower() in value_lower:
                            emulator_count += 1
                            if emulator_count >= 3:
                                emulator_detected = True
                                break
                
                if root_detected and emulator_detected:
                    break
            
            if root_detected:
                strength = "weak" if root_count < 5 else "moderate"
                findings.append(
                    Finding(
                        title="Root Detection Implemented (Bypassable)",
                        description=(
                            f"App implements root detection with {strength} coverage "
                            f"({root_count} indicators). "
                            f"Client-side root detection alone is insufficient."
                        ),
                        owasp_category=OWASP_M7,
                        severity="Low",
                        remediation=(
                            "Use multiple detection methods. "
                            "Implement server-side device attestation (SafetyNet/Play Integrity API). "
                            "Never rely solely on client-side detection."
                        ),
                        affected_component="Root Detection",
                        evidence={"indicator_count": root_count, "strength": strength},
                        rule_id=self.rule_id,
                    )
                )
            
            if emulator_detected:
                strength = "weak" if emulator_count < 5 else "moderate"
                findings.append(
                    Finding(
                        title="Emulator Detection Implemented (Bypassable)",
                        description=(
                            f"App implements emulator detection with {strength} coverage "
                            f"({emulator_count} indicators). "
                            f"Build property checks alone are trivially spoofed."
                        ),
                        owasp_category=OWASP_M7,
                        severity="Low",
                        remediation=(
                            "Combine multiple techniques: hardware sensors, battery, telephony. "
                            "Use Play Integrity API for server-side attestation."
                        ),
                        affected_component="Emulator Detection",
                        evidence={"indicator_count": emulator_count, "strength": strength},
                        rule_id=self.rule_id,
                    )
                )
                
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 12: Insecure WebView Configuration
# ============================================================================

class InsecureWebViewConfigRule(BaseRule):
    """
    Detect insecure WebView configurations using data.webview_sink_apis.
    
    Leverages:
    - data.webview_sink_apis (dangerous WebView methods)
    """
    
    DANGEROUS_METHODS = {
        "setAllowFileAccess": {
            "desc": "Allows WebView to access file:// URLs",
            "severity": "Medium",
            "remediation": "Set setAllowFileAccess(false). Use WebViewAssetLoader.",
        },
        "setAllowFileAccessFromFileURLs": {
            "desc": "Allows JavaScript in file:// to access other files (SOP bypass)",
            "severity": "High",
            "remediation": "Set setAllowFileAccessFromFileURLs(false).",
        },
        "setAllowUniversalAccessFromFileURLs": {
            "desc": "Allows JavaScript in file:// to access any origin (complete SOP bypass)",
            "severity": "Critical",
            "remediation": "Set setAllowUniversalAccessFromFileURLs(false). Never enable.",
        },
        "addJavascriptInterface": {
            "desc": "Exposes Java/Kotlin methods to JavaScript (RCE risk on API < 17)",
            "severity": "High",
            "remediation": "Use WebMessageChannel. Target API 17+ and use @JavascriptInterface.",
        },
        "setWebContentsDebuggingEnabled": {
            "desc": "Enables Chrome DevTools debugging for all WebViews",
            "severity": "High",
            "remediation": "Only enable in debug builds: if (BuildConfig.DEBUG) { ... }",
        },
    }
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_WEBVIEW_CONFIG"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if WebView sink APIs are used."""
        return len(data.webview_sink_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            for api in data.webview_sink_apis:
                if self.is_noise(api.dex_file):
                    continue
                
                # Check if this API matches any dangerous method
                for method, config in self.DANGEROUS_METHODS.items():
                    if method in api.api_called:
                        if api.method_signature in seen:
                            continue
                        seen.add(api.method_signature)
                        
                        owasp = OWASP_M4 if "javascript" in method.lower() else OWASP_M7
                        
                        finding = Finding(
                            title=f"Insecure WebView: {method}",
                            description=config["desc"],
                            owasp_category=owasp,
                            severity=config["severity"],
                            remediation=config["remediation"],
                            affected_component=api.api_called,
                            evidence={"api": api.api_called, "method": method},
                            rule_id=self.rule_id,
                        )
                        findings.append(finding)
                        
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 13: Path Traversal Risk
# ============================================================================

class PathTraversalRiskRule(BaseRule):
    """
    Detect path traversal vulnerabilities using data.strings and data.file_write_apis.
    
    Leverages:
    - data.strings for path traversal patterns
    - data.file_write_apis for File() construction
    """
    
    @property
    def rule_id(self) -> str:
        return "PATH_TRAVERSAL_RISK"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            # Check strings for path traversal patterns
            for string in data.strings:
                if self.is_noise(string.dex_file):
                    continue
                
                if string.length < 3 or string.value in seen:
                    continue
                
                # Direct traversal patterns
                has_traversal = False
                if "../" in string.value or "..\\" in string.value:
                    if "/" in string.value or "\\" in string.value:
                        has_traversal = True
                
                if has_traversal:
                    seen.add(string.value)
                    findings.append(
                        Finding(
                            title="Potential Path Traversal Risk",
                            description=(
                                f"Path traversal pattern detected: '{string.value[:80]}'. "
                                f"If user input influences file paths, attackers can read/write "
                                f"files outside intended directories."
                            ),
                            owasp_category=OWASP_M4,
                            severity="High",
                            remediation=(
                                "Validate all file paths. "
                                "Use File.getCanonicalPath() and verify it starts with expected base. "
                                "Reject paths containing '../'."
                            ),
                            affected_component=string.dex_file,
                            evidence={"path_fragment": string.value[:100]},
                            rule_id=self.rule_id,
                        )
                    )
                    
                    if len(findings) >= 5:
                        break
                        
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 14: Insecure SQLite Database
# ============================================================================

class InsecureSQLiteDatabaseRule(BaseRule):
    """
    Detect unencrypted SQLite database usage using data.storage_apis.
    
    Leverages:
    - data.storage_apis for SQLite APIs
    - data.strings for database file references
    """
    
    SQLITE_APIS = [
        "SQLiteDatabase", "SQLiteOpenHelper", "openOrCreateDatabase",
        "getWritableDatabase", "getReadableDatabase",
    ]
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_SQLITE_DATABASE"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        db_detected = False
        
        try:
            # Check storage_apis for SQLite
            for api in data.storage_apis:
                if self.is_noise(api.dex_file):
                    continue
                
                if any(sqlite_api in api.api_called for sqlite_api in self.SQLITE_APIS):
                    if api.method_signature in seen:
                        continue
                    seen.add(api.method_signature)
                    
                    # Check for SQLCipher (encrypted alternative)
                    if "SQLCipher" in api.api_called or "encrypted" in api.api_called.lower():
                        continue  # This is secure
                    
                    if not db_detected:
                        db_detected = True
                        findings.append(
                            Finding(
                                title="Unencrypted SQLite Database Usage",
                                description=(
                                    "App uses SQLite database. "
                                    "Databases are stored as unencrypted files, readable via "
                                    "adb backup, root access, or device forensics."
                                ),
                                owasp_category=OWASP_M9,
                                severity="Medium",
                                remediation="Use SQLCipher for database encryption or Room with encrypted storage.",
                                affected_component=api.api_called,
                                evidence={"api": api.api_called},
                                rule_id=self.rule_id,
                            )
                        )
                        
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 15: Certificate Validation Bypass
# ============================================================================

class CertificateValidationBypassRule(BaseRule):
    """
    Detect certificate validation bypass using data.network_apis and data.strings.
    
    Leverages:
    - data.network_apis for SSL/TLS configuration
    - data.strings for trust-all patterns
    """
    
    TRUST_ALL_INDICATORS = [
        "TrustAllCerts", "AllowAllHostnameVerifier", "ALLOW_ALL_HOSTNAME_VERIFIER",
        "NullHostnameVerifier", "AcceptAllHostnameVerifier", "X509TrustManager",
        "checkServerTrusted", "setHostnameVerifier", "VERIFY_NONE",
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
                if self.is_noise(string.dex_file):
                    continue
                
                value_lower = string.value.lower()
                
                for indicator in self.TRUST_ALL_INDICATORS:
                    if indicator.lower() in value_lower:
                        key = indicator.lower()
                        if key in seen:
                            continue
                        seen.add(key)
                        
                        severity = "Critical"
                        if indicator in ("X509TrustManager", "checkServerTrusted"):
                            severity = "High"  # Might be legitimate custom implementation
                        
                        findings.append(
                            Finding(
                                title=f"Certificate Validation Bypass: {indicator}",
                                description=(
                                    f"Detected '{indicator}' which may disable SSL/TLS certificate validation. "
                                    f"This allows MITM attacks on HTTPS connections."
                                ),
                                owasp_category=OWASP_M5,
                                severity=severity,
                                remediation=(
                                    "Remove custom TrustManager implementations that accept all certificates. "
                                    "Use platform default TrustManager. "
                                    "Implement certificate pinning for sensitive connections."
                                ),
                                affected_component=string.dex_file,
                                evidence={"indicator": indicator, "context": string.value[:100]},
                                rule_id=self.rule_id,
                            )
                        )
                        break
                        
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 16: Hardcoded Cryptographic Key
# ============================================================================

class HardcodedCryptoKeyRule(BaseRule):
    """
    Detect hardcoded cryptographic keys using data.crypto_apis.
    
    Leverages:
    - data.crypto_apis filtered for key construction (SecretKeySpec, PBEKeySpec)
    """
    
    KEY_CONSTRUCTION_APIS = [
        "SecretKeySpec", "PBEKeySpec", "DESedeKeySpec",
        "DESKeySpec", "SecretKey",
    ]
    
    @property
    def rule_id(self) -> str:
        return "HARDCODED_CRYPTO_KEY"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """Only run if crypto APIs are used."""
        return len(data.crypto_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            for api in data.crypto_apis:
                if self.is_noise(api.dex_file):
                    continue
                
                # Only check key construction APIs
                if not any(key_api in api.api_called for key_api in self.KEY_CONSTRUCTION_APIS):
                    continue
                
                # Check parameters for hardcoded keys
                for param in api.parameters:
                    if self._is_hardcoded_key(param):
                        key = f"{api.api_called}|{api.method_signature}"
                        if key in seen:
                            continue
                        seen.add(key)
                        
                        findings.append(
                            Finding(
                                title="Hardcoded Cryptographic Key",
                                description=(
                                    f"Cryptographic key appears hardcoded in {api.api_called}. "
                                    f"Hardcoded keys can be extracted by decompiling the APK."
                                ),
                                owasp_category=OWASP_M10,
                                severity="Critical",
                                remediation=(
                                    "Generate keys using Android Keystore. "
                                    "Derive keys from user input using PBKDF2. "
                                    "Fetch keys from secure backend. "
                                    "Never embed keys in source code."
                                ),
                                affected_component=api.api_called,
                                evidence={
                                    "api": api.api_called,
                                    "parameter_hint": param[:40] + ("..." if len(param) > 40 else ""),
                                },
                                rule_id=self.rule_id,
                            )
                        )
                        break
            
            # Check for weak PBKDF2 iteration counts
            findings.extend(self._check_weak_pbkdf2(data, seen))
            
        except Exception as e:
            self._log_error(f"Exception: {str(e)}")
        
        self._log_finding(len(findings))
        return findings
    
    def _check_weak_pbkdf2(self, data: AnalysisReadyAPK, seen: Set[str]) -> List[Finding]:
        """Check for weak PBKDF2 iteration counts."""
        findings = []
        
        for api in data.crypto_apis:
            if "PBEKeySpec" not in api.api_called:
                continue
            
            for param in api.parameters:
                # Extract iteration count
                iter_match = re.search(r'\b(\d{1,6})\b', param)
                if iter_match:
                    iterations = int(iter_match.group(1))
                    if 0 < iterations < 100000:  # OWASP minimum is 600k for 2023
                        key = f"weak_pbkdf2_{api.method_signature}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                Finding(
                                    title=f"Weak PBKDF2 Iteration Count: {iterations}",
                                    description=(
                                        f"PBEKeySpec uses only {iterations} iterations. "
                                        f"OWASP recommends minimum 600,000 for PBKDF2-HMAC-SHA256."
                                    ),
                                    owasp_category=OWASP_M10,
                                    severity="High",
                                    remediation="Use at least 600,000 iterations or migrate to Argon2.",
                                    affected_component=api.api_called,
                                    evidence={"iterations": iterations, "recommended": 600000},
                                    rule_id=self.rule_id,
                                )
                            )
        
        return findings
    
    @staticmethod
    def _is_hardcoded_key(value: str) -> bool:
        """Check if parameter looks like a hardcoded key."""
        if len(value) < 8:
            return False
        
        # Hex string key
        if re.match(r'^[0-9a-fA-F]{16,}$', value):
            return True
        
        # Base64 key
        if re.match(r'^[A-Za-z0-9+/]{12,}={0,2}$', value):
            if len(value) % 4 == 0 or value.endswith("="):
                return True
        
        # Quoted string key
        if re.match(r'^["\'].*["\']$', value) and len(value) > 10:
            return True
        
        # Byte array
        if re.match(r'^\{(\s*-?\d+\s*,?)+\}$', value):
            return True
        
        # Hex notation
        if re.search(r'(0x[0-9a-fA-F]{2}[,\s]*){8,}', value):
            return True
        
        return False

# ============================================================================
# RULE 17: Insecure Random Number Generator (ADDED)
# ============================================================================

class InsecureRandomRule(BaseRule):
    """
    Detect use of java.util.Random instead of SecureRandom for security purposes.
    
    java.util.Random is a PRNG that is predictable and not suitable for
    cryptographic operations, token generation, or security-sensitive contexts.
    
    Category: Cryptographic Issues (M10)
    """
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_RANDOM"
    
    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        return len(data.crypto_apis) > 0
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        seen: Set[str] = set()
        
        try:
            # Check crypto_apis for java.util.Random usage
            for api in data.crypto_apis:
                if self.is_noise(api.dex_file):
                    continue
                
                api_lower = api.api_called.lower()
                
                if "java.util.random" in api_lower or (
                    "random" in api_lower and "securerandom" not in api_lower
                ):
                    # Check if used in security context
                    sig_lower = api.method_signature.lower() if api.method_signature else ""
                    security_context = any(
                        kw in sig_lower
                        for kw in [
                            "token", "key", "nonce", "iv", "salt",
                            "session", "otp", "password", "auth",
                            "crypto", "encrypt", "random"
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
                                    f"java.util.Random is predictable; an attacker can predict future values."
                                ),
                                owasp_category=OWASP_M10,
                                severity="High" if security_context else "Medium",
                                remediation=(
                                    "Use java.security.SecureRandom for all security-sensitive "
                                    "random number generation (tokens, keys, IVs, nonces, salts)."
                                ),
                                affected_component=api.api_called,
                                evidence={
                                    "api": api.api_called,
                                    "security_context": security_context,
                                    "dex_file": api.dex_file,
                                },
                                rule_id=self.rule_id,
                            )
                        )
            
            # Also check strings for Random() constructor
            for string in data.strings:
                if self.is_noise(string.dex_file):
                    continue
                
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
# RULE 1: Debuggable Enabled
# ============================================================================

class DebuggableEnabledRule(BaseRule):
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
                    owasp_category=OWASP_M7,
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
                    owasp_category=OWASP_M9,
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
                    owasp_category=OWASP_M5,
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
                    # Build evidence dictionary
                    evidence = {
                        "component_type": component.type,
                        "component_name": component.name,
                        "exported": True,
                        "permission": None,
                        "intent_filters": component.intent_filter_count
                    }
                    # Add dex_file if available (scope_filter may not provide it)
                    if hasattr(component, "dex_file"):
                        evidence["dex_file"] = component.dex_file

                    finding = Finding(
                        title="Unprotected Exported Component",
                        description=(
                            f"The {component.type} '{component.name}' is exported but not "
                            "protected by any permission. Any app on the device can access it, "
                            "potentially leading to privilege escalation or data exposure."
                        ),
                        owasp_category=OWASP_M8,
                        severity="High",
                        remediation=(
                            f"Either set exported=\"false\" if the {component.type} is not needed "
                            "by other apps, or add a custom permission to protect it. For system "
                            "components, implement proper input validation."
                        ),
                        affected_component=component.name,
                        evidence=evidence,
                        rule_id=self.rule_id
                    )
                    findings.append(finding)
                    
                    # Limit to avoid spam
                    if len(findings) >= 20:
                        self._log_error(f"Limiting findings to 20 (found more)")
                        break
        
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
                    title=f"Dangerous Permission: {perm_short}",
                    description=(
                        f"The app requests the dangerous permission '{permission}'. "
                        "This permission provides access to sensitive user data or hardware. "
                        "Verify the app actually needs this permission."
                    ),
                    owasp_category=OWASP_M1,
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
                
                # Limit findings
                if len(findings) >= 15:
                    self._log_error(f"Limiting dangerous permissions to 15 (found {len(data.dangerous_permissions)} total)")
                    break
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 6: Custom URL Scheme / Deep Link Vulnerability
# ============================================================================

class CustomURLSchemeRule(BaseRule):
    """
    Check for custom URL schemes that may be vulnerable to hijacking.
    
    Custom URL schemes without proper validation can be exploited for
    phishing, data injection, or unauthorized actions.
    
    OWASP: M4: Insufficient Input/Output Validation
    """
    
    @property
    def rule_id(self) -> str:
        return "CUSTOM_URL_SCHEME"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Look for components with custom schemes
            for component in data.exported_components:
                if component.has_intent_filters and component.exported:
                    # This is a simplified check - in a real implementation,
                    # you'd parse intent-filter data elements to find schemes
                    # For now, flag any exported activity with intent filters
                    if component.type == "activity":
                        finding = Finding(
                            title="Potential Deep Link Vulnerability",
                            description=(
                                f"The activity '{component.name}' is exported with intent filters. "
                                "If it handles custom URL schemes or app links, ensure proper "
                                "validation of incoming data to prevent injection attacks."
                            ),
                            owasp_category=OWASP_M4,
                            severity="Medium",
                            remediation=(
                                "Validate all data received from deep links. Use app links "
                                "(with domain verification) instead of custom URL schemes. "
                                "Implement proper authentication for sensitive actions triggered "
                                "by deep links."
                            ),
                            affected_component=component.name,
                            evidence={
                                "component_type": component.type,
                                "exported": True,
                                "intent_filters": component.intent_filter_count
                            },
                            rule_id=self.rule_id
                        )
                        findings.append(finding)
                        
                        if len(findings) >= 10:
                            break
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 7: Missing Certificate Pinning
# ============================================================================

class MissingCertificatePinningRule(BaseRule):
    """
    Check if certificate pinning is implemented.
    
    Without certificate pinning, the app is vulnerable to MITM attacks
    using rogue certificates.
    
    OWASP: M5: Insecure Communication
    """
    
    @property
    def rule_id(self) -> str:
        return "MISSING_CERTIFICATE_PINNING"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Check if network security config exists and has pinning
            has_nsc = data.network_security_config is not None
            has_pinning = False
            
            if has_nsc and data.network_security_config:
                # Simple check for pin-set or pins in the config
                has_pinning = 'pin-set' in data.network_security_config or 'pins' in data.network_security_config
            
            # Also check for programmatic pinning in network APIs
            has_programmatic_pinning = any(
                'CertificatePinner' in api.api_called or 'PinningTrustManager' in api.api_called
                for api in data.network_apis
            )
            
            if not has_pinning and not has_programmatic_pinning:
                finding = Finding(
                    title="Certificate Pinning Not Detected",
                    description=(
                        "The app does not appear to implement certificate pinning. "
                        "This makes it vulnerable to man-in-the-middle attacks using "
                        "rogue or compromised certificates."
                    ),
                    owasp_category=OWASP_M5,
                    severity="Medium",
                    remediation=(
                        "Implement certificate pinning using either network security config "
                        "(pin-set) or programmatically (OkHttp CertificatePinner). Pin both "
                        "the certificate and backup pins. Monitor pin expiration."
                    ),
                    affected_component="Network Security Configuration",
                    evidence={
                        "has_network_security_config": has_nsc,
                        "has_pinning": has_pinning,
                        "network_apis_count": len(data.network_apis)
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 8: Clipboard Data Leakage
# ============================================================================

class ClipboardDataLeakageRule(BaseRule):
    """
    Check for clipboard usage that may leak sensitive data.
    
    Clipboard data can be accessed by other apps and should not contain
    sensitive information.
    
    OWASP: M9: Insecure Data Storage
    """
    
    @property
    def rule_id(self) -> str:
        return "CLIPBOARD_DATA_LEAKAGE"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Check storage APIs for clipboard operations
            clipboard_apis = [
                api for api in data.storage_apis
                if 'ClipboardManager' in api.api_called or 'clipboard' in api.api_called.lower()
            ]
            
            if clipboard_apis:
                finding = Finding(
                    title="Clipboard Usage Detected",
                    description=(
                        f"The app uses clipboard operations ({len(clipboard_apis)} API call(s)). "
                        "Clipboard data can be accessed by other apps and may leak sensitive "
                        "information like passwords, tokens, or personal data."
                    ),
                    owasp_category=OWASP_M9,
                    severity="Low",
                    remediation=(
                        "Avoid copying sensitive data to the clipboard. If clipboard usage "
                        "is necessary, clear clipboard data after use or set a content URI "
                        "with appropriate permissions. Consider using Android 13+ sensitive "
                        "content redaction."
                    ),
                    affected_component="Clipboard APIs",
                    evidence={
                        "clipboard_api_count": len(clipboard_apis),
                        "sample_apis": [api.api_called for api in clipboard_apis[:3]]
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 9: Insecure Broadcast
# ============================================================================

class InsecureBroadcastRule(BaseRule):
    """
    Check for insecure broadcast operations.
    
    Broadcasts without permissions can be received by any app, potentially
    leaking sensitive data.
    
    OWASP: M8: Security Misconfiguration
    """
    
    @property
    def rule_id(self) -> str:
        return "INSECURE_BROADCAST"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Check for exported broadcast receivers without permissions
            insecure_receivers = [
                comp for comp in data.exported_components
                if comp.type == "receiver" and comp.exported and not comp.permission
            ]
            
            if insecure_receivers:
                for receiver in insecure_receivers[:10]:  # Limit to 10
                    finding = Finding(
                        title="Unprotected Broadcast Receiver",
                        description=(
                            f"The broadcast receiver '{receiver.name}' is exported without "
                            "permission protection. Any app can send broadcasts to it, "
                            "potentially triggering unintended behavior or data leakage."
                        ),
                        owasp_category=OWASP_M8,
                        severity="Medium",
                        remediation=(
                            "Add permission protection to the receiver or set exported=\"false\". "
                            "Use LocalBroadcastManager for intra-app communication. Validate "
                            "all received broadcast data."
                        ),
                        affected_component=receiver.name,
                        evidence={
                            "component_type": "receiver",
                            "exported": True,
                            "permission": None
                        },
                        rule_id=self.rule_id
                    )
                    findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 10: Tapjacking / Screen Overlay Attack
# ============================================================================

class TapjackingRule(BaseRule):
    """
    Check for missing tapjacking protection.
    
    Apps vulnerable to tapjacking can have malicious overlays placed over
    sensitive UI elements to trick users.
    
    OWASP: M8: Security Misconfiguration
    """
    
    @property
    def rule_id(self) -> str:
        return "TAPJACKING_VULNERABILITY"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Look for SYSTEM_ALERT_WINDOW permission (often used for overlays)
            has_overlay_permission = any(
                'SYSTEM_ALERT_WINDOW' in perm
                for perm in data.dangerous_permissions
            )
            
            # Check for filterTouchesWhenObscured usage (protection against tapjacking)
            has_protection = any(
                'filterTouchesWhenObscured' in s.value
                for s in data.strings[:1000]  # Sample strings
            )
            
            if not has_protection and len(data.exported_components) > 0:
                finding = Finding(
                    title="Potential Tapjacking Vulnerability",
                    description=(
                        "The app does not appear to implement tapjacking protection. "
                        "Malicious apps can overlay UI elements to trick users into "
                        "performing unintended actions (e.g., granting permissions, "
                        "making payments)."
                    ),
                    owasp_category=OWASP_M8,
                    severity="Low",
                    remediation=(
                        "Set filterTouchesWhenObscured=\"true\" on sensitive UI elements "
                        "(buttons, input fields). Check for overlays programmatically using "
                        "FLAG_WINDOW_IS_OBSCURED. Implement additional user confirmation "
                        "for sensitive actions."
                    ),
                    affected_component="UI Components",
                    evidence={
                        "has_overlay_permission": has_overlay_permission,
                        "has_protection": has_protection,
                        "exported_activities": len([c for c in data.exported_components if c.type == "activity"])
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 11: Missing Code Obfuscation
# ============================================================================

class MissingObfuscationRule(BaseRule):
    """
    Check for code obfuscation.
    
    Apps without obfuscation are easier to reverse-engineer, making it
    simpler for attackers to find vulnerabilities or steal IP.
    
    OWASP: M7: Insufficient Binary Protections
    """
    
    @property
    def rule_id(self) -> str:
        return "MISSING_OBFUSCATION"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Simple heuristic: check class name patterns
            # Obfuscated code typically has short, meaningless class names
            sample_classes = data.classes[:100] if data.classes else []
            
            obfuscated_count = 0
            readable_count = 0
            
            for cls in sample_classes:
                # Extract simple class name
                simple_name = cls.simple_name if hasattr(cls, 'simple_name') else cls.name.split('/')[-1].rstrip(';')
                
                # Check if obfuscated (single letter or short random names)
                if len(simple_name) <= 2 or (len(simple_name) == 3 and simple_name.isalpha()):
                    obfuscated_count += 1
                elif len(simple_name) > 3:
                    readable_count += 1
            
            # If most classes are readable, likely not obfuscated
            if readable_count > obfuscated_count and sample_classes:
                obfuscation_ratio = obfuscated_count / len(sample_classes) if sample_classes else 0
                
                finding = Finding(
                    title="Code Obfuscation Not Detected",
                    description=(
                        "The app does not appear to use code obfuscation (ProGuard/R8). "
                        f"Only {obfuscation_ratio*100:.1f}% of sampled classes show obfuscation. "
                        "This makes reverse engineering easier for attackers."
                    ),
                    owasp_category=OWASP_M7,
                    severity="Low",
                    remediation=(
                        "Enable ProGuard or R8 obfuscation in release builds. Configure "
                        "proguard-rules.pro to obfuscate code while preserving necessary "
                        "classes (e.g., reflection targets, serialized classes). Consider "
                        "additional protections like native code or DexGuard."
                    ),
                    affected_component="Build Configuration",
                    evidence={
                        "obfuscated_classes": obfuscated_count,
                        "readable_classes": readable_count,
                        "sample_size": len(sample_classes),
                        "obfuscation_ratio": round(obfuscation_ratio, 2)
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 12: Unprotected Content Provider
# ============================================================================

class UnprotectedContentProviderRule(BaseRule):
    """
    Check for exported content providers without proper protection.
    
    Unprotected content providers can leak sensitive data to other apps.
    
    OWASP: M8: Security Misconfiguration
    """
    
    @property
    def rule_id(self) -> str:
        return "UNPROTECTED_CONTENT_PROVIDER"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Find exported providers without permissions
            unprotected_providers = [
                comp for comp in data.exported_components
                if comp.type == "provider" and comp.exported and not comp.permission
            ]
            
            for provider in unprotected_providers[:10]:  # Limit
                finding = Finding(
                    title="Unprotected Content Provider",
                    description=(
                        f"The content provider '{provider.name}' is exported without "
                        "permission protection. Any app can query, insert, update, or "
                        "delete data, potentially leading to data leakage or manipulation."
                    ),
                    owasp_category=OWASP_M8,
                    severity="High",
                    remediation=(
                        "Add read/write permissions to the provider. Set exported=\"false\" "
                        "if not needed by other apps. Use path permissions to restrict "
                        "access to specific URIs. Implement proper input validation and "
                        "SQL injection protection."
                    ),
                    affected_component=provider.name,
                    evidence={
                        "component_type": "provider",
                        "exported": True,
                        "permission": None
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 13: Task Affinity / Activity Hijacking
# ============================================================================

class TaskAffinityHijackingRule(BaseRule):
    """
    Check for task affinity hijacking vulnerabilities.
    
    Improper task affinity configuration can allow malicious apps to
    hijack activities or steal credentials.
    
    OWASP: M8: Security Misconfiguration
    """
    
    @property
    def rule_id(self) -> str:
        return "TASK_AFFINITY_HIJACKING"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Check for exported activities that might be vulnerable
            # This is a simplified check - full implementation would parse
            # taskAffinity and launchMode attributes
            exported_activities = [
                comp for comp in data.exported_components
                if comp.type == "activity" and comp.exported
            ]
            
            if len(exported_activities) > 0:
                # Check if FLAG_ACTIVITY_NEW_TASK or similar patterns exist
                has_task_flags = any(
                    'FLAG_ACTIVITY_NEW_TASK' in s.value or 'taskAffinity' in s.value
                    for s in data.strings[:1000]
                )
                
                if has_task_flags:
                    finding = Finding(
                        title="Potential Task Affinity Hijacking",
                        description=(
                            f"The app has {len(exported_activities)} exported activity(ies) "
                            "and uses task affinity flags. Improper configuration can allow "
                            "malicious apps to hijack the task stack and phish credentials."
                        ),
                        owasp_category=OWASP_M8,
                        severity="Medium",
                        remediation=(
                            "Review taskAffinity and launchMode settings for exported activities. "
                            "Set android:excludeFromRecents=\"true\" for sensitive activities. "
                            "Implement proper activity lifecycle checks. Consider using "
                            "singleTask or singleInstance launch modes carefully."
                        ),
                        affected_component="Activity Task Management",
                        evidence={
                            "exported_activities": len(exported_activities),
                            "has_task_flags": has_task_flags
                        },
                        rule_id=self.rule_id
                    )
                    findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 14: FLAG_SECURE Missing on Sensitive Screens
# ============================================================================

class MissingFlagSecureRule(BaseRule):
    """
    Check if FLAG_SECURE is used to prevent screenshots of sensitive screens.
    
    Without FLAG_SECURE, sensitive information can be captured via screenshots
    or screen recording, or leaked through recent apps thumbnails.
    
    OWASP: M6: Inadequate Privacy Controls
    """
    
    @property
    def rule_id(self) -> str:
        return "MISSING_FLAG_SECURE"
    
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        self._log_start()
        findings = []
        
        try:
            # Check if FLAG_SECURE is used
            has_flag_secure = any(
                'FLAG_SECURE' in s.value
                for s in data.strings[:2000]
            )
            
            # Look for activities that might handle sensitive data
            has_activities = len([c for c in data.exported_components if c.type == "activity"]) > 0
            
            # Check for password/credential-related strings
            has_sensitive_ui = any(
                keyword in s.value.lower()
                for s in data.strings[:1000]
                for keyword in ['password', 'pin', 'credit', 'card', 'payment', 'ssn', 'account']
            )
            
            if not has_flag_secure and has_activities and has_sensitive_ui:
                finding = Finding(
                    title="FLAG_SECURE Not Detected on Sensitive Screens",
                    description=(
                        "The app handles sensitive information but does not appear to use "
                        "FLAG_SECURE to prevent screenshots and recent apps thumbnails. "
                        "This could allow sensitive data to be captured or leaked."
                    ),
                    owasp_category=OWASP_M6,
                    severity="Medium",
                    remediation=(
                        "Add FLAG_SECURE to windows displaying sensitive information: "
                        "getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, "
                        "WindowManager.LayoutParams.FLAG_SECURE). Apply this to activities "
                        "showing passwords, PINs, payment info, or personal data."
                    ),
                    affected_component="Window Management",
                    evidence={
                        "has_flag_secure": has_flag_secure,
                        "has_activities": has_activities,
                        "has_sensitive_ui": has_sensitive_ui
                    },
                    rule_id=self.rule_id
                )
                findings.append(finding)
        
        except Exception as e:
            self._log_error(f"Exception in rule: {str(e)}")
        
        self._log_finding(len(findings))
        return findings


# ============================================================================
# RULE 18: Keyboard Cache / Input Type Issues (ADDED)
# ============================================================================

class KeyboardCacheRule(BaseRule):
    """
    Detect keyboard cache vulnerability for sensitive input fields.
    
    Sensitive data cached by keyboard (autocomplete/autocorrect not disabled for password fields).
    
    Category: Insecure Data Storage (M9)
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
                if self.is_noise(string.dex_file):
                    continue
                
                value_lower = string.value.lower()
                
                # Look for EditText/input handling without InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                if any(
                    kw in value_lower
                    for kw in ["edittext", "textinputedittext", "inputtype", "setinputtype"]
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
                if self.is_noise(string.dex_file):
                    continue
                
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
                            "Sensitive input fields may have keyboard caching/autocomplete enabled. "
                            "The keyboard stores typed words in a user dictionary file accessible "
                            "to other apps or via backup extraction."
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
                    if self.is_noise(string.dex_file):
                        continue
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
# ALL RULES REGISTRY (UPDATED with 32 rules)
# ============================================================================

ALL_RULES = [
    HardcodedSecretRule,
    WeakCryptoAlgorithmRule,
    WebViewJavaScriptEnabledRule,
    SQLInjectionRiskRule,
    InsecureLoggingRule,
    DynamicCodeLoadingRule,
    InsecureNetworkSecurityConfigRule,
    StaticIVRule,
    InsecureSharedPreferencesRule,
    InsecureFileStorageRule,
    WeakRootDetectionRule,
    InsecureWebViewConfigRule,
    PathTraversalRiskRule,
    InsecureSQLiteDatabaseRule,
    CertificateValidationBypassRule,
    HardcodedCryptoKeyRule,
    InsecureRandomRule,          # Added
    DebuggableEnabledRule,
    AllowBackupEnabledRule,
    CleartextTrafficAllowedRule,
    ExportedComponentWithoutPermissionRule,
    DangerousPermissionDeclaredRule,
    CustomURLSchemeRule,
    MissingCertificatePinningRule,
    ClipboardDataLeakageRule,
    InsecureBroadcastRule,
    TapjackingRule,
    MissingObfuscationRule,
    UnprotectedContentProviderRule,
    TaskAffinityHijackingRule,
    MissingFlagSecureRule,
    KeyboardCacheRule,           # Added
]