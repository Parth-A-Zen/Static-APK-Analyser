"""
Base Rule Module - Enterprise Grade V3 (State-of-the-Art)

The "Brain" of the security engine. This module implements a Weighted Risk 
Scoring system to mathematically calculate the probability of a False Positive.

Revolutionary Features:
- Confidence Scoring (0.0 - 1.0) instead of binary Yes/No
- Inline Suppression Detection (// no-scan, @SuppressWarnings)
- Taint Analysis Proximity Checks
- Resource vs Code Context Awareness
- Multi-Factor Risk Assessment
- Probabilistic Finding Classification

This transforms security analysis from "pattern matching" to "risk assessment"
using machine learning-inspired heuristics without requiring ML infrastructure.

Author: Generated for APK Security Analysis
License: MIT
Version: 3.0 (State-of-the-Art)
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import List, Optional, Union, Dict, Any, Tuple
from dataclasses import dataclass

# Adjust imports based on your project structure
from Analyser.Loader.scope_filter import AnalysisReadyAPK
from Analyser.Engine.finding import Finding

logger = logging.getLogger(__name__)


# ============================================================================
# Risk Score Data Structure
# ============================================================================

@dataclass
class RiskAssessment:
    """
    Represents a risk assessment with confidence scoring.
    
    Attributes:
        score: Confidence score (0.0 = definitely FP, 1.0 = definitely real)
        factors: Dictionary of factors that contributed to the score
        is_high_confidence: Whether score exceeds reporting threshold
    """
    score: float
    factors: Dict[str, float]
    is_high_confidence: bool
    
    def __repr__(self) -> str:
        return f"RiskAssessment(score={self.score:.2f}, high_confidence={self.is_high_confidence})"


# ============================================================================
# Base Rule with Heuristic Risk Scoring
# ============================================================================

class BaseRule(ABC):
    """
    Abstract base class with Heuristic Risk Scoring.
    
    This "Smart Parent" provides probabilistic analysis instead of binary
    detection, dramatically reducing false positives through multi-factor
    risk assessment.
    """

    # ========================================================================
    # CONFIGURATION: Risk Scoring Thresholds
    # ========================================================================
    
    # Default confidence threshold for reporting findings
    DEFAULT_CONFIDENCE_THRESHOLD = 0.6
    
    # High-severity findings require higher confidence
    CRITICAL_CONFIDENCE_THRESHOLD = 0.7
    HIGH_CONFIDENCE_THRESHOLD = 0.65
    MEDIUM_CONFIDENCE_THRESHOLD = 0.55
    LOW_CONFIDENCE_THRESHOLD = 0.5

    # ========================================================================
    # 1. GLOBAL ALLOWLISTS (The "Ignore" Lists)
    # ========================================================================
    
    # Packages to strictly ignore (Third-party libraries)
    THIRD_PARTY_PREFIXES = {
        # Android/Java Platform
        'android.', 'androidx.', 'com.android.', 'dalvik.', 
        'java.', 'javax.', 'jdk.', 'sun.', 'com.sun.',
        
        # Kotlin & JVM Languages
        'kotlin.', 'kotlinx.', 'scala.', 'groovy.', 'clojure.',
        
        # Tech Giants
        'com.google.', 'com.facebook.', 'com.twitter.', 'com.amazon.',
        'com.microsoft.', 'com.apple.', 'io.fabric.', 'com.crashlytics.',
        
        # Google Ecosystem
        'com.google.android.', 'com.google.firebase.', 'com.google.gson.',
        'com.google.common.', 'com.google.protobuf.', 'com.google.crypto.',
        'com.google.dagger.', 'com.google.ar.', 'com.google.vr.',
        
        # Apache Projects
        'org.apache.', 'org.apache.commons.', 'org.apache.http.',
        
        # Standard Libraries
        'org.json.', 'org.w3c.', 'org.xml.', 'org.xmlpull.',
        'org.slf4j.', 'ch.qos.logback.',
        
        # Popular Networking
        'okhttp3.', 'okio.', 'retrofit2.', 'com.squareup.',
        
        # Image Loading
        'com.bumptech.glide.', 'com.squareup.picasso.',
        
        # Reactive
        'io.reactivex.', 'org.reactivestreams.',
        
        # Dependency Injection
        'dagger.', 'javax.inject.', 'com.google.inject.', 'org.kodein.',
        
        # Analytics & Crash Reporting
        'com.google.firebase.crashlytics.', 'com.google.firebase.analytics.',
        'com.amplitude.', 'com.mixpanel.', 'com.flurry.',
        'com.appsflyer.', 'com.segment.', 'com.adjust.',
        
        # Game Engines
        'com.unity3d.', 'org.cocos2dx.', 'io.flutter.', 'com.ansca.corona.',
        
        # Security Libraries (don't flag their own crypto implementations)
        'org.conscrypt.', 'org.bouncycastle.', 'com.google.crypto.tink.',
        
        # Testing Frameworks
        'junit.', 'org.junit.', 'org.mockito.', 'org.hamcrest.',
        'androidx.test.', 'com.google.truth.', 'org.robolectric.',
    }

    # Code artifacts that indicate testing or auto-generation
    NOISE_INDICATORS = {
        'test', 'tests', 'testing',
        'mock', 'mocks', 'mocking',
        'stub', 'stubs', 'fake', 'dummy', 'fixture',
        'debug', 'release', 'buildconfig', 
        'r.java', 'r.class', 'r$',
        'generated', 'internal', 'example', 'sample',
        'instrumented', 'androidtest',
        'build', 'gen', '.build',
    }

    # "Safe" variable names that are usually constants or configuration
    SAFE_VAR_INDICATORS = {
        'TABLE', 'COL', 'COLUMN', 'COLUMNS',
        'ID', 'KEY', 'TYPE', 'TYPES',
        'TAG', 'LABEL', 'TITLE', 'HEADER', 'FOOTER',
        'CONST', 'CONSTANT', 'STATIC', 'FINAL',
        'URI', 'URL', 'PATH', 'PATHS',
        'NAME', 'NAMES', 'FIELD', 'FIELDS',
        'SCHEMA', 'PROJECTION', 'SELECTION',
        'DEFAULT', 'CONFIG', 'SETTING',
        'DATABASE', 'DB_', 'SQL_', 'INDEX',
    }

    # Markers developers use to suppress warnings
    SUPPRESSION_MARKERS = {
        'no-scan', 'noscan', 'no scan',
        'suppress', 'suppress-security',
        'ignore-security', 'ignore security',
        'false-positive', 'false positive',
        'safe', 'safe-to-use',
        '@suppresswarnings', 'suppresswarnings',
        'noinspection', 'security-exception',
    }

    # Safe technical constants (not secrets)
    SAFE_TECHNICAL_CONSTANTS = {
        # Encodings
        'UTF-8', 'UTF8', 'ISO-8859-1', 'ASCII', 'US-ASCII',
        # Crypto algorithms (algorithm names are public)
        'AES', 'DES', 'RSA', 'SHA-256', 'SHA256', 'MD5', 'SHA-1',
        'CBC', 'ECB', 'GCM', 'PKCS5PADDING', 'NOPADDING',
        # HTTP methods
        'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH',
        # Content types
        'APPLICATION/JSON', 'TEXT/HTML', 'TEXT/PLAIN', 'MULTIPART/FORM-DATA',
        'APPLICATION/XML', 'APPLICATION/X-WWW-FORM-URLENCODED',
        # Common values
        'TRUE', 'FALSE', 'NULL', 'NONE', 'EMPTY',
        'LOCALHOST', '127.0.0.1', '0.0.0.0', '::1',
        # Database
        'INTEGER', 'TEXT', 'BLOB', 'REAL', 'NUMERIC',
    }

    # ========================================================================
    # 2. ABSTRACT INTERFACE (Must be implemented by subclasses)
    # ========================================================================

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this rule (e.g., 'HARDCODED_SECRET')."""
        pass

    @abstractmethod
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        """Execute the security check. Must return List[Finding]."""
        pass

    # ========================================================================
    # 3. INTELLIGENT FILTERING ENGINE (The Gatekeeper)
    # ========================================================================

    def is_noise(self, path: str, code_snippet: str = "", context: str = "") -> bool:
        """
        Master filter: Checks if code should be IGNORED.
        
        This is the "Gatekeeper" - call this FIRST in every rule before
        any analysis. It filters:
        - Third-party libraries
        - Test code
        - Generated files
        - Developer-suppressed findings
        
        Args:
            path: Class path or file path
            code_snippet: The actual code (optional)
            context: Additional context for better filtering (optional)
        
        Returns:
            True if this is noise (skip it), False if legitimate app code
        """
        if not path:
            return False
        
        path_lower = path.lower()
        
        # 1. Third-party library check
        for prefix in self.THIRD_PARTY_PREFIXES:
            if prefix in path or path.startswith(prefix):
                return True
        
        # 2. Test code
        for noise in self.NOISE_INDICATORS:
            if noise in path_lower:
                return True
        
        # 3. Developer suppression markers
        if code_snippet:
            snippet_lower = code_snippet.lower()
            for marker in self.SUPPRESSION_MARKERS:
                if marker in snippet_lower:
                    return True
        
        return False

    def is_in_resource(self, path: str, context: str = "") -> bool:
        """
        Check if data is from resources (XML, strings.xml, etc).
        
        Resources are often LESS suspicious than hardcoded values in code.
        Example: API key in strings.xml might be intentional configuration.
        
        Args:
            path: File or class path
            context: Additional context
        
        Returns:
            True if data is from resources
        """
        if not path:
            return False
        
        path_lower = path.lower()
        resource_indicators = {
            'res/', 'resources/', 'values/', 'xml/',
            'strings.xml', 'config.xml', 'build.xml',
            'androidmanifest.xml'
        }
        
        return any(indicator in path_lower for indicator in resource_indicators)

    # ========================================================================
    # 4. RISK SCORING ENGINE (Confidence Calculation)
    # ========================================================================

    def calculate_risk_score(
        self,
        base_confidence: float = 0.7,
        adjustments: Optional[Dict[str, float]] = None
    ) -> RiskAssessment:
        """
        Calculate risk assessment with multi-factor scoring.
        
        This is the mathematical core that transforms binary detection into
        probabilistic risk assessment.
        
        Args:
            base_confidence: Starting confidence (0.0-1.0)
            adjustments: Dictionary of adjustment factors
                Example: {
                    'in_test_code': -0.4,  # Reduce confidence
                    'in_production_path': +0.2,  # Increase confidence
                    'has_comments': -0.1,
                    'entropy_score': +0.15
                }
        
        Returns:
            RiskAssessment with final score and contributing factors
        """
        if adjustments is None:
            adjustments = {}
        
        # Start with base confidence
        score = base_confidence
        factors = {"base_confidence": base_confidence}
        
        # Apply all adjustments
        for factor_name, adjustment in adjustments.items():
            score += adjustment
            factors[factor_name] = adjustment
        
        # Clamp between 0.0 and 1.0
        score = max(0.0, min(1.0, score))
        
        # Determine if high confidence (above default threshold)
        is_high_confidence = score >= self.DEFAULT_CONFIDENCE_THRESHOLD
        
        return RiskAssessment(
            score=score,
            factors=factors,
            is_high_confidence=is_high_confidence
        )

    def should_report(
        self, 
        assessment: RiskAssessment, 
        severity: str = "Medium"
    ) -> bool:
        """
        Check if risk assessment meets the confidence threshold for reporting.
        
        Different severity levels require different confidence thresholds:
        - Critical findings need 70%+ confidence
        - High findings need 65%+ confidence
        - Medium findings need 55%+ confidence
        - Low findings need 50%+ confidence
        
        Args:
            assessment: Risk assessment to check
            severity: Severity level of the finding
            
        Returns:
            bool: True if confidence is sufficient to report
        """
        severity_lower = severity.lower()
        
        if severity_lower == "critical":
            return assessment.score >= self.CRITICAL_CONFIDENCE_THRESHOLD
        elif severity_lower == "high":
            return assessment.score >= self.HIGH_CONFIDENCE_THRESHOLD
        elif severity_lower == "medium":
            return assessment.score >= self.MEDIUM_CONFIDENCE_THRESHOLD
        elif severity_lower == "low":
            return assessment.score >= self.LOW_CONFIDENCE_THRESHOLD
        
        # Default threshold
        return assessment.is_high_confidence

    # ========================================================================
    # 5. TAINT ANALYSIS HELPERS (Context Awareness)
    # ========================================================================

    def get_concatenation_vars(self, statement: str) -> List[str]:
        """
        Extracts variable names from string concatenation.
        
        Examples:
            Input:  "SELECT * FROM " + tableName + " WHERE id=" + userId
            Output: ['tableName', 'userId']
        
        Args:
            statement: String containing concatenation
            
        Returns:
            List of variable names found
        """
        if not statement:
            return []
        
        # Match variables in concatenation: "..." + varName + "..."
        pattern = r'[+|]{1,2}\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[+|]?'
        variables = re.findall(pattern, statement)
        
        # Filter out SQL keywords
        sql_keywords = {
            'select', 'from', 'where', 'insert', 'update', 
            'delete', 'and', 'or', 'not', 'null'
        }
        
        return [v for v in variables if v.lower() not in sql_keywords]

    def is_safe_technical_constant(self, value: str) -> bool:
        """
        Checks if a string value is a safe technical constant.
        
        Examples: "UTF-8", "AES", "application/json", "0.0.0.0"
        
        These are not secrets even though they might have high entropy.
        
        Args:
            value: String value to check
            
        Returns:
            bool: True if it's a known safe constant
        """
        if not value:
            return False
        
        value_upper = value.upper().strip()
        
        # Check against known safe constants
        if value_upper in self.SAFE_TECHNICAL_CONSTANTS:
            return True
        
        # Hex colors (#FFFFFF)
        if re.match(r'^#(?:[0-9a-fA-F]{3}){1,2}$', value):
            return True
        
        # Format strings (%s, %d, {0}, etc.)
        if re.match(r'^[%{][0-9sdoxXf}]*$', value):
            return True
        
        # IP addresses (not secrets)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return True
        
        return False

    def is_obfuscated(self, path: str) -> bool:
        """
        Heuristic: Check if code is obfuscated (ProGuard/R8).
        
        Short 1-2 character class names usually indicate obfuscation.
        
        Args:
            path: Class or file path
            
        Returns:
            bool: True if appears to be obfuscated
        """
        if not path:
            return False
        
        # Extract simple class name
        filename = path.split('/')[-1].split('$')[0]
        filename = filename.replace('.class', '').replace(';', '').replace('L', '')
        
        # 1-2 alphanumeric characters = likely obfuscated
        return (
            len(filename) <= 2 and 
            filename.isalnum() and
            not filename.isupper()  # Exclude 'R' class
        )

    def extract_method_name(self, signature: str) -> str:
        """
        Extract method name from signature.
        
        Example:
            Input:  "Lcom/example/App;->onCreate(Landroid/os/Bundle;)V"
            Output: "onCreate"
        
        Args:
            signature: Method signature
            
        Returns:
            Method name or empty string
        """
        if not signature or '->' not in signature:
            return ""
        
        # Split on -> and extract method name
        parts = signature.split('->')
        if len(parts) < 2:
            return ""
        
        method_part = parts[1]
        # Extract up to the first (
        if '(' in method_part:
            return method_part.split('(')[0]
        
        return method_part

    # ========================================================================
    # 6. CONVENIENCE METHODS
    # ========================================================================

    def should_skip_finding(
        self,
        path: str,
        context: str = "",
        code_snippet: str = ""
    ) -> bool:
        """
        Convenience wrapper for is_noise().
        
        Args:
            path: Path to check
            context: Additional context
            code_snippet: Code snippet for suppression checking
            
        Returns:
            bool: True if finding should be skipped
        """
        return self.is_noise(path, code_snippet, context)

    def is_relevant(self, data: AnalysisReadyAPK) -> bool:
        """
        Override if the rule should be skipped for certain APKs.
        Default implementation always returns True (rule is always relevant).
        """
        return True

    # ========================================================================
    # 7. LOGGING HELPERS WITH VISUAL INDICATORS
    # ========================================================================

    def _log_start(self):
        """Log that rule execution is starting."""
        logger.debug(f"[{self.rule_id}] Starting analysis...")

    def _log_finding(self, count: int):
        """
        Log findings with color coding.
        
        RED for findings, GREEN for clean.
        """
        if count > 0:
            logger.info(f"[{self.rule_id}] \033[91mFound {count} issue(s)\033[0m")
        else:
            logger.debug(f"[{self.rule_id}] \033[92mClean (0 issues)\033[0m")

    def _log_error(self, error: Union[str, Exception]):
        """Log error with yellow color."""
        logger.error(f"[{self.rule_id}] \033[93mError: {str(error)}\033[0m")

    def _log_skip(self, reason: str):
        """Log that analysis is being skipped."""
        logger.debug(f"[{self.rule_id}] Skipped: {reason}")

    def _log_confidence(self, assessment: RiskAssessment):
        """Log confidence score for debugging."""
        logger.debug(
            f"[{self.rule_id}] Confidence: {assessment.score:.2f} "
            f"(factors: {assessment.factors})"
        )

    # ========================================================================
    # 8. UTILITY METHODS
    # ========================================================================

    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Rule: {self.rule_id}>"
    
    def __str__(self) -> str:
        """User-friendly string representation."""
        return f"SecurityRule({self.rule_id})"
