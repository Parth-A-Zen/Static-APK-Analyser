"""
Scope Filter Module

A post-processor for APKModel that filters out non-application data and organizes
remaining information into security-relevant buckets for OWASP Mobile Top 10 analysis.

This module removes Android framework and third-party library code, focusing analysis
on the application's own code and identifying potential security issues.

Author: Generated for APK Security Analysis
License: MIT

Version 2.3 - False Positive Reduction:
- All v2.2 features preserved
- Expanded blocklist patterns: class descriptors (L...;), method descriptors ((...)...;),
  and array descriptors ([L...;) are now excluded from secret detection
- High-entropy detection skips strings that look like code artifacts
  (contain parentheses, slashes, semicolons in signature-like patterns)
- Confidence calculation penalises strings with code-artifact characters
- "Potential API Key" logic requires stronger evidence: security keyword OR
  very high entropy (>5.0), and strings with ; or / are excluded unless
  they contain a clear keyword
- Compatibility with updated apk_loader.py (fixed manifest parsing) maintained
"""

import logging
import math
import re
import functools
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

# Import from apk_loader
try:
    from Analyser.Loader.apk_loader import APKModel, Component, Permission
except ImportError:
    raise ImportError(
        "apk_loader module is required. Ensure apk_loader.py is in the same directory."
    )


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Dataclasses for structured data
@dataclass
class FilteredClass:
    """Filtered class information."""
    name: str           # Internal format (Lcom/example/MyClass;)
    package: str        # Package format (com.example)
    simple_name: str    # Simple class name (MyClass)
    dex_file: str       # Source DEX file
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "package": self.package,
            "simple_name": self.simple_name,
            "dex_file": self.dex_file
        }


@dataclass
class SecurityString:
    """Container for security-relevant string findings."""
    value: str
    dex_file: str
    length: int
    contains_url: bool
    contains_ip: bool
    contains_email: bool
    contains_file_path: bool
    contains_db_conn: bool
    is_high_entropy: bool
    looks_like_api_key: bool
    confidence: float  # Confidence score 0.0-1.0
    entropy: Optional[float] = None
    pattern_matched: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "dex_file": self.dex_file,
            "length": self.length,
            "contains_url": self.contains_url,
            "contains_ip": self.contains_ip,
            "contains_email": self.contains_email,
            "contains_file_path": self.contains_file_path,
            "contains_db_conn": self.contains_db_conn,
            "is_high_entropy": self.is_high_entropy,
            "looks_like_api_key": self.looks_like_api_key,
            "confidence": self.confidence,
            "entropy": self.entropy,
            "pattern_matched": self.pattern_matched
        }


@dataclass
class APIAPI:
    """Generic API call information."""
    method_signature: str
    api_called: str
    category: str  # crypto, network, storage, etc.
    dex_file: str
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "method_signature": self.method_signature,
            "api_called": self.api_called,
            "category": self.category,
            "dex_file": self.dex_file
        }


@dataclass
class CryptoAPI:
    """Cryptography API call with extracted parameters."""
    method_signature: str
    api_called: str
    parameters: List[str]  # e.g., ["AES/CBC/PKCS5Padding"]
    dex_file: str
    category: str = "crypto"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "method_signature": self.method_signature,
            "api_called": self.api_called,
            "parameters": self.parameters,
            "dex_file": self.dex_file,
            "category": self.category
        }


@dataclass
class FilteredComponent:
    """Filtered component information."""
    type: str
    name: str
    exported: bool
    permission: Optional[str]
    enabled: bool
    intent_filter_count: int
    has_intent_filters: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "name": self.name,
            "exported": self.exported,
            "permission": self.permission,
            "enabled": self.enabled,
            "intent_filter_count": self.intent_filter_count,
            "has_intent_filters": self.has_intent_filters
        }


@dataclass
class AnalysisReadyAPK:
    """Container for all filtered, analysis-ready data."""
    # Metadata
    package_name: str
    version_name: str
    version_code: str
    min_sdk_version: Optional[str]
    target_sdk_version: Optional[str]
    
    # Statistics
    total_classes: int
    app_classes_count: int
    total_methods: int
    app_methods_count: int
    total_strings: int
    
    # App code (filtered)
    classes: List[FilteredClass]
    
    # API usage (categorized)
    crypto_apis: List[CryptoAPI]
    network_apis: List[APIAPI]
    storage_apis: List[APIAPI]
    reflection_apis: List[APIAPI]
    webview_apis: List[APIAPI]
    dynamic_code_apis: List[APIAPI]
    
    # Source APIs (untrusted input detection)
    intent_apis: List[APIAPI]
    user_input_apis: List[APIAPI]
    web_input_apis: List[APIAPI]
    
    # Sink APIs (dangerous operations)
    sql_apis: List[APIAPI]
    command_exec_apis: List[APIAPI]
    file_write_apis: List[APIAPI]
    crypto_weak_apis: List[CryptoAPI]
    webview_sink_apis: List[APIAPI]
    
    # Security-relevant strings
    strings: List[SecurityString]
    
    # Manifest data (filtered)
    exported_components: List[FilteredComponent]
    dangerous_permissions: List[str]
    
    # App attributes
    allow_backup: Optional[bool]
    debuggable: Optional[bool]
    uses_cleartext_traffic: Optional[bool]
    network_security_config: Optional[str]
    
    # Risk flags (computed from manifest)
    cleartext_traffic_allowed: bool
    backup_enabled: bool
    uses_test_keys: bool
    exported_without_permission: bool
    dangerous_permissions_used: bool
    
    # Third-party libraries
    third_party_libraries: List[Dict[str, str]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "metadata": {
                "package_name": self.package_name,
                "version_name": self.version_name,
                "version_code": self.version_code,
                "min_sdk_version": self.min_sdk_version,
                "target_sdk_version": self.target_sdk_version
            },
            "statistics": {
                "total_classes": self.total_classes,
                "app_classes_count": self.app_classes_count,
                "total_methods": self.total_methods,
                "app_methods_count": self.app_methods_count,
                "total_strings": self.total_strings,
                "crypto_apis_count": len(self.crypto_apis),
                "network_apis_count": len(self.network_apis),
                "storage_apis_count": len(self.storage_apis),
                "reflection_apis_count": len(self.reflection_apis),
                "webview_apis_count": len(self.webview_apis),
                "dynamic_code_apis_count": len(self.dynamic_code_apis),
                "intent_apis_count": len(self.intent_apis),
                "user_input_apis_count": len(self.user_input_apis),
                "web_input_apis_count": len(self.web_input_apis),
                "sql_apis_count": len(self.sql_apis),
                "command_exec_apis_count": len(self.command_exec_apis),
                "file_write_apis_count": len(self.file_write_apis),
                "crypto_weak_apis_count": len(self.crypto_weak_apis),
                "webview_sink_apis_count": len(self.webview_sink_apis),
                "suspicious_strings_count": len(self.strings),
                "exported_components_count": len(self.exported_components),
                "dangerous_permissions_count": len(self.dangerous_permissions)
            },
            "app_classes": [c.to_dict() for c in self.classes],
            "api_usage": {
                "crypto": [api.to_dict() for api in self.crypto_apis],
                "network": [api.to_dict() for api in self.network_apis],
                "storage": [api.to_dict() for api in self.storage_apis],
                "reflection": [api.to_dict() for api in self.reflection_apis],
                "webview": [api.to_dict() for api in self.webview_apis],
                "dynamic_code": [api.to_dict() for api in self.dynamic_code_apis],
                "intent": [api.to_dict() for api in self.intent_apis],
                "user_input": [api.to_dict() for api in self.user_input_apis],
                "web_input": [api.to_dict() for api in self.web_input_apis],
                "sql": [api.to_dict() for api in self.sql_apis],
                "command_exec": [api.to_dict() for api in self.command_exec_apis],
                "file_write": [api.to_dict() for api in self.file_write_apis],
                "crypto_weak": [api.to_dict() for api in self.crypto_weak_apis],
                "webview_sink": [api.to_dict() for api in self.webview_sink_apis],
            },
            "security_strings": [s.to_dict() for s in self.strings],
            "manifest_analysis": {
                "exported_components": [c.to_dict() for c in self.exported_components],
                "dangerous_permissions": self.dangerous_permissions,
                "allow_backup": self.allow_backup,
                "debuggable": self.debuggable,
                "uses_cleartext_traffic": self.uses_cleartext_traffic,
                "network_security_config": self.network_security_config,
                "risk_flags": {
                    "cleartext_traffic_allowed": self.cleartext_traffic_allowed,
                    "backup_enabled": self.backup_enabled,
                    "uses_test_keys": self.uses_test_keys,
                    "exported_without_permission": self.exported_without_permission,
                    "dangerous_permissions_used": self.dangerous_permissions_used,
                }
            },
            "third_party_libraries": self.third_party_libraries
        }
    
    def save_json(self, filepath: str, pretty: bool = True) -> None:
        """
        Save the analysis-ready data to a JSON file.
        
        Args:
            filepath: Path where JSON will be saved
            pretty: If True, format with indentation (default: True)
        """
        import json
        indent = 2 if pretty else None
        
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=indent)
        
        logger.info(f"Analysis data saved to {filepath}")


class ScopeFilter:
    """
    Post-processor for APKModel that filters and categorizes security-relevant data.
    
    Version 2.3 - False Positive Reduction:
    - All v2.2 features preserved
    - Expanded blocklist: class descriptors, method descriptors, array descriptors
    - Code-artifact detection in entropy analysis
    - Confidence penalty for code-like strings
    - Stronger API key evidence requirements
    """
    
    # Configuration constants
    APP_PACKAGE_FILTER = True
    
    # Framework and library packages to filter out
    FRAMEWORK_PACKAGES = {
        'android', 'androidx', 'dalvik', 'java', 'javax', 'kotlin', 'kotlinx',
        'org.w3c', 'org.xml', 'org.json',
    }
    
    # Common third-party library prefixes
    LIBRARY_PACKAGES = {
        'com.google.android.gms', 'com.google.android.material', 'com.google.firebase',
        'com.google.gson', 'com.google.dagger', 'com.google.common',
        'com.squareup.okhttp', 'com.squareup.okhttp3', 'com.squareup.retrofit',
        'com.squareup.retrofit2', 'com.squareup.picasso', 'com.squareup.okio',
        'com.squareup.moshi', 'com.squareup.leakcanary', 'io.reactivex', 'io.realm',
        'org.apache.commons', 'org.apache.http', 'com.facebook', 'com.android.volley',
        'com.github.bumptech.glide', 'org.greenrobot', 'com.jakewharton',
        'butterknife', 'timber.log',
    }
    
    # User-configurable package lists
    ALLOWED_PACKAGES: List[str] = []
    BLOCKED_PACKAGES: List[str] = []
    
    # Whitelist of known safe patterns to reduce false positives
    SAFE_PATTERNS = {
        'url': [
            r'schemas?\.android\.com',
            r'www\.w3\.org',
            r'example\.com',
            r'developer\.android\.com',
            r'apache\.org',
            r'xmlpull\.org',
            r'eclipse\.org',
            r'opensource\.org',
            r'localhost',
            r'127\.0\.0\.1',
            r'schemas\.openxmlformats\.org',
            r'github\.com',
            r'githubusercontent\.com',
            r'googleapis\.com',
            r'gstatic\.com',
            r'firebase\.google\.com',
            r'stackoverflow\.com',
            r'maven\.org',
            r'gradle\.org',
            r'jetbrains\.com',
        ],
        'ip': [
            r'\b127\.0\.0\.1\b',
            r'\b10\.0\.2\.2\b',
            r'\b10\.0\.2\.15\b',
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b',
            r'\b0\.0\.0\.0\b',
            r'\blocalhost\b',
        ],
        'email': [
            r'noreply@',
            r'support@',
            r'info@',
            r'admin@',
            r'.*@example\.com',
            r'.*@test\.com',
            r'.*@localhost',
            r'.*@domain\.com',
            r'user@',
        ],
        'api_key': [
            r'AKIAIOSFODNN7EXAMPLE',
            r'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            r'AIzaSyA.*example',
            r'YOUR_API_KEY',
            r'your-api-key',
            r'API_KEY_HERE',
            r'INSERT_API_KEY',
            r'<api.key>',
            r'\$\{.*\}',
            r'xoxb-.*-example',
            r'sk_test_',
            r'pk_test_',
            # UUIDs (standard format: 8-4-4-4-12)
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            # UUIDs without hyphens
            r'[0-9a-fA-F]{32}',
        ],
        'file_path': [
            r'/system/',
            r'/proc/',
            r'/dev/',
        ]
    }
    
    # Official Android dangerous permissions
    OFFICIAL_DANGEROUS_PERMISSIONS = {
        'android.permission.READ_CALENDAR',
        'android.permission.WRITE_CALENDAR',
        'android.permission.CAMERA',
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.GET_ACCOUNTS',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.ACCESS_BACKGROUND_LOCATION',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_PHONE_STATE',
        'android.permission.READ_PHONE_NUMBERS',
        'android.permission.CALL_PHONE',
        'android.permission.ANSWER_PHONE_CALLS',
        'android.permission.READ_CALL_LOG',
        'android.permission.WRITE_CALL_LOG',
        'android.permission.ADD_VOICEMAIL',
        'android.permission.USE_SIP',
        'android.permission.PROCESS_OUTGOING_CALLS',
        'android.permission.BODY_SENSORS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_SMS',
        'android.permission.RECEIVE_WAP_PUSH',
        'android.permission.RECEIVE_MMS',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.ACCESS_MEDIA_LOCATION',
        'android.permission.BLUETOOTH_SCAN',
        'android.permission.BLUETOOTH_CONNECT',
        'android.permission.BLUETOOTH_ADVERTISE',
        'android.permission.POST_NOTIFICATIONS',
        'android.permission.NEARBY_WIFI_DEVICES',
        'android.permission.READ_MEDIA_IMAGES',
        'android.permission.READ_MEDIA_VIDEO',
        'android.permission.READ_MEDIA_AUDIO',
        'android.permission.BODY_SENSORS_BACKGROUND',
    }
    
    # Fallback keywords for custom permissions
    DANGEROUS_PERMISSION_KEYWORDS = [
        'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
        'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'READ_PHONE_STATE',
        'CALL_PHONE', 'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'ACCESS_FINE_LOCATION',
        'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_EXTERNAL_STORAGE',
        'WRITE_EXTERNAL_STORAGE', 'BODY_SENSORS', 'READ_CALENDAR', 'WRITE_CALENDAR',
        'BLUETOOTH_CONNECT', 'BLUETOOTH_SCAN', 'BLUETOOTH_ADVERTISE', 'NEARBY_WIFI_DEVICES',
        'POST_NOTIFICATIONS',
    ]
    
    MIN_STRING_ENTROPY = 4.2
    MIN_HIGH_ENTROPY_LENGTH = 12
    
    # ─── CHANGED (v2.3): Expanded blocklist patterns ─────────────────────
    # These patterns identify strings that are code artifacts (class descriptors,
    # method descriptors, array descriptors) and should never be treated as secrets.
    CODE_ARTIFACT_BLOCKLIST = [
        re.compile(r'^L[^;]+;$'),           # Class descriptor: Lcom/example/Foo;
        re.compile(r'^\([^)]*\)[^;]*;$'),   # Method descriptor: ()Ljava/lang/String;
        re.compile(r'^\[L[^;]+;$'),         # Array descriptor: [Lcom/example/Foo;
        re.compile(r'^L[^;]+;->[^(]+\('),   # Full method signature: Lcom/example/Foo;->bar(
        re.compile(r'^\[+[ZBCSIJFDV]$'),    # Primitive array descriptors: [I, [[B, etc.
    ]
    
    # Characters that strongly indicate a string is a code artifact
    CODE_ARTIFACT_CHARS = set('();/')
    # ─── END CHANGED ─────────────────────────────────────────────────────
    
    # Security-related keywords used for contextual evidence in secret detection
    # ─── CHANGED (v2.3): Extracted as class constant for reuse ───────────
    SECRET_CONTEXT_KEYWORDS = [
        'key', 'secret', 'token', 'auth', 'password', 'pass',
        'credential', 'api', 'apikey', 'api_key', 'access',
        'private', 'encrypt', 'signing',
    ]
    # ─── END CHANGED ─────────────────────────────────────────────────────
    
    # API patterns (unchanged)
    CRYPTO_PATTERNS = {
        r'Cipher;->getInstance': 'Cipher.getInstance',
        r'MessageDigest;->getInstance': 'MessageDigest.getInstance',
        r'Mac;->getInstance': 'Mac.getInstance',
        r'Signature;->getInstance': 'Signature.getInstance',
        r'KeyGenerator;->getInstance': 'KeyGenerator.getInstance',
        r'SecretKeySpec;-><init>': 'SecretKeySpec.<init>',
        r'IvParameterSpec;-><init>': 'IvParameterSpec.<init>',
    }
    
    NETWORK_PATTERNS = {
        r'HttpURLConnection;->': 'HttpURLConnection',
        r'HttpsURLConnection;->': 'HttpsURLConnection',
        r'URL;->openConnection': 'URL.openConnection',
        r'Socket;->': 'Socket',
        r'SSLSocket;->': 'SSLSocket',
        r'SSLContext;->': 'SSLContext',
        r'TrustManager;->': 'TrustManager',
        r'HostnameVerifier;->': 'HostnameVerifier',
        r'WebView;->loadUrl': 'WebView.loadUrl',
        r'WebView;->loadData': 'WebView.loadData',
    }
    
    STORAGE_PATTERNS = {
        r'FileOutputStream;->': 'FileOutputStream',
        r'FileInputStream;->': 'FileInputStream',
        r'SharedPreferences;->': 'SharedPreferences',
        r'SQLiteDatabase;->': 'SQLiteDatabase',
        r'openFileOutput': 'openFileOutput',
        r'openFileInput': 'openFileInput',
        r'getExternalStorageDirectory': 'getExternalStorageDirectory',
        r'ContentResolver;->': 'ContentResolver',
    }
    
    REFLECTION_PATTERNS = {
        r'Class;->forName': 'Class.forName',
        r'Method;->invoke': 'Method.invoke',
        r'Field;->get': 'Field.get',
        r'Field;->set': 'Field.set',
        r'Constructor;->newInstance': 'Constructor.newInstance',
    }
    
    WEBVIEW_PATTERNS = {
        r'WebView;->addJavascriptInterface': 'addJavascriptInterface',
        r'WebView;->setJavaScriptEnabled': 'setJavaScriptEnabled',
        r'WebSettings;->setJavaScriptEnabled': 'WebSettings.setJavaScriptEnabled',
    }
    
    DYNAMIC_CODE_PATTERNS = {
        r'DexClassLoader;->': 'DexClassLoader',
        r'PathClassLoader;->': 'PathClassLoader',
        r'loadDex': 'loadDex',
        r'DexFile;->': 'DexFile',
    }
    
    SOURCE_INTENT_PATTERNS = {
        r'Activity;->getIntent': 'Activity.getIntent',
        r'Intent;->getStringExtra': 'Intent.getStringExtra',
        r'Intent;->getIntExtra': 'Intent.getIntExtra',
        r'Intent;->getBooleanExtra': 'Intent.getBooleanExtra',
        r'Intent;->getExtras': 'Intent.getExtras',
        r'Intent;->getData': 'Intent.getData',
        r'Intent;->getDataString': 'Intent.getDataString',
        r'Intent;->getAction': 'Intent.getAction',
        r'Intent;->getParcelableExtra': 'Intent.getParcelableExtra',
        r'Intent;->getSerializableExtra': 'Intent.getSerializableExtra',
    }
    
    SOURCE_USER_INPUT_PATTERNS = {
        r'EditText;->getText': 'EditText.getText',
        r'TextView;->getText': 'TextView.getText',
        r'EditText;->getEditableText': 'EditText.getEditableText',
        r'SearchView;->getQuery': 'SearchView.getQuery',
        r'AutoCompleteTextView;->getText': 'AutoCompleteTextView.getText',
    }
    
    SOURCE_WEB_INPUT_PATTERNS = {
        r'WebView;->loadUrl': 'WebView.loadUrl',
        r'WebView;->loadData': 'WebView.loadData',
        r'WebView;->loadDataWithBaseURL': 'WebView.loadDataWithBaseURL',
        r'WebView;->evaluateJavascript': 'WebView.evaluateJavascript',
        r'WebView;->addJavascriptInterface': 'WebView.addJavascriptInterface',
    }
    
    SINK_SQL_PATTERNS = {
        r'SQLiteDatabase;->execSQL': 'SQLiteDatabase.execSQL',
        r'SQLiteDatabase;->rawQuery': 'SQLiteDatabase.rawQuery',
        r'SQLiteDatabase;->query': 'SQLiteDatabase.query',
        r'SQLiteDatabase;->delete': 'SQLiteDatabase.delete',
        r'SQLiteDatabase;->update': 'SQLiteDatabase.update',
        r'SQLiteDatabase;->insert': 'SQLiteDatabase.insert',
    }
    
    SINK_COMMAND_EXEC_PATTERNS = {
        r'Runtime;->exec': 'Runtime.exec',
        r'ProcessBuilder;->start': 'ProcessBuilder.start',
        r'ProcessBuilder;->command': 'ProcessBuilder.command',
    }
    
    SINK_FILE_WRITE_PATTERNS = {
        r'FileOutputStream;-><init>': 'FileOutputStream.<init>',
        r'FileOutputStream;->write': 'FileOutputStream.write',
        r'openFileOutput': 'Context.openFileOutput',
        r'FileWriter;-><init>': 'FileWriter.<init>',
        r'FileWriter;->write': 'FileWriter.write',
        r'RandomAccessFile;->write': 'RandomAccessFile.write',
    }
    
    SINK_CRYPTO_WEAK_PATTERNS = {
        r'Cipher;->getInstance': 'Cipher.getInstance',
        r'SecretKeySpec;-><init>': 'SecretKeySpec.<init>',
        r'IvParameterSpec;-><init>': 'IvParameterSpec.<init>',
        r'KeyGenerator;->getInstance': 'KeyGenerator.getInstance',
    }
    
    SINK_WEBVIEW_PATTERNS = {
        r'WebSettings;->setJavaScriptEnabled': 'WebSettings.setJavaScriptEnabled',
        r'WebView;->setJavaScriptEnabled': 'WebView.setJavaScriptEnabled',
        r'WebView;->addJavascriptInterface': 'WebView.addJavascriptInterface',
        r'WebView;->setAllowFileAccess': 'WebView.setAllowFileAccess',
        r'WebView;->setAllowContentAccess': 'WebView.setAllowContentAccess',
    }

    def __init__(self, model: APKModel):
        """
        Initialize the scope filter with an APK model.
        
        Args:
            model: APKModel instance from apk_loader
        """
        self.model = model
        self.app_package = model.manifest.package_name
        self.logger = logger
        
        # Multi-package support
        self.app_packages: List[str] = []
        
        # Lazy-loaded caches
        self._app_classes: Optional[List[FilteredClass]] = None
        self._app_methods: Optional[List[str]] = None
        self._app_strings: Optional[List[str]] = None
        self._dex_map: Optional[Dict[str, str]] = None
        
        # Lazy-loaded API buckets
        self._crypto_apis: Optional[List[APIAPI]] = None
        self._network_apis: Optional[List[APIAPI]] = None
        self._storage_apis: Optional[List[APIAPI]] = None
        self._reflection_apis: Optional[List[APIAPI]] = None
        self._webview_apis: Optional[List[APIAPI]] = None
        self._dynamic_code_apis: Optional[List[APIAPI]] = None
        
        # Source API caches
        self._intent_apis: Optional[List[APIAPI]] = None
        self._user_input_apis: Optional[List[APIAPI]] = None
        self._web_input_apis: Optional[List[APIAPI]] = None
        
        # Sink API caches
        self._sql_apis: Optional[List[APIAPI]] = None
        self._command_exec_apis: Optional[List[APIAPI]] = None
        self._file_write_apis: Optional[List[APIAPI]] = None
        self._crypto_weak_apis: Optional[List[CryptoAPI]] = None
        self._webview_sink_apis: Optional[List[APIAPI]] = None
        
        # Lazy-loaded analysis data
        self._security_strings: Optional[List[SecurityString]] = None
        self._analysis_ready: Optional[AnalysisReadyAPK] = None
        
        # Compile patterns once
        self._compile_patterns()
        
        # Auto-detect application packages
        self._initialize_app_packages()
        
        self.logger.info(f"Initialized ScopeFilter for package: {self.app_package}")
        self.logger.info(f"Detected app packages: {self.app_packages}")
    
    def _initialize_app_packages(self) -> None:
        """Initialize the list of application packages (auto-detect + manual overrides)."""
        detected = [self.app_package]
        
        if self.APP_PACKAGE_FILTER:
            all_classes = []
            for dex in self.model.dex_files:
                all_classes.extend(dex.classes)
            
            additional = self.auto_detect_packages(self.app_package, all_classes)
            detected.extend([p for p in additional if p not in detected])
        
        for allowed in self.ALLOWED_PACKAGES:
            if allowed not in detected:
                detected.append(allowed)
        
        self.app_packages = detected
    
    @classmethod
    def auto_detect_packages(cls, main_package: str, all_classes: List[str]) -> List[str]:
        """
        Auto-detect packages that likely belong to the application.
        
        Args:
            main_package: The main application package (e.g., "com.example.app")
            all_classes: List of all class names from DEX files
            
        Returns:
            List of detected application packages
        """
        root_segments = main_package.split('.')[:2]
        root = '.'.join(root_segments)
        
        package_counts: Dict[str, int] = {}
        
        for class_name in all_classes:
            if not class_name.startswith('L'):
                continue
            
            pkg = class_name[1:].rstrip(';').replace('/', '.')
            
            if '.' in pkg:
                pkg_parts = pkg.split('.')
                for depth in range(2, len(pkg_parts)):
                    pkg_prefix = '.'.join(pkg_parts[:depth])
                    package_counts[pkg_prefix] = package_counts.get(pkg_prefix, 0) + 1
        
        detected = []
        for pkg, count in package_counts.items():
            if count < 10:
                continue
            if not pkg.startswith(root):
                continue
            is_framework = any(pkg.startswith(fw) for fw in cls.FRAMEWORK_PACKAGES)
            if is_framework:
                continue
            is_library = any(pkg.startswith(lib) for lib in cls.LIBRARY_PACKAGES)
            if is_library:
                continue
            detected.append(pkg)
        
        return detected
    
    def _compile_patterns(self):
        """Precompile regex patterns for efficiency."""
        self._crypto_regex = {re.compile(p): name for p, name in self.CRYPTO_PATTERNS.items()}
        self._network_regex = {re.compile(p): name for p, name in self.NETWORK_PATTERNS.items()}
        self._storage_regex = {re.compile(p): name for p, name in self.STORAGE_PATTERNS.items()}
        self._reflection_regex = {re.compile(p): name for p, name in self.REFLECTION_PATTERNS.items()}
        self._webview_regex = {re.compile(p): name for p, name in self.WEBVIEW_PATTERNS.items()}
        self._dynamic_code_regex = {re.compile(p): name for p, name in self.DYNAMIC_CODE_PATTERNS.items()}
        
        self._intent_regex = {re.compile(p): name for p, name in self.SOURCE_INTENT_PATTERNS.items()}
        self._user_input_regex = {re.compile(p): name for p, name in self.SOURCE_USER_INPUT_PATTERNS.items()}
        self._web_input_regex = {re.compile(p): name for p, name in self.SOURCE_WEB_INPUT_PATTERNS.items()}
        
        self._sql_regex = {re.compile(p): name for p, name in self.SINK_SQL_PATTERNS.items()}
        self._command_exec_regex = {re.compile(p): name for p, name in self.SINK_COMMAND_EXEC_PATTERNS.items()}
        self._file_write_regex = {re.compile(p): name for p, name in self.SINK_FILE_WRITE_PATTERNS.items()}
        self._crypto_weak_regex = {re.compile(p): name for p, name in self.SINK_CRYPTO_WEAK_PATTERNS.items()}
        self._webview_sink_regex = {re.compile(p): name for p, name in self.SINK_WEBVIEW_PATTERNS.items()}
        
        self._url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+|content://[^\s<>"{}|\\^`\[\]]+')
        
        # Provider-specific API key patterns
        self._specific_api_patterns = {
            'google_api': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            'aws_access': re.compile(r'AKIA[0-9A-Z]{16}'),
            'aws_secret': re.compile(r'[0-9a-zA-Z/+]{40}'),
            'stripe_live': re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
            'stripe_test': re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
            'github_token': re.compile(r'ghp_[0-9a-zA-Z]{36}'),
            'slack_token': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}'),
            'firebase_key': re.compile(r'[0-9a-zA-Z_-]{40,}'),
        }
        
        self._generic_api_pattern = re.compile(r'[a-zA-Z0-9_\-]{32,}')
        
        self._ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self._email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self._file_path_pattern = re.compile(r'(?:/data/data/|/sdcard/|/storage/|/mnt/)[^\s<>"{}|\\^`\[\]]*')
        self._db_conn_pattern = re.compile(r'jdbc:|mongodb:|postgres:|mysql:', re.IGNORECASE)
        
        # Compile whitelist patterns
        self._whitelist_patterns = {}
        for pattern_type, patterns in self.SAFE_PATTERNS.items():
            self._whitelist_patterns[pattern_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def _build_dex_map(self) -> Dict[str, str]:
        """Build a map of class/method/string to DEX file."""
        if self._dex_map is None:
            self._dex_map = {}
            for dex in self.model.dex_files:
                for cls in dex.classes:
                    self._dex_map[cls] = dex.file_name
                for method in dex.methods:
                    self._dex_map[method] = dex.file_name
                for string in dex.strings:
                    if string not in self._dex_map:
                        self._dex_map[string] = dex.file_name
        return self._dex_map
    
    def is_app_class(self, class_name: str) -> bool:
        """
        Determine if a class belongs to the application's own code.
        
        Args:
            class_name: Class name in internal format (e.g., "Lcom/example/MyClass;")
            
        Returns:
            True if the class is application code, False if framework/library
        """
        if not class_name.startswith('L'):
            return False
        
        pkg = class_name[1:].rstrip(';').replace('/', '.')
        
        for allowed in self.ALLOWED_PACKAGES:
            if pkg.startswith(allowed):
                return True
        
        for blocked in self.BLOCKED_PACKAGES:
            if pkg.startswith(blocked):
                return False
        
        for framework in self.FRAMEWORK_PACKAGES:
            if pkg.startswith(framework):
                return False
        
        for library in self.LIBRARY_PACKAGES:
            if pkg.startswith(library):
                return False
        
        if self.APP_PACKAGE_FILTER:
            return any(pkg.startswith(app_pkg) for app_pkg in self.app_packages)
        
        return True
    
    def _is_whitelisted(self, s: str, pattern_type: str) -> bool:
        """
        Check if a string matches any whitelist pattern for the given type.
        
        Args:
            s: The string to check
            pattern_type: Type of pattern ('url', 'ip', 'email', 'api_key', 'file_path')
            
        Returns:
            True if the string is whitelisted (safe), False otherwise
        """
        patterns = self._whitelist_patterns.get(pattern_type, [])
        return any(pattern.search(s) for pattern in patterns)
    
    def _has_mixed_chars(self, s: str) -> bool:
        """
        Check if a string contains a mix of character classes.
        
        Args:
            s: The string to check
            
        Returns:
            True if the string has mixed character classes
        """
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        has_special = any(not c.isalnum() for c in s)
        
        char_class_count = sum([has_upper, has_lower, has_digit, has_special])
        return char_class_count >= 2
    
    # ─── CHANGED (v2.3): New helper to detect code artifacts ─────────────
    def _is_code_artifact(self, s: str) -> bool:
        """
        Check if a string is a code artifact (class descriptor, method descriptor,
        array descriptor, or method signature) that should not be treated as a secret.
        
        Args:
            s: The string to check
            
        Returns:
            True if the string looks like a code artifact
        """
        # Check against compiled blocklist patterns
        for pattern in self.CODE_ARTIFACT_BLOCKLIST:
            if pattern.match(s):
                return True
        
        # Additional heuristic: strings containing '->' are method references
        if '->' in s and ';' in s:
            return True
        
        return False
    
    def _has_code_artifact_chars(self, s: str) -> bool:
        """
        Check if a string contains characters typical of code artifacts.
        
        This is a softer check than _is_code_artifact — used for confidence
        penalties rather than outright exclusion.
        
        Args:
            s: The string to check
            
        Returns:
            True if the string contains code-like punctuation
        """
        return bool(self.CODE_ARTIFACT_CHARS.intersection(s))
    # ─── END CHANGED ─────────────────────────────────────────────────────
    
    def _is_base64_resource(self, s: str) -> bool:
        """
        Check if a string looks like a Base64-encoded resource.
        
        Args:
            s: The string to check
            
        Returns:
            True if the string looks like a Base64 resource
        """
        if len(s) < 100:
            return False
        
        if not ('+' in s or '/' in s):
            return False
        
        base64_prefixes = [
            'iVBORw0KGgo',  # PNG
            'R0lGOD',       # GIF
            '/9j/',         # JPEG
            'PD94bWwg',     # XML
            'AAAA',         # Common padding
        ]
        
        return any(s.startswith(prefix) for prefix in base64_prefixes)
    
    @functools.lru_cache(maxsize=1024)
    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Args:
            s: The string to analyze
            
        Returns:
            Entropy value (0.0 to ~8.0 for typical strings)
        """
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
    
    # ─── CHANGED (v2.3): Confidence penalty for code artifacts ───────────
    def _calculate_confidence(self, sec_string: SecurityString) -> float:
        """
        Calculate confidence score for a security string finding.
        
        Confidence is based on multiple factors:
        - Base confidence: 0.3
        - Provider-specific API key: +0.3 (higher than generic)
        - API key pattern: +0.2
        - High entropy: +0.1
        - Additional patterns: +0.1 each
        - Short length penalty: -0.1 if < 10 chars
        - Mixed characters bonus: +0.05
        - Test/example key penalty: -0.3
        - Code artifact penalty: -0.2 (NEW in v2.3)
        
        Args:
            sec_string: SecurityString object (partially constructed)
            
        Returns:
            Confidence score between 0.0 and 0.95
        """
        confidence = 0.3
        
        # Check if it's a test/example key
        is_test_key = any(
            indicator in sec_string.value.lower()
            for indicator in ['test', 'example', 'demo', 'sample', 'placeholder', 'dummy']
        )
        
        # Provider-specific API keys get highest boost (unless test keys)
        if sec_string.pattern_matched and 'API Key (' in sec_string.pattern_matched:
            if is_test_key:
                confidence += 0.1
            else:
                confidence += 0.3
        elif sec_string.looks_like_api_key:
            if is_test_key:
                confidence += 0.05
            else:
                confidence += 0.2
        
        if sec_string.is_high_entropy:
            confidence += 0.1
        
        pattern_count = sum([
            sec_string.contains_url,
            sec_string.contains_ip,
            sec_string.contains_email,
            sec_string.contains_file_path,
            sec_string.contains_db_conn
        ])
        confidence += pattern_count * 0.1
        
        if sec_string.length < 10:
            confidence -= 0.1
        
        if sec_string.looks_like_api_key and self._has_mixed_chars(sec_string.value):
            confidence += 0.05
        
        # Test key penalty
        if is_test_key:
            confidence -= 0.3
        
        # ── NEW (v2.3): Penalise strings with code-artifact characters ──
        if self._has_code_artifact_chars(sec_string.value):
            confidence -= 0.2
        # ── END NEW ─────────────────────────────────────────────────────
        
        return max(0.0, min(0.95, confidence))
    # ─── END CHANGED ─────────────────────────────────────────────────────
    
    # ─── CHANGED (v2.3): Tightened secret detection ──────────────────────
    def _analyze_string(self, s: str, dex_file: str) -> Optional[SecurityString]:
        """
        Analyze a single string for security relevance.
        
        v2.3 changes:
        - Blocklist check: class/method/array descriptors are rejected early
        - High-entropy detection skips code artifacts
        - API key detection requires keyword evidence OR very high entropy (>5.0)
        - Strings with ; or / are not API keys unless they contain a keyword
        - Confidence scoring penalises code-artifact characters
        
        Args:
            s: The string to analyze
            dex_file: Source DEX file name
            
        Returns:
            SecurityString object if suspicious, None otherwise
        """
        # Basic filtering
        if len(s) < 4 or s in ['true', 'false', 'null', 'void', 'this']:
            return None
        
        # ── NEW (v2.3): Early rejection of code artifacts ────────────────
        if self._is_code_artifact(s):
            return None
        # ── END NEW ─────────────────────────────────────────────────────
        
        # Skip Base64-encoded resources
        if self._is_base64_resource(s):
            return None
        
        length = len(s)
        entropy = self._calculate_entropy(s)
        
        # Pattern detection
        contains_url = bool(self._url_pattern.search(s))
        contains_ip = bool(self._ip_pattern.search(s))
        contains_email = bool(self._email_pattern.search(s))
        contains_file_path = bool(self._file_path_pattern.search(s))
        contains_db_conn = bool(self._db_conn_pattern.search(s))
        
        # Whitelist checking
        if contains_url and self._is_whitelisted(s, 'url'):
            return None
        if contains_ip and self._is_whitelisted(s, 'ip'):
            return None
        if contains_email and self._is_whitelisted(s, 'email'):
            return None
        if contains_file_path and self._is_whitelisted(s, 'file_path'):
            return None
        
        # Provider-specific API key detection (HIGH ACCURACY)
        specific_api_match = None
        for provider, pattern in self._specific_api_patterns.items():
            if pattern.search(s):
                specific_api_match = provider
                break
        
        # Check if it's a whitelisted API key before flagging
        if specific_api_match and self._is_whitelisted(s, 'api_key'):
            return None
        
        # ── CHANGED (v2.3): Check security context using class constant ──
        has_security_context = any(
            keyword in s.lower()
            for keyword in self.SECRET_CONTEXT_KEYWORDS
        )
        # ── END CHANGED ──────────────────────────────────────────────────
        
        # ── CHANGED (v2.3): High-entropy detection excludes code artifacts ─
        # A string that contains code-artifact characters (parentheses,
        # semicolons, slashes) is almost certainly not a secret, even if it
        # happens to have high entropy and mixed characters.
        is_code_like = self._has_code_artifact_chars(s)
        
        is_high_entropy = (
            entropy > 4.5 and
            length >= 16 and
            self._has_mixed_chars(s) and
            has_security_context and
            not is_code_like  # NEW: exclude code artifacts
        )
        # ── END CHANGED ──────────────────────────────────────────────────
        
        # ── CHANGED (v2.3): Tightened generic API key detection ──────────
        # Generic API key detection now requires stronger evidence:
        #   1. Must be >= 32 chars and match the generic pattern
        #   2. Must have reasonable entropy (>4.0)
        #   3. Must NOT be whitelisted
        #   4. NEW: Must either contain a security keyword OR have very
        #      high entropy (>5.0)
        #   5. NEW: Strings with ; or / are excluded unless they contain
        #      a clear keyword
        looks_like_api_key = False
        
        if specific_api_match is not None:
            # Provider-specific match — always trust it (already whitelist-checked)
            looks_like_api_key = True
        elif (
            length >= 32
            and bool(self._generic_api_pattern.fullmatch(s))
            and entropy > 4.0
            and not self._is_whitelisted(s, 'api_key')
        ):
            # Generic match — require additional evidence
            has_code_punctuation = bool(set(';/()').intersection(s))
            
            if has_code_punctuation:
                # Only flag if it explicitly contains a security keyword
                looks_like_api_key = has_security_context
            else:
                # No code punctuation: accept with keyword OR very high entropy
                looks_like_api_key = has_security_context or entropy > 5.0
        # ── END CHANGED ──────────────────────────────────────────────────
        
        # Determine primary pattern
        pattern_matched = None
        if specific_api_match:
            pattern_matched = f"API Key ({specific_api_match})"
        elif contains_url:
            pattern_matched = "URL/URI"
        elif contains_ip:
            pattern_matched = "IP Address"
        elif contains_email:
            pattern_matched = "Email"
        elif contains_file_path:
            pattern_matched = "File Path"
        elif contains_db_conn:
            pattern_matched = "DB Connection"
        elif looks_like_api_key:
            pattern_matched = "Potential API Key"
        elif is_high_entropy:
            pattern_matched = "High Entropy (with context)"
        
        # Only return if something suspicious was found
        if pattern_matched:
            sec_string = SecurityString(
                value=s,
                dex_file=dex_file,
                length=length,
                contains_url=contains_url,
                contains_ip=contains_ip,
                contains_email=contains_email,
                contains_file_path=contains_file_path,
                contains_db_conn=contains_db_conn,
                is_high_entropy=is_high_entropy,
                looks_like_api_key=looks_like_api_key,
                confidence=0.0,
                entropy=entropy,
                pattern_matched=pattern_matched
            )
            
            # Calculate confidence score (includes code-artifact penalty)
            sec_string.confidence = self._calculate_confidence(sec_string)
            
            # ── NEW (v2.3): Final gate — reject if confidence is too low ─
            # Strings that only matched "Potential API Key" or
            # "High Entropy" but scored below 0.15 after penalties are
            # almost certainly false positives.
            if sec_string.confidence < 0.15 and pattern_matched in (
                "Potential API Key", "High Entropy (with context)"
            ):
                return None
            # ── END NEW ─────────────────────────────────────────────────
            
            return sec_string
        
        return None
    # ─── END CHANGED ─────────────────────────────────────────────────────
    
    def _get_filtered_classes(self) -> List[FilteredClass]:
        """Get list of application-owned classes with metadata."""
        if self._app_classes is None:
            self.logger.info("Filtering classes to application scope")
            dex_map = self._build_dex_map()
            filtered = []
            
            for dex in self.model.dex_files:
                for cls in dex.classes:
                    if self.is_app_class(cls):
                        pkg = cls[1:].rstrip(';').replace('/', '.')
                        simple_name = pkg.split('.')[-1]
                        package = '.'.join(pkg.split('.')[:-1])
                        
                        filtered.append(FilteredClass(
                            name=cls,
                            package=package,
                            simple_name=simple_name,
                            dex_file=dex.file_name
                        ))
            
            self._app_classes = filtered
            self.logger.info(f"Filtered to {len(filtered)} app classes")
        
        return self._app_classes
    
    def _get_filtered_methods(self) -> List[str]:
        """Get list of methods from application-owned classes."""
        if self._app_methods is None:
            self.logger.info("Filtering methods to application scope")
            app_classes_set = {cls.name for cls in self._get_filtered_classes()}
            filtered = []
            
            for dex in self.model.dex_files:
                for method in dex.methods:
                    if '->' in method:
                        class_name = method.split('->')[0]
                        if class_name in app_classes_set:
                            filtered.append(method)
            
            self._app_methods = filtered
            self.logger.info(f"Filtered to {len(filtered)} app methods")
        
        return self._app_methods
    
    def _extract_string_parameters(self, method_sig: str) -> List[str]:
        """
        Extract string literals from method signature.
        
        Args:
            method_sig: Full method signature
            
        Returns:
            List of extracted string parameters
        """
        parameters = []
        
        quoted = re.findall(r'"([^"]+)"', method_sig)
        parameters.extend(quoted)
        
        single_quoted = re.findall(r"'([^']+)'", method_sig)
        parameters.extend(single_quoted)
        
        const_string = re.findall(r'const-string.*?["\']([^"\']+)["\']', method_sig)
        parameters.extend(const_string)
        
        if re.search(r'\bgetInstance\b', method_sig):
            matches = re.finditer(r'getInstance\s*\(\s*["\']?([A-Za-z0-9/_]+)["\']?\s*[,)]', method_sig)
            for match in matches:
                param = match.group(1).strip()
                if param and param not in parameters and not param.startswith('v'):
                    parameters.append(param)
        
        transformation = re.findall(r'\b([A-Z0-9]{3,}(?:/[A-Z0-9]+){1,2})\b', method_sig)
        for trans in transformation:
            if trans not in parameters:
                parameters.append(trans)
        
        crypto_keywords = re.findall(
            r'\b(DES|3DES|AES|RSA|DSA|EC|MD5|SHA1?|SHA-?1|SHA-?256|SHA-?384|SHA-?512|'
            r'HMAC|PBKDF2|Blowfish|RC4|ChaCha20)\b',
            method_sig
        )
        for keyword in crypto_keywords:
            if keyword not in parameters:
                parameters.append(keyword)
        
        seen = set()
        unique_params = []
        for param in parameters:
            if param not in seen:
                seen.add(param)
                unique_params.append(param)
        
        return unique_params
    
    def _categorize_apis(self, methods: List[str], patterns: Dict, category: str) -> List[Any]:
        """
        Categorize methods by API patterns.
        
        Args:
            methods: List of method signatures
            patterns: Dict of regex patterns to API names
            category: Category name
            
        Returns:
            List of API objects (CryptoAPI for crypto, APIAPI for others)
        """
        dex_map = self._build_dex_map()
        apis = []
        
        for method in methods:
            for pattern, api_name in patterns.items():
                if pattern.search(method):
                    if category == "crypto":
                        params = self._extract_string_parameters(method)
                        apis.append(CryptoAPI(
                            method_signature=method,
                            api_called=api_name,
                            parameters=params,
                            dex_file=dex_map.get(method, "unknown"),
                            category=category
                        ))
                    else:
                        apis.append(APIAPI(
                            method_signature=method,
                            api_called=api_name,
                            category=category,
                            dex_file=dex_map.get(method, "unknown")
                        ))
                    break
        
        return apis
    
    def prepare(self) -> AnalysisReadyAPK:
        """
        Prepare analysis-ready data by filtering and categorizing.
        
        Returns:
            AnalysisReadyAPK object ready for rule engine consumption
        """
        if self._analysis_ready is not None:
            return self._analysis_ready
        
        self.logger.info("Preparing analysis-ready APK data")
        
        app_classes = self._get_filtered_classes()
        app_methods = self._get_filtered_methods()
        dex_map = self._build_dex_map()
        
        total_classes = sum(len(dex.classes) for dex in self.model.dex_files)
        total_methods = sum(len(dex.methods) for dex in self.model.dex_files)
        total_strings = sum(len(dex.strings) for dex in self.model.dex_files)
        
        self.logger.info("Categorizing API usage")
        crypto_apis = self._categorize_apis(app_methods, self._crypto_regex, "crypto")
        network_apis = self._categorize_apis(app_methods, self._network_regex, "network")
        storage_apis = self._categorize_apis(app_methods, self._storage_regex, "storage")
        reflection_apis = self._categorize_apis(app_methods, self._reflection_regex, "reflection")
        webview_apis = self._categorize_apis(app_methods, self._webview_regex, "webview")
        dynamic_code_apis = self._categorize_apis(app_methods, self._dynamic_code_regex, "dynamic_code")
        
        self.logger.info("Categorizing source APIs (untrusted input)")
        intent_apis = self._categorize_apis(app_methods, self._intent_regex, "intent_source")
        user_input_apis = self._categorize_apis(app_methods, self._user_input_regex, "user_input_source")
        web_input_apis = self._categorize_apis(app_methods, self._web_input_regex, "web_input_source")
        
        self.logger.info("Categorizing sink APIs (dangerous operations)")
        sql_apis = self._categorize_apis(app_methods, self._sql_regex, "sql_sink")
        command_exec_apis = self._categorize_apis(app_methods, self._command_exec_regex, "command_exec_sink")
        file_write_apis = self._categorize_apis(app_methods, self._file_write_regex, "file_write_sink")
        crypto_weak_apis = self._categorize_apis(app_methods, self._crypto_weak_regex, "crypto")
        webview_sink_apis = self._categorize_apis(app_methods, self._webview_sink_regex, "webview_sink")
        
        self.logger.info("Analyzing strings for security issues")
        security_strings = []
        for dex in self.model.dex_files:
            for s in dex.strings:
                result = self._analyze_string(s, dex.file_name)
                if result:
                    security_strings.append(result)
        
        self.logger.info(f"Found {len(security_strings)} suspicious strings (with confidence scores)")
        
        self.logger.info("Filtering exported components")
        exported_components = []
        for comp in self.model.manifest.components:
            if comp.exported:
                exported_components.append(FilteredComponent(
                    type=comp.type,
                    name=comp.name,
                    exported=comp.exported,
                    permission=comp.permission,
                    enabled=comp.enabled,
                    intent_filter_count=len(comp.intent_filters),
                    has_intent_filters=len(comp.intent_filters) > 0
                ))
        
        self.logger.info("Identifying dangerous permissions")
        dangerous_permissions = []
        for perm in self.model.manifest.permissions:
            if perm.name in self.OFFICIAL_DANGEROUS_PERMISSIONS:
                dangerous_permissions.append(perm.name)
            elif perm.name.startswith("android.permission."):
                for keyword in self.DANGEROUS_PERMISSION_KEYWORDS:
                    if keyword in perm.name.upper():
                        dangerous_permissions.append(perm.name)
                        break
        
        third_party = [
            {
                "name": lib.name,
                "package_prefix": lib.package_prefix,
                "confidence": lib.confidence
            }
            for lib in self.model.third_party_libraries
        ]
        
        self.logger.info("Computing manifest risk flags")
        cleartext_traffic_allowed = bool(self.model.manifest.application.uses_cleartext_traffic)
        backup_enabled = bool(self.model.manifest.application.allow_backup)
        
        uses_test_keys = False
        if self.model.apk.certificates:
            for cert in self.model.apk.certificates:
                debug_fingerprints = {
                    'C51CE410C124A10E0DB5E4B97FC2E81DDB8AD4',
                    '38918A453D07199354F8B19AF05EC6562CED5788',
                }
                sha1_clean = cert.fingerprint_sha1.replace(':', '').upper()
                if sha1_clean in debug_fingerprints or 'debug' in cert.subject.lower():
                    uses_test_keys = True
                    break
        
        exported_without_permission = any(
            comp.exported and not comp.permission
            for comp in exported_components
        )
        
        dangerous_permissions_used = len(dangerous_permissions) > 0
        
        self._analysis_ready = AnalysisReadyAPK(
            package_name=self.model.manifest.package_name,
            version_name=self.model.manifest.version_name,
            version_code=self.model.manifest.version_code,
            min_sdk_version=self.model.manifest.min_sdk_version,
            target_sdk_version=self.model.manifest.target_sdk_version,
            total_classes=total_classes,
            app_classes_count=len(app_classes),
            total_methods=total_methods,
            app_methods_count=len(app_methods),
            total_strings=total_strings,
            classes=app_classes,
            crypto_apis=crypto_apis,
            network_apis=network_apis,
            storage_apis=storage_apis,
            reflection_apis=reflection_apis,
            webview_apis=webview_apis,
            dynamic_code_apis=dynamic_code_apis,
            intent_apis=intent_apis,
            user_input_apis=user_input_apis,
            web_input_apis=web_input_apis,
            sql_apis=sql_apis,
            command_exec_apis=command_exec_apis,
            file_write_apis=file_write_apis,
            crypto_weak_apis=crypto_weak_apis,
            webview_sink_apis=webview_sink_apis,
            strings=security_strings,
            exported_components=exported_components,
            dangerous_permissions=dangerous_permissions,
            allow_backup=self.model.manifest.application.allow_backup,
            debuggable=self.model.manifest.application.debuggable,
            uses_cleartext_traffic=self.model.manifest.application.uses_cleartext_traffic,
            network_security_config=self.model.manifest.application.network_security_config,
            cleartext_traffic_allowed=cleartext_traffic_allowed,
            backup_enabled=backup_enabled,
            uses_test_keys=uses_test_keys,
            exported_without_permission=exported_without_permission,
            dangerous_permissions_used=dangerous_permissions_used,
            third_party_libraries=third_party
        )
        
        self.logger.info("Analysis-ready data prepared successfully")
        self.logger.info(f"Source API detection: {len(intent_apis)} intent, {len(user_input_apis)} user input, {len(web_input_apis)} web input")
        self.logger.info(f"Sink API detection: {len(sql_apis)} SQL, {len(command_exec_apis)} command exec, {len(file_write_apis)} file write")
        self.logger.info(f"Risk flags: cleartext={cleartext_traffic_allowed}, backup={backup_enabled}, test_keys={uses_test_keys}")
        self.logger.info(f"False positive reduction: provider-specific patterns, contextual detection")
        self.logger.info(f"v2.3: Code-artifact blocklist, confidence penalties, stronger API key evidence")
        
        return self._analysis_ready
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"ScopeFilter(package={self.app_package}, app_packages={len(self.app_packages)})"


def main():
    """Command-line interface for testing."""
    import sys
    import argparse
    from apk_loader import APKLoader
    
    parser = argparse.ArgumentParser(
        description='Scope Filter v2.3 - False-positive-reduced APK security analysis'
    )
    parser.add_argument('apk_path', help='Path to the APK file')
    parser.add_argument('-o', '--output', help='Save filtered data to JSON file (optional)')
    parser.add_argument('--compact', action='store_true', help='Save JSON in compact format')
    parser.add_argument('--summary', action='store_true', help='Print summary statistics')
    parser.add_argument('--show-confidence', action='store_true', help='Show confidence scores for strings')
    
    args = parser.parse_args()
    
    try:
        print(f"Loading APK: {args.apk_path}")
        loader = APKLoader()
        model = loader.load(args.apk_path)
        
        print("Applying scope filter v2.3 (false-positive reduction)...")
        scope = ScopeFilter(model)
        analysis_ready = scope.prepare()
        
        print(f"✓ Filtering complete: {analysis_ready.package_name}")
        
        if args.output:
            pretty = not args.compact
            analysis_ready.save_json(args.output, pretty=pretty)
            print(f"✓ Filtered data saved to {args.output}")
        
        if args.summary:
            print("\n" + "="*60)
            print("SCOPE FILTER v2.3 - FALSE POSITIVE REDUCTION")
            print("="*60)
            print(f"Package:          {analysis_ready.package_name}")
            print(f"Version:          {analysis_ready.version_name}")
            print(f"Detected packages: {len(scope.app_packages)}")
            for pkg in scope.app_packages:
                print(f"  - {pkg}")
            print(f"\nFiltering Results:")
            print(f"Total classes:    {analysis_ready.total_classes:,}")
            print(f"App classes:      {analysis_ready.app_classes_count:,}")
            print(f"Total methods:    {analysis_ready.total_methods:,}")
            print(f"App methods:      {analysis_ready.app_methods_count:,}")
            print(f"\nAPI Usage:")
            print(f"Crypto APIs:      {len(analysis_ready.crypto_apis)}")
            print(f"Network APIs:     {len(analysis_ready.network_apis)}")
            print(f"Storage APIs:     {len(analysis_ready.storage_apis)}")
            print(f"Reflection APIs:  {len(analysis_ready.reflection_apis)}")
            print(f"WebView APIs:     {len(analysis_ready.webview_apis)}")
            print(f"Dynamic Code:     {len(analysis_ready.dynamic_code_apis)}")
            print(f"\nSource APIs (Untrusted Input):")
            print(f"Intent APIs:      {len(analysis_ready.intent_apis)}")
            print(f"User Input APIs:  {len(analysis_ready.user_input_apis)}")
            print(f"Web Input APIs:   {len(analysis_ready.web_input_apis)}")
            print(f"\nSink APIs (Dangerous Operations):")
            print(f"SQL APIs:         {len(analysis_ready.sql_apis)}")
            print(f"Command Exec:     {len(analysis_ready.command_exec_apis)}")
            print(f"File Write:       {len(analysis_ready.file_write_apis)}")
            print(f"Crypto Weak:      {len(analysis_ready.crypto_weak_apis)}")
            print(f"WebView Sink:     {len(analysis_ready.webview_sink_apis)}")
            print(f"\nSecurity Issues:")
            print(f"Suspicious strings:     {len(analysis_ready.strings)}")
            print(f"Exported components:    {len(analysis_ready.exported_components)}")
            print(f"Dangerous permissions:  {len(analysis_ready.dangerous_permissions)}")
            print(f"\nApp Configuration:")
            print(f"Allow backup:          {analysis_ready.allow_backup}")
            print(f"Debuggable:            {analysis_ready.debuggable}")
            print(f"Cleartext traffic:     {analysis_ready.uses_cleartext_traffic}")
            print(f"\nRisk Flags:")
            print(f"Cleartext allowed:     {analysis_ready.cleartext_traffic_allowed}")
            print(f"Backup enabled:        {analysis_ready.backup_enabled}")
            print(f"Uses test keys:        {analysis_ready.uses_test_keys}")
            print(f"Exported w/o perm:     {analysis_ready.exported_without_permission}")
            print(f"Dangerous perms used:  {analysis_ready.dangerous_permissions_used}")
            print("="*60)
        
        if args.show_confidence and analysis_ready.strings:
            print("\n" + "="*60)
            print("STRING FINDINGS WITH CONFIDENCE SCORES")
            print("="*60)
            sorted_strings = sorted(analysis_ready.strings, key=lambda x: x.confidence, reverse=True)
            for i, s in enumerate(sorted_strings[:20], 1):
                print(f"\n{i}. [{s.pattern_matched}] Confidence: {s.confidence:.2f}")
                print(f"   Value: {s.value[:80]}{'...' if len(s.value) > 80 else ''}")
                print(f"   Entropy: {s.entropy:.2f}, Length: {s.length}")
            if len(sorted_strings) > 20:
                print(f"\n... and {len(sorted_strings) - 20} more findings")
            print("="*60)
        
        if not args.output and not args.summary:
            print("\n💡 Tip: Use --output to save JSON, --summary to view details, or --show-confidence to see string scores")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())