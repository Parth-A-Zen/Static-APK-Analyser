"""
Scope Filter Module

A post-processor for APKModel that filters out non-application data and organizes
remaining information into security-relevant buckets for OWASP Mobile Top 10 analysis.

This module removes Android framework and third-party library code, focusing analysis
on the application's own code and identifying potential security issues.

Author: Generated for APK Security Analysis
License: MIT
"""

import logging
import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

# Import from apk_loader
try:
    from Loader.apk_loader import APKModel, Component, Permission
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
    crypto_apis: List[CryptoAPI]  # Now uses CryptoAPI with parameters
    network_apis: List[APIAPI]
    storage_apis: List[APIAPI]
    reflection_apis: List[APIAPI]
    webview_apis: List[APIAPI]
    dynamic_code_apis: List[APIAPI]
    
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
                "dynamic_code": [api.to_dict() for api in self.dynamic_code_apis]
            },
            "security_strings": [s.to_dict() for s in self.strings],
            "manifest_analysis": {
                "exported_components": [c.to_dict() for c in self.exported_components],
                "dangerous_permissions": self.dangerous_permissions,
                "allow_backup": self.allow_backup,
                "debuggable": self.debuggable,
                "uses_cleartext_traffic": self.uses_cleartext_traffic,
                "network_security_config": self.network_security_config
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
    
    This class removes framework and library code, then organizes the remaining
    application-specific data into buckets for security analysis.
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
    
    ALLOWED_PACKAGES: List[str] = []
    BLOCKED_PACKAGES: List[str] = []
    
    # Dangerous permissions
    DANGEROUS_PERMISSIONS = [
        'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
        'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'READ_PHONE_STATE',
        'CALL_PHONE', 'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'ACCESS_FINE_LOCATION',
        'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_EXTERNAL_STORAGE',
        'WRITE_EXTERNAL_STORAGE', 'BODY_SENSORS', 'READ_CALENDAR', 'WRITE_CALENDAR',
        'BLUETOOTH_CONNECT', 'BLUETOOTH_SCAN', 'BLUETOOTH_ADVERTISE', 'NEARBY_WIFI_DEVICES',
        'POST_NOTIFICATIONS',
    ]
    
    MIN_STRING_ENTROPY = 4.5
    
    # API patterns
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

    def __init__(self, model: APKModel):
        """
        Initialize the scope filter with an APK model.
        
        Args:
            model: APKModel instance from apk_loader
        """
        self.model = model
        self.app_package = model.manifest.package_name
        self.logger = logger
        
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
        
        # Lazy-loaded analysis data
        self._security_strings: Optional[List[SecurityString]] = None
        self._analysis_ready: Optional[AnalysisReadyAPK] = None
        
        # Compile patterns once
        self._compile_patterns()
        
        self.logger.info(f"Initialized ScopeFilter for package: {self.app_package}")
    
    def _compile_patterns(self):
        """Precompile regex patterns for efficiency."""
        self._crypto_regex = {re.compile(p): name for p, name in self.CRYPTO_PATTERNS.items()}
        self._network_regex = {re.compile(p): name for p, name in self.NETWORK_PATTERNS.items()}
        self._storage_regex = {re.compile(p): name for p, name in self.STORAGE_PATTERNS.items()}
        self._reflection_regex = {re.compile(p): name for p, name in self.REFLECTION_PATTERNS.items()}
        self._webview_regex = {re.compile(p): name for p, name in self.WEBVIEW_PATTERNS.items()}
        self._dynamic_code_regex = {re.compile(p): name for p, name in self.DYNAMIC_CODE_PATTERNS.items()}
        
        # String patterns
        self._url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+|content://[^\s<>"{}|\\^`\[\]]+')
        self._api_key_pattern = re.compile(r'[a-zA-Z0-9_\-]{20,}')
        self._ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self._email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self._file_path_pattern = re.compile(r'(?:/data/data/|/sdcard/|/storage/|/mnt/)[^\s<>"{}|\\^`\[\]]*')
        self._db_conn_pattern = re.compile(r'jdbc:|mongodb:|postgres:|mysql:', re.IGNORECASE)
    
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
                    if string not in self._dex_map:  # First occurrence
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
        
        # Check allowed packages
        for allowed in self.ALLOWED_PACKAGES:
            if pkg.startswith(allowed):
                return True
        
        # Check blocked packages
        for blocked in self.BLOCKED_PACKAGES:
            if pkg.startswith(blocked):
                return False
        
        # Check framework packages
        for framework in self.FRAMEWORK_PACKAGES:
            if pkg.startswith(framework):
                return False
        
        # Check library packages
        for library in self.LIBRARY_PACKAGES:
            if pkg.startswith(library):
                return False
        
        # APP_PACKAGE_FILTER: only keep app package
        if self.APP_PACKAGE_FILTER:
            return pkg.startswith(self.app_package)
        
        return True
    
    def _get_filtered_classes(self) -> List[FilteredClass]:
        """Get list of application-owned classes with metadata."""
        if self._app_classes is None:
            self.logger.info("Filtering classes to application scope")
            dex_map = self._build_dex_map()
            filtered = []
            
            for dex in self.model.dex_files:
                for cls in dex.classes:
                    if self.is_app_class(cls):
                        # Parse class name
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
        
        Looks for quoted strings and common patterns in the method signature
        to capture algorithm names, keys, etc.
        
        Args:
            method_sig: Full method signature
            
        Returns:
            List of extracted string parameters
        """
        parameters = []
        
        # Look for quoted strings (most common)
        quoted = re.findall(r'"([^"]+)"', method_sig)
        parameters.extend(quoted)
        
        # Look for string literals in the format used by smali
        # e.g., const-string v0, "AES/CBC/PKCS5Padding"
        const_string = re.findall(r'const-string.*?"([^"]+)"', method_sig)
        parameters.extend(const_string)
        
        # Look for common algorithm names even without quotes
        # This catches things like Cipher.getInstance("AES") in decompiled code
        if 'getInstance' in method_sig:
            # Try to find the parameter after getInstance(
            match = re.search(r'getInstance\(["\']?([^"\',)]+)', method_sig)
            if match:
                param = match.group(1).strip()
                if param and param not in parameters:
                    parameters.append(param)
        
        return parameters
    
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
                        # Use CryptoAPI with parameter extraction
                        params = self._extract_string_parameters(method)
                        apis.append(CryptoAPI(
                            method_signature=method,
                            api_called=api_name,
                            parameters=params,
                            dex_file=dex_map.get(method, "unknown"),
                            category=category
                        ))
                    else:
                        # Use generic APIAPI for other categories
                        apis.append(APIAPI(
                            method_signature=method,
                            api_called=api_name,
                            category=category,
                            dex_file=dex_map.get(method, "unknown")
                        ))
                    break  # Only match once per method
        
        return apis
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
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
    
    def _analyze_string(self, s: str, dex_file: str) -> Optional[SecurityString]:
        """Analyze a single string for security relevance."""
        if len(s) < 4 or s in ['true', 'false', 'null', 'void', 'this']:
            return None
        
        length = len(s)
        entropy = self._calculate_entropy(s)
        
        contains_url = bool(self._url_pattern.search(s))
        contains_ip = bool(self._ip_pattern.search(s))
        contains_email = bool(self._email_pattern.search(s))
        contains_file_path = bool(self._file_path_pattern.search(s))
        contains_db_conn = bool(self._db_conn_pattern.search(s))
        is_high_entropy = entropy > self.MIN_STRING_ENTROPY
        looks_like_api_key = (length >= 20 and bool(self._api_key_pattern.fullmatch(s)) and entropy > 3.5)
        
        # Determine primary pattern
        pattern_matched = None
        if contains_url:
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
            pattern_matched = "High Entropy"
        
        # Only return if something suspicious was found
        if pattern_matched:
            return SecurityString(
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
                entropy=entropy,
                pattern_matched=pattern_matched
            )
        
        return None
    
    def prepare(self) -> AnalysisReadyAPK:
        """
        Prepare analysis-ready data by filtering and categorizing.
        
        Returns:
            AnalysisReadyAPK object ready for rule engine consumption
        """
        if self._analysis_ready is not None:
            return self._analysis_ready
        
        self.logger.info("Preparing analysis-ready APK data")
        
        # Get filtered data
        app_classes = self._get_filtered_classes()
        app_methods = self._get_filtered_methods()
        dex_map = self._build_dex_map()
        
        # Count totals
        total_classes = sum(len(dex.classes) for dex in self.model.dex_files)
        total_methods = sum(len(dex.methods) for dex in self.model.dex_files)
        total_strings = sum(len(dex.strings) for dex in self.model.dex_files)
        
        # Categorize APIs
        self.logger.info("Categorizing API usage")
        crypto_apis = self._categorize_apis(app_methods, self._crypto_regex, "crypto")
        network_apis = self._categorize_apis(app_methods, self._network_regex, "network")
        storage_apis = self._categorize_apis(app_methods, self._storage_regex, "storage")
        reflection_apis = self._categorize_apis(app_methods, self._reflection_regex, "reflection")
        webview_apis = self._categorize_apis(app_methods, self._webview_regex, "webview")
        dynamic_code_apis = self._categorize_apis(app_methods, self._dynamic_code_regex, "dynamic_code")
        
        # Analyze strings
        self.logger.info("Analyzing strings for security issues")
        security_strings = []
        for dex in self.model.dex_files:
            for s in dex.strings:
                result = self._analyze_string(s, dex.file_name)
                if result:
                    security_strings.append(result)
        
        # Filter components
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
        
        # Filter dangerous permissions
        self.logger.info("Identifying dangerous permissions")
        dangerous_permissions = []
        for perm in self.model.manifest.permissions:
            for keyword in self.DANGEROUS_PERMISSIONS:
                if keyword in perm.name.upper():
                    dangerous_permissions.append(perm.name)
                    break
        
        # Convert third-party libraries
        third_party = [
            {
                "name": lib.name,
                "package_prefix": lib.package_prefix,
                "confidence": lib.confidence
            }
            for lib in self.model.third_party_libraries
        ]
        
        # Build analysis-ready object
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
            strings=security_strings,
            exported_components=exported_components,
            dangerous_permissions=dangerous_permissions,
            allow_backup=self.model.manifest.application.allow_backup,
            debuggable=self.model.manifest.application.debuggable,
            uses_cleartext_traffic=self.model.manifest.application.uses_cleartext_traffic,
            network_security_config=self.model.manifest.application.network_security_config,
            third_party_libraries=third_party
        )
        
        self.logger.info("Analysis-ready data prepared successfully")
        return self._analysis_ready
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"ScopeFilter(package={self.app_package})"


def main():
    """Command-line interface for testing."""
    import sys
    import argparse
    from apk_loader import APKLoader
    
    parser = argparse.ArgumentParser(
        description='Scope Filter - Prepare APK data for security analysis'
    )
    parser.add_argument('apk_path', help='Path to the APK file')
    parser.add_argument('-o', '--output', help='Save filtered data to JSON file (optional)')
    parser.add_argument('--compact', action='store_true', help='Save JSON in compact format')
    parser.add_argument('--summary', action='store_true', help='Print summary statistics')
    
    args = parser.parse_args()
    
    try:
        # Load APK
        print(f"Loading APK: {args.apk_path}")
        loader = APKLoader()
        model = loader.load(args.apk_path)
        
        # Apply scope filter
        print("Applying scope filter...")
        scope = ScopeFilter(model)
        analysis_ready = scope.prepare()
        
        print(f"✓ Filtering complete: {analysis_ready.package_name}")
        
        # Save JSON if requested
        if args.output:
            pretty = not args.compact
            analysis_ready.save_json(args.output, pretty=pretty)
            print(f"✓ Filtered data saved to {args.output}")
        
        # Print summary if requested
        if args.summary:
            print("\n" + "="*60)
            print("SCOPE FILTER SUMMARY")
            print("="*60)
            print(f"Package:          {analysis_ready.package_name}")
            print(f"Version:          {analysis_ready.version_name}")
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
            print(f"\nSecurity Issues:")
            print(f"Suspicious strings:     {len(analysis_ready.strings)}")
            print(f"Exported components:    {len(analysis_ready.exported_components)}")
            print(f"Dangerous permissions:  {len(analysis_ready.dangerous_permissions)}")
            print(f"\nApp Configuration:")
            print(f"Allow backup:          {analysis_ready.allow_backup}")
            print(f"Debuggable:            {analysis_ready.debuggable}")
            print(f"Cleartext traffic:     {analysis_ready.uses_cleartext_traffic}")
            print("="*60)
        
        # Show hint if no options
        if not args.output and not args.summary:
            print("\n💡 Tip: Use --output to save JSON or --summary to view details")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())