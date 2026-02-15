"""
APK Loader Module

A production-quality module for extracting exhaustive information from Android APK files
using the androguard library. Designed for security analysis covering OWASP Mobile Top 10
and common vulnerabilities.

Author: Generated for APK Security Analysis
License: MIT
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

try:
    from androguard.core.apk import APK
    from androguard.misc import AnalyzeAPK
    from androguard.core.axml import AXMLPrinter
except ImportError:
    raise ImportError(
        "androguard is required. Install with: pip install androguard"
    )

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logging.warning("cryptography library not available. Certificate parsing will be limited.")


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Custom Exceptions
class APKLoaderError(Exception):
    """Base exception for APK loader errors."""
    pass


class APKNotFoundError(APKLoaderError):
    """Raised when the APK file is not found."""
    pass


class APKParseError(APKLoaderError):
    """Raised when the APK cannot be parsed."""
    pass


# Dataclasses for structured data
@dataclass
class Hashes:
    """Hash values for a file."""
    md5: str
    sha1: str
    sha256: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256
        }


@dataclass
class Certificate:
    """APK certificate information."""
    subject: str
    issuer: str
    serial_number: str
    valid_from: str
    valid_to: str
    fingerprint_md5: str
    fingerprint_sha1: str
    fingerprint_sha256: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "fingerprint_md5": self.fingerprint_md5,
            "fingerprint_sha1": self.fingerprint_sha1,
            "fingerprint_sha256": self.fingerprint_sha256
        }


@dataclass
class APKInfo:
    """APK file metadata."""
    file_path: str
    size_bytes: int
    hashes: Hashes
    certificates: List[Certificate]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "size_bytes": self.size_bytes,
            "hashes": self.hashes.to_dict(),
            "signature_info": {
                "certificates": [cert.to_dict() for cert in self.certificates]
            }
        }


@dataclass
class Permission:
    """Android permission."""
    name: str
    max_sdk_version: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "name": self.name,
            "max_sdk_version": self.max_sdk_version,
            "description": self.description
        }


@dataclass
class Feature:
    """Android feature requirement."""
    name: str
    required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "required": self.required
        }


@dataclass
class Library:
    """Android library requirement."""
    name: str
    required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "required": self.required
        }


@dataclass
class IntentFilter:
    """Intent filter configuration."""
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actions": self.actions,
            "categories": self.categories,
            "data": self.data
        }


@dataclass
class Component:
    """Android component (activity, service, receiver, provider)."""
    type: str  # activity, service, receiver, provider
    name: str
    exported: bool
    permission: Optional[str]
    enabled: bool
    intent_filters: List[IntentFilter] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "type": self.type,
            "name": self.name,
            "exported": self.exported,
            "permission": self.permission,
            "enabled": self.enabled,
            "intent_filters": [f.to_dict() for f in self.intent_filters]
        }
        if self.attributes:
            result["attributes"] = self.attributes
        return result


@dataclass
class Application:
    """Application-level attributes."""
    allow_backup: Optional[bool] = None
    debuggable: Optional[bool] = None
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    backup_agent: Optional[str] = None
    backup_rules: Optional[str] = None
    icon: Optional[str] = None
    label: Optional[str] = None
    theme: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allow_backup": self.allow_backup,
            "debuggable": self.debuggable,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "network_security_config": self.network_security_config,
            "backup_agent": self.backup_agent,
            "backup_rules": self.backup_rules,
            "icon": self.icon,
            "label": self.label,
            "theme": self.theme
        }


@dataclass
class Manifest:
    """AndroidManifest.xml data."""
    package_name: str
    version_name: str
    version_code: str
    min_sdk_version: Optional[str]
    target_sdk_version: Optional[str]
    max_sdk_version: Optional[str]
    permissions: List[Permission]
    features: List[Feature]
    libraries: List[Library]
    application: Application
    components: List[Component]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk_version": self.min_sdk_version,
            "target_sdk_version": self.target_sdk_version,
            "max_sdk_version": self.max_sdk_version,
            "permissions": [p.to_dict() for p in self.permissions],
            "features": [f.to_dict() for f in self.features],
            "libraries": [lib.to_dict() for lib in self.libraries],
            "application": self.application.to_dict(),
            "components": [c.to_dict() for c in self.components]
        }


@dataclass
class DexInfo:
    """DEX file information."""
    file_name: str
    size_bytes: int
    hashes: Hashes
    classes: List[str]
    methods: List[str]
    strings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "size_bytes": self.size_bytes,
            "hashes": self.hashes.to_dict(),
            "classes": self.classes,
            "methods": self.methods,
            "strings": self.strings
        }


@dataclass
class ResourceFile:
    """Resource file information."""
    path: str
    size_bytes: int
    hashes: Dict[str, str]
    content_type: str
    parsed_content: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "hashes": self.hashes,
            "content_type": self.content_type,
            "parsed_content": self.parsed_content
        }


@dataclass
class Resources:
    """APK resources."""
    assets: List[ResourceFile]
    res_files: List[ResourceFile]
    native_libraries: List[ResourceFile]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assets": [a.to_dict() for a in self.assets],
            "res_files": [r.to_dict() for r in self.res_files],
            "native_libraries": [n.to_dict() for n in self.native_libraries]
        }


@dataclass
class ThirdPartyLibrary:
    """Third-party library detection."""
    name: str
    version: Optional[str]
    package_prefix: str
    confidence: str  # high, medium, low
    known_vulnerabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "package_prefix": self.package_prefix,
            "confidence": self.confidence,
            "known_vulnerabilities": self.known_vulnerabilities
        }


@dataclass
class AnalysisMetadata:
    """Analysis metadata."""
    dex_count: int
    strings_count: int
    classes_count: int
    methods_count: int
    total_files: int
    package_name: str
    version_name: str
    version_code: str
    min_sdk_version: Optional[str]
    target_sdk_version: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dex_count": self.dex_count,
            "strings_count": self.strings_count,
            "classes_count": self.classes_count,
            "methods_count": self.methods_count,
            "total_files": self.total_files,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk_version": self.min_sdk_version,
            "target_sdk_version": self.target_sdk_version
        }


@dataclass
class APKModel:
    """Complete APK analysis model."""
    apk: APKInfo
    manifest: Manifest
    dex_files: List[DexInfo]
    resources: Resources
    third_party_libraries: List[ThirdPartyLibrary]
    analysis_metadata: AnalysisMetadata

    def to_dict(self) -> Dict[str, Any]:
        """Convert the model to a JSON-serializable dictionary."""
        return {
            "apk": self.apk.to_dict(),
            "manifest": self.manifest.to_dict(),
            "dex_files": [dex.to_dict() for dex in self.dex_files],
            "resources": self.resources.to_dict(),
            "third_party_libraries": [lib.to_dict() for lib in self.third_party_libraries],
            "analysis_metadata": self.analysis_metadata.to_dict()
        }


class APKLoader:
    """
    Main loader class for extracting comprehensive information from APK files.
    
    This class provides methods to parse and extract all relevant data from an
    Android APK file, including manifest information, DEX files, resources,
    certificates, and more.
    """

    # Known third-party library mappings
    LIBRARY_MAPPINGS = {
        "retrofit2": ("Retrofit", "high"),
        "okhttp3": ("OkHttp", "high"),
        "com.google.gson": ("Gson", "high"),
        "com.squareup.picasso": ("Picasso", "high"),
        "com.squareup.okio": ("Okio", "high"),
        "io.reactivex": ("RxJava", "high"),
        "com.google.android.gms": ("Google Play Services", "high"),
        "androidx": ("AndroidX", "high"),
        "com.facebook": ("Facebook SDK", "high"),
        "com.google.firebase": ("Firebase", "high"),
        "org.apache.commons": ("Apache Commons", "medium"),
        "com.android.volley": ("Volley", "high"),
        "com.github.bumptech.glide": ("Glide", "high"),
        "io.realm": ("Realm", "high"),
        "com.google.dagger": ("Dagger", "high"),
        "org.greenrobot.eventbus": ("EventBus", "high"),
        "com.jakewharton": ("JakeWharton Libraries", "medium"),
        "butterknife": ("ButterKnife", "high"),
        "timber.log": ("Timber", "high"),
        "leakcanary": ("LeakCanary", "high"),
    }

    def __init__(self):
        """Initialize the APK loader."""
        self.logger = logger

    def load(self, apk_path: str) -> APKModel:
        """
        Load and analyze an APK file.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            APKModel containing all extracted information
            
        Raises:
            APKNotFoundError: If the APK file doesn't exist
            APKParseError: If the APK cannot be parsed
        """
        self.logger.info(f"Loading APK: {apk_path}")
        
        # Validate file exists
        if not os.path.exists(apk_path):
            raise APKNotFoundError(f"APK file not found: {apk_path}")
        
        try:
            # Use modern Androguard v4+ API
            # Returns: (APK object, list of DalvikVMFormat objects, Analysis object)
            self.logger.info("Analyzing APK with AnalyzeAPK")
            apk, dex_objects, analysis = AnalyzeAPK(apk_path)
            
            # Extract all components using the APK object
            apk_info = self._extract_apk_info(apk_path, apk)
            manifest = self._extract_manifest(apk)
            
            # Extract DEX files using the dex_objects list
            dex_files = self._extract_dex_files_from_objects(dex_objects)
            
            # Extract resources
            resources = self._extract_resources(apk)
            
            # Detect third-party libraries
            all_classes = []
            for dex in dex_files:
                all_classes.extend(dex.classes)
            third_party_libs = self._detect_third_party_libraries(all_classes)
            
            # Compute analysis metadata
            analysis_metadata = self._compute_analysis_metadata(
                dex_files, resources, manifest
            )
            
            self.logger.info("APK loading completed successfully")
            
            return APKModel(
                apk=apk_info,
                manifest=manifest,
                dex_files=dex_files,
                resources=resources,
                third_party_libraries=third_party_libs,
                analysis_metadata=analysis_metadata
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse APK: {str(e)}")
            raise APKParseError(f"Failed to parse APK: {str(e)}") from e

    def _extract_apk_info(self, apk_path: str, apk: APK) -> APKInfo:
        """Extract APK metadata including hashes and certificates."""
        self.logger.info("Extracting APK metadata")
        
        # Get file size
        size_bytes = os.path.getsize(apk_path)
        
        # Compute hashes
        hashes = self._compute_file_hashes(apk_path)
        
        # Extract certificates
        certificates = self._extract_certificates(apk)
        
        return APKInfo(
            file_path=apk_path,
            size_bytes=size_bytes,
            hashes=hashes,
            certificates=certificates
        )

    def _compute_file_hashes(self, file_path: str) -> Hashes:
        """Compute MD5, SHA1, and SHA256 hashes of a file."""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read in chunks for memory efficiency
            for chunk in iter(lambda: f.read(8192), b''):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return Hashes(
            md5=md5_hash.hexdigest(),
            sha1=sha1_hash.hexdigest(),
            sha256=sha256_hash.hexdigest()
        )

    def _compute_data_hashes(self, data: bytes) -> Hashes:
        """Compute MD5, SHA1, and SHA256 hashes of data."""
        return Hashes(
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest()
        )

    def _extract_certificates(self, apk: APK) -> List[Certificate]:
        """Extract certificate information from APK signature."""
        certificates = []
        
        try:
            # Get certificate data from APK
            certs = apk.get_certificates_der_v2() or apk.get_certificates_der_v3()
            if not certs:
                certs = apk.get_certificates_der_v1()
            
            if not certs:
                self.logger.warning("No certificates found in APK")
                return certificates
            
            for cert_der in certs:
                try:
                    if CRYPTOGRAPHY_AVAILABLE:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        # Extract subject and issuer
                        subject = cert.subject.rfc4514_string()
                        issuer = cert.issuer.rfc4514_string()
                        
                        # Serial number
                        serial_number = str(cert.serial_number)
                        
                        # Validity period
                        valid_from = cert.not_valid_before_utc.isoformat() + "Z"
                        valid_to = cert.not_valid_after_utc.isoformat() + "Z"
                        
                        # Compute fingerprints
                        fp_md5 = hashlib.md5(cert_der).hexdigest()
                        fp_sha1 = hashlib.sha1(cert_der).hexdigest()
                        fp_sha256 = hashlib.sha256(cert_der).hexdigest()
                        
                    else:
                        # Fallback without cryptography library
                        subject = "Certificate details unavailable (cryptography library not installed)"
                        issuer = "Certificate details unavailable"
                        serial_number = "unknown"
                        valid_from = "unknown"
                        valid_to = "unknown"
                        fp_md5 = hashlib.md5(cert_der).hexdigest()
                        fp_sha1 = hashlib.sha1(cert_der).hexdigest()
                        fp_sha256 = hashlib.sha256(cert_der).hexdigest()
                    
                    certificates.append(Certificate(
                        subject=subject,
                        issuer=issuer,
                        serial_number=serial_number,
                        valid_from=valid_from,
                        valid_to=valid_to,
                        fingerprint_md5=fp_md5,
                        fingerprint_sha1=fp_sha1,
                        fingerprint_sha256=fp_sha256
                    ))
                    
                except Exception as e:
                    self.logger.warning(f"Failed to parse certificate: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.warning(f"Failed to extract certificates: {str(e)}")
        
        return certificates

    def _extract_manifest(self, apk: APK) -> Manifest:
        """Extract AndroidManifest.xml information."""
        self.logger.info("Extracting manifest data")
        
        # Basic info
        package_name = apk.get_package() or ""
        version_name = apk.get_androidversion_name() or ""
        version_code = apk.get_androidversion_code() or ""
        min_sdk = apk.get_min_sdk_version() or None
        target_sdk = apk.get_target_sdk_version() or None
        max_sdk = apk.get_max_sdk_version() or None
        
        # Parse XML once for reuse
        try:
            xml_str = apk.get_android_manifest_xml()
            root = ET.fromstring(xml_str.encode('utf-8'))
        except Exception as e:
            self.logger.warning(f"Failed to parse manifest XML: {str(e)}")
            # Return minimal manifest
            return Manifest(
                package_name=package_name,
                version_name=version_name,
                version_code=str(version_code) if version_code else "",
                min_sdk_version=str(min_sdk) if min_sdk else None,
                target_sdk_version=str(target_sdk) if target_sdk else None,
                max_sdk_version=str(max_sdk) if max_sdk else None,
                permissions=[],
                features=[],
                libraries=[],
                application=Application(),
                components=[]
            )
        
        # Helper functions for attribute extraction
        def get_bool_attr(elem, name: str, default: bool = True) -> bool:
            val = elem.get(f'{{http://schemas.android.com/apk/res/android}}{name}')
            if val is None:
                val = elem.get(name)
            if val is None:
                return default
            return val.lower() == 'true'
        
        def get_str_attr(elem, name: str) -> Optional[str]:
            val = elem.get(f'{{http://schemas.android.com/apk/res/android}}{name}')
            if val is None:
                val = elem.get(name)
            return val
        
        # Permissions - extract with maxSdkVersion from XML
        permissions = []
        for perm_elem in root.findall('.//uses-permission'):
            perm_name = get_str_attr(perm_elem, 'name')
            if perm_name:
                max_sdk_version = get_str_attr(perm_elem, 'maxSdkVersion')
                permissions.append(Permission(
                    name=perm_name,
                    max_sdk_version=max_sdk_version,
                    description=None  # Description resolution would require resource parsing
                ))
        
        # Features - extract with required attribute
        features = []
        for feature_elem in root.findall('.//uses-feature'):
            feature_name = get_str_attr(feature_elem, 'name')
            if feature_name:
                required = get_bool_attr(feature_elem, 'required', default=True)
                features.append(Feature(name=feature_name, required=required))
        
        # Libraries - extract with required attribute
        libraries = []
        for lib_elem in root.findall('.//uses-library'):
            lib_name = get_str_attr(lib_elem, 'name')
            if lib_name:
                required = get_bool_attr(lib_elem, 'required', default=True)
                libraries.append(Library(name=lib_name, required=required))
        
        # Application attributes - pass root to avoid re-parsing
        application = self._extract_application_info_from_root(root)
        
        # Components - pass root to avoid re-parsing
        components = self._extract_components_from_root(apk, root)
        
        return Manifest(
            package_name=package_name,
            version_name=version_name,
            version_code=str(version_code) if version_code else "",
            min_sdk_version=str(min_sdk) if min_sdk else None,
            target_sdk_version=str(target_sdk) if target_sdk else None,
            max_sdk_version=str(max_sdk) if max_sdk else None,
            permissions=permissions,
            features=features,
            libraries=libraries,
            application=application,
            components=components
        )

    def _extract_application_info_from_root(self, root: ET.Element) -> Application:
        """Extract application-level attributes from parsed XML root."""
        try:
            # Find application element
            app_elem = root.find('.//application')
            
            if app_elem is None:
                return Application()
            
            # Helper functions for attribute extraction
            def get_bool_attr(name: str) -> Optional[bool]:
                val = app_elem.get(f'{{http://schemas.android.com/apk/res/android}}{name}')
                if val is None:
                    val = app_elem.get(name)
                if val is None:
                    return None
                return val.lower() == 'true'
            
            def get_str_attr(name: str) -> Optional[str]:
                val = app_elem.get(f'{{http://schemas.android.com/apk/res/android}}{name}')
                if val is None:
                    val = app_elem.get(name)
                return val
            
            return Application(
                allow_backup=get_bool_attr('allowBackup'),
                debuggable=get_bool_attr('debuggable'),
                uses_cleartext_traffic=get_bool_attr('usesCleartextTraffic'),
                network_security_config=get_str_attr('networkSecurityConfig'),
                backup_agent=get_str_attr('backupAgent'),
                backup_rules=get_str_attr('backupRules') or get_str_attr('fullBackupContent'),
                icon=get_str_attr('icon'),
                label=get_str_attr('label'),
                theme=get_str_attr('theme')
            )
        
        except Exception as e:
            self.logger.warning(f"Failed to extract application info: {str(e)}")
            return Application()

    def _extract_components_from_root(self, apk: APK, root: ET.Element) -> List[Component]:
        """Extract all components (activities, services, receivers, providers) from parsed XML root."""
        components = []
        
        # Activities
        for activity in apk.get_activities():
            comp = self._parse_component_from_root(root, 'activity', activity)
            if comp:
                components.append(comp)
        
        # Services
        for service in apk.get_services():
            comp = self._parse_component_from_root(root, 'service', service)
            if comp:
                components.append(comp)
        
        # Receivers
        for receiver in apk.get_receivers():
            comp = self._parse_component_from_root(root, 'receiver', receiver)
            if comp:
                components.append(comp)
        
        # Providers
        for provider in apk.get_providers():
            comp = self._parse_component_from_root(root, 'provider', provider)
            if comp:
                components.append(comp)
        
        return components

    def _parse_component_from_root(self, root: ET.Element, comp_type: str, comp_name: str) -> Optional[Component]:
        """Parse a single component from the parsed manifest XML root."""
        try:
            # Map component type to XML tag
            tag_map = {
                'activity': 'activity',
                'service': 'service',
                'receiver': 'receiver',
                'provider': 'provider'
            }
            tag = tag_map.get(comp_type)
            
            # Find the component element
            comp_elem = None
            for elem in root.findall(f'.//application/{tag}'):
                name_attr = elem.get('{http://schemas.android.com/apk/res/android}name')
                if not name_attr:
                    name_attr = elem.get('name')
                
                if name_attr == comp_name or name_attr.endswith('.' + comp_name.split('.')[-1]):
                    comp_elem = elem
                    break
            
            if comp_elem is None:
                # Create minimal component
                return Component(
                    type=comp_type,
                    name=comp_name,
                    exported=False,
                    permission=None,
                    enabled=True,
                    intent_filters=[],
                    attributes={}
                )
            
            def get_bool_attr(elem, name: str, default: bool = True) -> bool:
                val = elem.get(f'{{http://schemas.android.com/apk/res/android}}{name}')
                if val is None:
                    val = elem.get(name)
                if val is None:
                    return default
                return val.lower() == 'true'
            
            def get_str_attr(elem, name: str) -> Optional[str]:
                val = elem.get(f'{{http://schemas.android.com/apk/res/android}}{name}')
                if val is None:
                    val = elem.get(name)
                return val
            
            # Extract basic attributes
            exported = get_bool_attr(comp_elem, 'exported', default=False)
            permission = get_str_attr(comp_elem, 'permission')
            enabled = get_bool_attr(comp_elem, 'enabled', default=True)
            
            # Extract intent filters
            intent_filters = []
            for intent_filter in comp_elem.findall('intent-filter'):
                actions = []
                categories = []
                data = []
                
                for action in intent_filter.findall('action'):
                    action_name = get_str_attr(action, 'name')
                    if action_name:
                        actions.append(action_name)
                
                for category in intent_filter.findall('category'):
                    cat_name = get_str_attr(category, 'name')
                    if cat_name:
                        categories.append(cat_name)
                
                for data_elem in intent_filter.findall('data'):
                    data_dict = {}
                    for attr in ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                        val = get_str_attr(data_elem, attr)
                        if val:
                            data_dict[attr] = val
                    if data_dict:
                        data.append(data_dict)
                
                intent_filters.append(IntentFilter(
                    actions=actions,
                    categories=categories,
                    data=data
                ))
            
            # Provider-specific attributes
            attributes = {}
            if comp_type == 'provider':
                authorities = get_str_attr(comp_elem, 'authorities')
                if authorities:
                    attributes['authorities'] = authorities
                grant_uri = get_bool_attr(comp_elem, 'grantUriPermissions', default=False)
                attributes['grantUriPermissions'] = grant_uri
            
            return Component(
                type=comp_type,
                name=comp_name,
                exported=exported,
                permission=permission,
                enabled=enabled,
                intent_filters=intent_filters,
                attributes=attributes
            )
        
        except Exception as e:
            self.logger.debug(f"Failed to parse component {comp_name}: {str(e)}")
            return Component(
                type=comp_type,
                name=comp_name,
                exported=False,
                permission=None,
                enabled=True,
                intent_filters=[],
                attributes={}
            )

    def _extract_dex_files_from_objects(self, dex_objects: List) -> List[DexInfo]:
        """
        Extract information from DEX objects returned by AnalyzeAPK.
        
        Args:
            dex_objects: List of DalvikVMFormat objects from AnalyzeAPK
            
        Returns:
            List of DexInfo objects with extracted data
        """
        self.logger.info("Extracting DEX files from parsed objects")
        
        dex_files = []
        
        if not dex_objects:
            self.logger.warning("No DEX objects provided")
            return dex_files
        
        self.logger.info(f"Found {len(dex_objects)} DEX object(s)")
        
        for idx, dex in enumerate(dex_objects):
            dex_name = f"classes{idx + 1}.dex" if idx > 0 else "classes.dex"
            
            try:
                self.logger.info(f"Processing {dex_name} ({idx + 1}/{len(dex_objects)})")
                
                # Get raw DEX bytes for hashing
                try:
                    dex_data = dex.get_buff()
                except AttributeError:
                    # Fallback if get_buff() doesn't exist
                    self.logger.warning(f"{dex_name}: Could not get raw DEX bytes, skipping hash computation")
                    dex_data = None
                
                # Validate DEX data if available
                if dex_data:
                    if len(dex_data) < 40:
                        self.logger.warning(f"{dex_name}: DEX data too small")
                        dex_files.append(self._create_empty_dex_info(dex_name, dex_data))
                        continue
                    
                    # Check DEX magic number
                    magic = dex_data[:8]
                    if not magic.startswith(b'dex\n'):
                        self.logger.warning(f"{dex_name}: Invalid DEX magic number: {magic[:4]}")
                        dex_files.append(self._create_empty_dex_info(dex_name, dex_data))
                        continue
                    
                    # Compute hashes
                    hashes = self._compute_data_hashes(dex_data)
                    size_bytes = len(dex_data)
                else:
                    # No raw bytes available, use empty hashes
                    hashes = Hashes("", "", "")
                    size_bytes = 0
                
                # Extract classes
                self.logger.debug(f"{dex_name}: Extracting classes")
                classes = []
                try:
                    for cls in dex.get_classes():
                        class_name = cls.get_name()
                        if class_name:
                            classes.append(class_name)
                except Exception as e:
                    self.logger.error(f"{dex_name}: Failed to extract classes: {str(e)}")
                    import traceback
                    self.logger.debug(traceback.format_exc())
                
                self.logger.info(f"{dex_name}: Extracted {len(classes)} classes")
                
                # Extract methods
                self.logger.debug(f"{dex_name}: Extracting methods")
                methods = []
                try:
                    for cls in dex.get_classes():
                        class_name = cls.get_name()
                        for method in cls.get_methods():
                            try:
                                method_name = method.get_name()
                                method_descriptor = method.get_descriptor()
                                method_sig = f"{class_name}->{method_name}{method_descriptor}"
                                methods.append(method_sig)
                            except Exception as e:
                                self.logger.debug(f"Failed to extract method signature: {str(e)}")
                                continue
                except Exception as e:
                    self.logger.error(f"{dex_name}: Failed to extract methods: {str(e)}")
                    import traceback
                    self.logger.debug(traceback.format_exc())
                
                self.logger.info(f"{dex_name}: Extracted {len(methods)} methods")
                
                # Extract strings
                self.logger.debug(f"{dex_name}: Extracting strings")
                strings = []
                try:
                    for s in dex.get_strings():
                        if s:  # Filter out None/empty strings
                            strings.append(s)
                except Exception as e:
                    self.logger.error(f"{dex_name}: Failed to extract strings: {str(e)}")
                    import traceback
                    self.logger.debug(traceback.format_exc())
                
                self.logger.info(f"{dex_name}: Extracted {len(strings)} strings")
                
                dex_info = DexInfo(
                    file_name=dex_name,
                    size_bytes=size_bytes,
                    hashes=hashes,
                    classes=classes,
                    methods=methods,
                    strings=strings
                )
                
                dex_files.append(dex_info)
                self.logger.info(f"{dex_name}: Successfully processed")
                
            except Exception as e:
                self.logger.error(f"Failed to process {dex_name}: {str(e)}")
                import traceback
                self.logger.error(traceback.format_exc())
                
                # Add entry with empty data
                dex_files.append(self._create_empty_dex_info(dex_name, None))
        
        return dex_files
    
    def _create_empty_dex_info(self, dex_name: str, dex_data: Optional[bytes]) -> DexInfo:
        """Create an empty DexInfo entry for a failed DEX parse."""
        if dex_data:
            try:
                hashes = self._compute_data_hashes(dex_data)
                size = len(dex_data)
            except:
                hashes = Hashes("", "", "")
                size = 0
        else:
            hashes = Hashes("", "", "")
            size = 0
        
        return DexInfo(
            file_name=dex_name,
            size_bytes=size,
            hashes=hashes,
            classes=[],
            methods=[],
            strings=[]
        )

    def _extract_resources(self, apk: APK) -> Resources:
        """Extract all resources including assets, res files, and native libraries."""
        self.logger.info("Extracting resources")
        
        assets = []
        res_files = []
        native_libraries = []
        
        try:
            # Get all files from APK
            files = apk.get_files()
            
            for file_path in files:
                try:
                    # Get file data
                    file_data = apk.get_file(file_path)
                    
                    if file_data is None:
                        continue
                    
                    size_bytes = len(file_data)
                    
                    # Determine file type and category
                    if file_path.startswith('assets/'):
                        # Asset file
                        content_type = self._detect_content_type(file_path)
                        hashes_dict = self._compute_data_hashes(file_data).to_dict()
                        
                        assets.append(ResourceFile(
                            path=file_path,
                            size_bytes=size_bytes,
                            hashes=hashes_dict,
                            content_type=content_type,
                            parsed_content=None
                        ))
                    
                    elif file_path.startswith('res/'):
                        # Resource file
                        content_type = self._detect_content_type(file_path)
                        hashes_dict = self._compute_data_hashes(file_data).to_dict()
                        
                        # Parse security-relevant XML files
                        parsed_content = None
                        if content_type == 'xml' and any(name in file_path for name in 
                            ['network_security_config', 'backup_rules', 'backup_descriptor']):
                            parsed_content = self._parse_security_xml(file_data)
                        
                        res_files.append(ResourceFile(
                            path=file_path,
                            size_bytes=size_bytes,
                            hashes=hashes_dict,
                            content_type=content_type,
                            parsed_content=parsed_content
                        ))
                    
                    elif file_path.startswith('lib/') and file_path.endswith('.so'):
                        # Native library
                        hashes_dict = self._compute_data_hashes(file_data).to_dict()
                        
                        native_libraries.append(ResourceFile(
                            path=file_path,
                            size_bytes=size_bytes,
                            hashes=hashes_dict,
                            content_type='native',
                            parsed_content=None
                        ))
                
                except Exception as e:
                    self.logger.debug(f"Failed to process file {file_path}: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.warning(f"Failed to extract resources: {str(e)}")
        
        return Resources(
            assets=assets,
            res_files=res_files,
            native_libraries=native_libraries
        )

    def _detect_content_type(self, file_path: str) -> str:
        """Detect content type from file extension."""
        ext = Path(file_path).suffix.lower()
        
        type_map = {
            '.xml': 'xml',
            '.json': 'json',
            '.png': 'image',
            '.jpg': 'image',
            '.jpeg': 'image',
            '.webp': 'image',
            '.gif': 'image',
            '.arsc': 'arsc',
            '.so': 'native',
            '.dex': 'dex',
            '.txt': 'text',
            '.html': 'html',
            '.js': 'javascript',
            '.css': 'css'
        }
        
        return type_map.get(ext, 'unknown')

    def _parse_security_xml(self, data: bytes) -> Optional[Dict[str, Any]]:
            """
            Parse security-relevant XML files like network_security_config.xml.
            Handles binary Android XML (AXML) format.
            """
            try:
                
                # Decode binary XML using AXMLPrinter
                axml = AXMLPrinter(data)
                xml_str = axml.get_xml()
                if isinstance(xml_str, bytes):
                    xml_str = xml_str.decode('utf-8', errors='ignore')
                
                root = ET.fromstring(xml_str)
                
                # Network security config
                if root.tag == 'network-security-config' or 'network-security-config' in xml_str:
                    domain_configs = []
                    
                    for domain_config in root.findall('.//domain-config'):
                        domains = []
                        for domain in domain_config.findall('domain'):
                            if domain.text:
                                domains.append(domain.text.strip())
                        
                        cleartext = domain_config.get('cleartextTrafficPermitted')
                        cleartext_allowed = cleartext == 'true' if cleartext else None
                        
                        # Certificate pinning
                        pinning = {}
                        pin_set = domain_config.find('.//pin-set')
                        if pin_set is not None:
                            for pin in pin_set.findall('pin'):
                                digest = pin.get('digest')
                                if digest and pin.text:
                                    pinning['digest'] = f"{digest}/{pin.text.strip()}"
                                    break
                        
                        for domain_name in domains:
                            domain_configs.append({
                                'domain': domain_name,
                                'cleartext_traffic_allowed': cleartext_allowed,
                                'pinning': pinning if pinning else None
                            })
                    
                    if domain_configs:
                        return {'domain_config': domain_configs}
                
                return None
            
            except Exception as e:
                self.logger.debug(f"Failed to parse security XML: {str(e)}")
                return None

    def _detect_third_party_libraries(self, classes: List[str]) -> List[ThirdPartyLibrary]:
        """Detect third-party libraries from class names."""
        self.logger.info("Detecting third-party libraries")
        
        detected_libs = {}
        
        for class_name in classes:
            # Remove L prefix and convert to package format
            pkg = class_name.lstrip('L').replace('/', '.')
            
            # Check against known library prefixes
            for prefix, (lib_name, confidence) in self.LIBRARY_MAPPINGS.items():
                if pkg.startswith(prefix):
                    if lib_name not in detected_libs:
                        detected_libs[lib_name] = ThirdPartyLibrary(
                            name=lib_name,
                            version=None,  # Version detection would require more complex analysis
                            package_prefix=prefix,
                            confidence=confidence,
                            known_vulnerabilities=[]
                        )
                    break
        
        return list(detected_libs.values())

    def _compute_analysis_metadata(
        self,
        dex_files: List[DexInfo],
        resources: Resources,
        manifest: Manifest
    ) -> AnalysisMetadata:
        """Compute analysis metadata."""
        self.logger.info("Computing analysis metadata")
        
        strings_count = sum(len(dex.strings) for dex in dex_files)
        classes_count = sum(len(dex.classes) for dex in dex_files)
        methods_count = sum(len(dex.methods) for dex in dex_files)
        
        total_files = (
            len(resources.assets) +
            len(resources.res_files) +
            len(resources.native_libraries)
        )
        
        return AnalysisMetadata(
            dex_count=len(dex_files),
            strings_count=strings_count,
            classes_count=classes_count,
            methods_count=methods_count,
            total_files=total_files,
            package_name=manifest.package_name,
            version_name=manifest.version_name,
            version_code=manifest.version_code,
            min_sdk_version=manifest.min_sdk_version,
            target_sdk_version=manifest.target_sdk_version
        )


def main():
    """Command-line interface for testing."""
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python apk_loader.py <apk_path> [output_json]")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output.json"
    
    try:
        loader = APKLoader()
        model = loader.load(apk_path)
        
        with open(output_path, 'w') as f:
            json.dump(model.to_dict(), f, indent=2)
        
        print(f"APK analysis completed. Output saved to {output_path}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()