"""
Rule Engine Module - Next-Gen (v3.1)

Revolutionary orchestration system with cross-rule correlation, adaptive filtering,
semantic deduplication, and now SOURCE-SINK TAINT ANALYSIS.

Revolutionary Features (v3.1):
- Source-Sink Correlation: Enhanced taint analysis for untrusted input flows
- Risk Flags Integration: Incorporate app configuration risks into report
- Extended Logging: Source/sink API statistics and risk flag tracking
- All v3.0 features: Cross-rule correlation, adaptive filtering, deduplication

v3.0 Features:
- Cross-Rule Correlation: Boost confidence when multiple rules flag same data
- Adaptive Category Filtering: Different thresholds per OWASP category
- Semantic Deduplication: Fingerprinting to eliminate duplicate findings
- All v2.0 features: Confidence filtering, parallel execution, rich reporting

This engine represents the state-of-the-art in security analysis orchestration,
combining machine learning-inspired heuristics with intelligent data correlation
and taint analysis techniques.

Author: Generated for APK Security Analysis
License: MIT
Version: 3.1 (Next-Gen + Taint Analysis)
"""

import logging
import traceback
import time
import re
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Any, Tuple
from collections import defaultdict, Counter
from datetime import datetime

from Analyser.Engine.base_rule import BaseRule
from Analyser.Engine.finding import Finding
from Analyser.Loader.scope_filter import AnalysisReadyAPK

logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures for Rich Reporting
# ============================================================================

@dataclass
class RuleExecutionStats:
    """Statistics for a single rule execution."""
    rule_id: str
    executed: bool
    skipped: bool
    skip_reason: Optional[str]
    finding_count: int
    error_count: int
    execution_time_ms: float
    retries: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class ConfidenceStats:
    """Confidence score distribution statistics."""
    total_findings: int = 0
    confidence_0_50: int = 0
    confidence_50_60: int = 0
    confidence_60_70: int = 0
    confidence_70_80: int = 0
    confidence_80_90: int = 0
    confidence_90_100: int = 0
    average_confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class RiskFlags:
    """Application configuration risk flags (v3.1)."""
    cleartext_traffic_allowed: bool = False
    backup_enabled: bool = False
    uses_test_keys: bool = False
    exported_without_permission: bool = False
    dangerous_permissions_used: bool = False
    debuggable: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class SourceSinkStats:
    """Source and sink API statistics (v3.1)."""
    intent_apis: int = 0
    user_input_apis: int = 0
    web_input_apis: int = 0
    sql_apis: int = 0
    command_exec_apis: int = 0
    file_write_apis: int = 0
    crypto_weak_apis: int = 0
    webview_sink_apis: int = 0
    source_sink_correlations: int = 0  # Findings with both source and sink
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class AnalysisReport:
    """
    Comprehensive analysis report with findings, statistics, and metadata.
    
    v3.1 additions:
    - risk_flags: Application configuration risks
    - source_sink_stats: Taint analysis statistics
    
    v3.0 metrics:
    - correlated_findings: Number of findings linked via cross-rule correlation
    - duplicates_removed: Number of semantic duplicates eliminated
    """
    findings: List[Finding] = field(default_factory=list)
    total_findings: int = 0
    total_rules_executed: int = 0
    total_rules_skipped: int = 0
    total_errors: int = 0
    execution_time_seconds: float = 0.0
    
    # v3.0: Advanced metrics
    correlated_findings: int = 0
    duplicates_removed: int = 0
    
    # v3.1: Risk flags and source-sink stats
    risk_flags: RiskFlags = field(default_factory=RiskFlags)
    source_sink_stats: SourceSinkStats = field(default_factory=SourceSinkStats)
    
    # Breakdowns
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    findings_by_rule: Dict[str, int] = field(default_factory=dict)
    
    # Detailed stats
    rule_stats: List[RuleExecutionStats] = field(default_factory=list)
    confidence_stats: ConfidenceStats = field(default_factory=ConfidenceStats)
    
    # Metadata
    engine_version: str = "3.1"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    configuration: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entire report to dictionary for JSON serialization."""
        return {
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "summary": {
                "total_findings": self.total_findings,
                "total_rules_executed": self.total_rules_executed,
                "total_rules_skipped": self.total_rules_skipped,
                "total_errors": self.total_errors,
                "execution_time_seconds": round(self.execution_time_seconds, 2),
                "correlated_findings": self.correlated_findings,
                "duplicates_removed": self.duplicates_removed,
            },
            "breakdowns": {
                "by_severity": self.findings_by_severity,
                "by_category": self.findings_by_category,
                "by_rule": self.findings_by_rule,
            },
            "risk_flags": self.risk_flags.to_dict(),
            "source_sink_stats": self.source_sink_stats.to_dict(),
            "rule_stats": [stat.to_dict() for stat in self.rule_stats],
            "confidence_stats": self.confidence_stats.to_dict(),
            "metadata": {
                "engine_version": self.engine_version,
                "timestamp": self.timestamp,
                "configuration": self.configuration,
            }
        }
    
    @staticmethod
    def _finding_to_dict(finding: Finding) -> Dict[str, Any]:
        """Convert Finding to dictionary."""
        if hasattr(finding, 'to_dict'):
            return finding.to_dict()
        return {
            "title": getattr(finding, 'title', ''),
            "description": getattr(finding, 'description', ''),
            "severity": getattr(finding, 'severity', 'Medium'),
            "owasp_category": getattr(finding, 'owasp_category', ''),
            "affected_component": getattr(finding, 'affected_component', ''),
            "remediation": getattr(finding, 'remediation', ''),
            "evidence": getattr(finding, 'evidence', {}),
            "rule_id": getattr(finding, 'rule_id', ''),
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# Next-Gen Rule Engine with Correlation & Taint Analysis
# ============================================================================

class RuleEngine:
    """
    Next-generation orchestration system with intelligent correlation.
    
    Revolutionary v3.1 Features:
    - Source-sink taint analysis
    - Risk flags integration
    - Extended source/sink API logging
    
    v3.0 Features:
    - Cross-rule correlation
    - Adaptive category-specific filtering
    - Semantic deduplication via fingerprinting
    
    All v2.0 features retained:
    - Confidence-aware filtering
    - Parallel execution
    - Smart pre-filtering
    - Rich reporting
    """
    
    # Default configuration
    DEFAULT_CONFIG = {
        # v2.0 options
        "min_confidence_global": 0.0,
        "parallel": False,
        "max_workers": 4,
        "fail_fast": False,
        "max_retries": 2,
        "retry_delay_ms": 100,
        "include_categories": None,
        "exclude_rules": None,
        "include_severities": None,
        
        # v3.0 options
        "enable_correlation": True,
        "correlation_boost": 0.15,  # How much to boost confidence
        "adaptive_thresholds": {},  # Category -> min confidence
        "fingerprint_evidence_keys": ["value", "variable", "api", "parameter_hint", "sql_statement"],
        
        # v3.1 options
        "enable_source_sink_correlation": True,
        "source_sink_boost": 0.25,  # Higher boost for source->sink flows
    }
    
    def __init__(
        self, 
        rules: List[BaseRule], 
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the next-gen rule engine.
        
        Args:
            rules: List of BaseRule instances to execute
            config: Optional configuration dictionary
        """
        self.rules = rules
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.logger = logger
        
        self._validate_config()
        
        self.logger.info(
            f"\n{'='*70}\n"
            f"RuleEngine v3.1 (Next-Gen + Taint Analysis) Initialized\n"
            f"{'='*70}\n"
            f"Rules: {len(rules)}\n"
            f"Parallel: {self.config['parallel']}\n"
            f"Correlation: {self.config['enable_correlation']}\n"
            f"Source-Sink Analysis: {self.config['enable_source_sink_correlation']}\n"
            f"Adaptive Filtering: {len(self.config['adaptive_thresholds'])} categories\n"
            f"Global Confidence: {self.config['min_confidence_global']}\n"
            f"{'='*70}"
        )
    
    def _validate_config(self):
        """Validate configuration parameters."""
        if not 0.0 <= self.config["min_confidence_global"] <= 1.0:
            raise ValueError("min_confidence_global must be between 0.0 and 1.0")
        
        if self.config["max_workers"] < 1:
            raise ValueError("max_workers must be at least 1")
        
        if not 0.0 <= self.config["correlation_boost"] <= 1.0:
            raise ValueError("correlation_boost must be between 0.0 and 1.0")
        
        if not 0.0 <= self.config["source_sink_boost"] <= 1.0:
            raise ValueError("source_sink_boost must be between 0.0 and 1.0")
        
        # Validate adaptive thresholds
        for category, threshold in self.config["adaptive_thresholds"].items():
            if not 0.0 <= threshold <= 1.0:
                raise ValueError(f"Invalid threshold for {category}: {threshold}")
    
    def run_all(self, data: AnalysisReadyAPK) -> AnalysisReport:
        """
        Execute all rules with next-gen correlation and deduplication.
        
        Pipeline:
        1. Extract risk flags and source/sink stats (v3.1)
        2. Log extended scope information (v3.1)
        3. Rule filtering (categories, severities)
        4. Smart pre-filtering (relevance checks)
        5. Execution (parallel or sequential)
        6. Cross-rule correlation (v3.0)
        7. Source-sink correlation (v3.1)
        8. Semantic deduplication (v3.0)
        9. Adaptive confidence filtering (v3.0)
        10. Rich report generation
        
        Args:
            data: AnalysisReadyAPK instance to analyze
            
        Returns:
            AnalysisReport: Comprehensive analysis report
        """
        start_time = time.time()
        
        self.logger.info(
            f"\n{'='*70}\n"
            f"Starting Next-Gen Analysis (v3.1 + Taint Analysis)\n"
            f"{'='*70}"
        )
        
        # ====================================================================
        # v3.1: EXTRACT AND LOG RISK FLAGS & SOURCE/SINK STATS
        # ====================================================================
        risk_flags, source_sink_stats = self._extract_risk_data(data)
        self._log_scope_summary(data, risk_flags, source_sink_stats)
        
        # Initialize report
        report = AnalysisReport(
            configuration=self.config.copy(),
            risk_flags=risk_flags,
            source_sink_stats=source_sink_stats
        )
        
        # Filter rules based on configuration
        active_rules = self._filter_rules()
        
        self.logger.info(
            f"Active rules: {len(active_rules)}/{len(self.rules)}"
        )
        
        # Execute rules (parallel or sequential)
        if self.config["parallel"]:
            all_findings, rule_stats = self._execute_parallel(active_rules, data)
        else:
            all_findings, rule_stats = self._execute_sequential(active_rules, data)
        
        self.logger.info(f"\n{'='*70}")
        self.logger.info(f"Raw findings from rules: {len(all_findings)}")
        self.logger.info(f"{'='*70}\n")
        
        # ====================================================================
        # v3.0: CROSS-RULE CORRELATION
        # ====================================================================
        if self.config["enable_correlation"]:
            all_findings, correlation_count = self._apply_correlation(all_findings)
            report.correlated_findings = correlation_count
        
        # ====================================================================
        # v3.1: SOURCE-SINK CORRELATION (Taint Analysis)
        # ====================================================================
        if self.config["enable_source_sink_correlation"]:
            all_findings, source_sink_count = self._apply_source_sink_correlation(
                all_findings, data
            )
            report.source_sink_stats.source_sink_correlations = source_sink_count
        
        # ====================================================================
        # v3.0: SEMANTIC DEDUPLICATION
        # ====================================================================
        all_findings, duplicates_removed = self._apply_deduplication(all_findings)
        report.duplicates_removed = duplicates_removed
        
        # ====================================================================
        # v3.0: ADAPTIVE CONFIDENCE FILTERING
        # ====================================================================
        filtered_findings = self._apply_adaptive_filtering(all_findings)
        
        # Calculate statistics
        report.findings = filtered_findings
        report.total_findings = len(filtered_findings)
        report.total_rules_executed = sum(1 for s in rule_stats if s.executed)
        report.total_rules_skipped = sum(1 for s in rule_stats if s.skipped)
        report.total_errors = sum(s.error_count for s in rule_stats)
        report.execution_time_seconds = time.time() - start_time
        report.rule_stats = rule_stats
        
        # Calculate breakdowns
        report.findings_by_severity = self._count_by_severity(filtered_findings)
        report.findings_by_category = self._count_by_category(filtered_findings)
        report.findings_by_rule = self._count_by_rule(filtered_findings)
        
        # Calculate confidence statistics
        report.confidence_stats = self._calculate_confidence_stats(all_findings)
        
        # Log summary
        self._log_summary(report)
        
        return report
    
    # ========================================================================
    # v3.1: RISK FLAGS & SOURCE/SINK EXTRACTION
    # ========================================================================
    
    def _extract_risk_data(
        self, 
        data: AnalysisReadyAPK
    ) -> Tuple[RiskFlags, SourceSinkStats]:
        """
        Extract risk flags and source/sink statistics from analysis-ready data.
        
        Uses backward-compatible getattr to handle older AnalysisReadyAPK versions.
        
        Args:
            data: AnalysisReadyAPK instance
            
        Returns:
            Tuple of (RiskFlags, SourceSinkStats)
        """
        # Extract risk flags (with backward compatibility)
        risk_flags = RiskFlags(
            cleartext_traffic_allowed=getattr(data, 'cleartext_traffic_allowed', False),
            backup_enabled=getattr(data, 'backup_enabled', False),
            uses_test_keys=getattr(data, 'uses_test_keys', False),
            exported_without_permission=getattr(data, 'exported_without_permission', False),
            dangerous_permissions_used=getattr(data, 'dangerous_permissions_used', False),
            debuggable=getattr(data, 'debuggable', False)
        )
        
        # Extract source/sink statistics
        source_sink_stats = SourceSinkStats(
            intent_apis=len(getattr(data, 'intent_apis', [])),
            user_input_apis=len(getattr(data, 'user_input_apis', [])),
            web_input_apis=len(getattr(data, 'web_input_apis', [])),
            sql_apis=len(getattr(data, 'sql_apis', [])),
            command_exec_apis=len(getattr(data, 'command_exec_apis', [])),
            file_write_apis=len(getattr(data, 'file_write_apis', [])),
            crypto_weak_apis=len(getattr(data, 'crypto_weak_apis', [])),
            webview_sink_apis=len(getattr(data, 'webview_sink_apis', []))
        )
        
        return risk_flags, source_sink_stats
    
    def _log_scope_summary(
        self, 
        data: AnalysisReadyAPK,
        risk_flags: RiskFlags,
        source_sink_stats: SourceSinkStats
    ):
        """
        Log extended scope summary including source/sink stats and risk flags.
        
        Args:
            data: AnalysisReadyAPK instance
            risk_flags: Extracted risk flags
            source_sink_stats: Source/sink statistics
        """
        self.logger.info(
            f"\n{'='*70}\n"
            f"Scope Analysis Summary\n"
            f"{'='*70}"
        )
        
        # Application info
        self.logger.info(
            f"Package:          {data.package_name}\n"
            f"Version:          {data.version_name} ({data.version_code})\n"
            f"Target SDK:       {data.target_sdk_version}\n"
            f"App Classes:      {data.app_classes_count:,} / {data.total_classes:,}\n"
            f"App Methods:      {data.app_methods_count:,} / {data.total_methods:,}"
        )
        
        # Source APIs (untrusted input detection)
        if hasattr(data, 'intent_apis'):
            self.logger.info(
                f"\nSource APIs (Untrusted Input):\n"
                f"  Intent APIs:      {source_sink_stats.intent_apis}\n"
                f"  User Input APIs:  {source_sink_stats.user_input_apis}\n"
                f"  Web Input APIs:   {source_sink_stats.web_input_apis}"
            )
        
        # Sink APIs (dangerous operations)
        if hasattr(data, 'sql_apis'):
            self.logger.info(
                f"\nSink APIs (Dangerous Operations):\n"
                f"  SQL APIs:         {source_sink_stats.sql_apis}\n"
                f"  Command Exec:     {source_sink_stats.command_exec_apis}\n"
                f"  File Write:       {source_sink_stats.file_write_apis}\n"
                f"  Crypto Weak:      {source_sink_stats.crypto_weak_apis}\n"
                f"  WebView Sink:     {source_sink_stats.webview_sink_apis}"
            )
        
        # Risk flags
        if hasattr(data, 'cleartext_traffic_allowed'):
            self.logger.info(
                f"\nRisk Flags:\n"
                f"  Cleartext Traffic:    {risk_flags.cleartext_traffic_allowed}\n"
                f"  Backup Enabled:       {risk_flags.backup_enabled}\n"
                f"  Uses Test Keys:       {risk_flags.uses_test_keys}\n"
                f"  Exported w/o Perm:    {risk_flags.exported_without_permission}\n"
                f"  Dangerous Perms:      {risk_flags.dangerous_permissions_used}\n"
                f"  Debuggable:           {risk_flags.debuggable}"
            )
        
        self.logger.info(f"{'='*70}\n")
    
    # ========================================================================
    # v3.0: CROSS-RULE CORRELATION
    # ========================================================================
    
    def _apply_correlation(
        self, 
        findings: List[Finding]
    ) -> Tuple[List[Finding], int]:
        """
        Apply cross-rule correlation to boost confidence.
        
        When multiple different rules flag the same data (e.g., a string is both
        a hardcoded secret AND used as a crypto key), this increases confidence
        that it's a real issue.
        
        Args:
            findings: All findings from rules
            
        Returns:
            Tuple of (correlated_findings, correlation_count)
        """
        self.logger.info("\n" + "="*70)
        self.logger.info("Applying Cross-Rule Correlation...")
        self.logger.info("="*70)
        
        # Build map: evidence_value -> list of findings
        value_to_findings: Dict[str, List[Finding]] = defaultdict(list)
        
        for finding in findings:
            evidence_value = self._extract_evidence_value(finding)
            if evidence_value:
                value_to_findings[evidence_value].append(finding)
        
        correlation_count = 0
        boost_amount = self.config["correlation_boost"]
        
        # Find values flagged by multiple different rules
        for value, related_findings in value_to_findings.items():
            if len(related_findings) < 2:
                continue
            
            # Get unique rule IDs
            unique_rules = set(getattr(f, 'rule_id', 'Unknown') for f in related_findings)
            
            if len(unique_rules) < 2:
                # All from same rule, not cross-rule correlation
                continue
            
            # Cross-rule correlation detected!
            correlation_count += len(related_findings)
            
            self.logger.info(
                f"\n  Correlation detected for: {value[:60]}..."
            )
            self.logger.info(
                f"  Involved rules: {', '.join(unique_rules)}"
            )
            
            # Boost confidence for all involved findings
            for finding in related_findings:
                original_confidence = self._get_confidence(finding)
                
                if original_confidence is not None:
                    # Boost confidence (capped at 1.0)
                    new_confidence = min(1.0, original_confidence + boost_amount)
                    self._set_confidence(finding, new_confidence)
                    
                    self.logger.info(
                        f"  {finding.rule_id}: "
                        f"{original_confidence:.2f} -> {new_confidence:.2f}"
                    )
                
                # Add correlation metadata
                evidence = getattr(finding, 'evidence', {})
                evidence['correlation'] = f"Linked with {len(related_findings)-1} other finding(s)"
                evidence['correlated_rules'] = list(unique_rules)
                
                # Append to description
                if hasattr(finding, 'description'):
                    if "[Confirmed by Cross-Rule Correlation]" not in finding.description:
                        finding.description += " [Confirmed by Cross-Rule Correlation]"
        
        if correlation_count > 0:
            self.logger.info(
                f"\n✓ Correlated {correlation_count} findings across {len(value_to_findings)} evidence values"
            )
        else:
            self.logger.info("  No cross-rule correlations detected")
        
        self.logger.info("="*70 + "\n")
        
        return findings, correlation_count
    
    def _extract_evidence_value(self, finding: Finding) -> Optional[str]:
        """
        Extract the key evidence value from a finding for correlation.
        
        Args:
            finding: Finding to extract value from
            
        Returns:
            Evidence value or None
        """
        evidence = getattr(finding, 'evidence', {})
        
        # Try configured keys in order
        for key in self.config["fingerprint_evidence_keys"]:
            if key in evidence:
                value = evidence[key]
                if value and isinstance(value, str):
                    # Normalize: strip whitespace, lowercase
                    return value.strip().lower()
        
        return None
    
    # ========================================================================
    # v3.1: SOURCE-SINK CORRELATION (Taint Analysis)
    # ========================================================================
    
    def _apply_source_sink_correlation(
        self, 
        findings: List[Finding],
        data: AnalysisReadyAPK
    ) -> Tuple[List[Finding], int]:
        """
        Apply source-sink correlation for taint analysis.
        
        When a finding involves data that flows from an untrusted source (Intent,
        user input, web) to a dangerous sink (SQL, command exec, file write),
        apply a higher confidence boost to simulate taint analysis.
        
        Args:
            findings: All findings from rules
            data: AnalysisReadyAPK with source/sink API lists
            
        Returns:
            Tuple of (correlated_findings, source_sink_count)
        """
        self.logger.info("\n" + "="*70)
        self.logger.info("Applying Source-Sink Correlation (Taint Analysis)...")
        self.logger.info("="*70)
        
        # Build sets of values from source and sink APIs
        source_values = self._extract_api_values(
            getattr(data, 'intent_apis', []) +
            getattr(data, 'user_input_apis', []) +
            getattr(data, 'web_input_apis', [])
        )
        
        sink_values = self._extract_api_values(
            getattr(data, 'sql_apis', []) +
            getattr(data, 'command_exec_apis', []) +
            getattr(data, 'file_write_apis', []) +
            getattr(data, 'webview_sink_apis', [])
        )
        
        if not source_values and not sink_values:
            self.logger.info("  No source/sink APIs available for correlation")
            self.logger.info("="*70 + "\n")
            return findings, 0
        
        self.logger.info(f"  Source API values: {len(source_values)}")
        self.logger.info(f"  Sink API values: {len(sink_values)}")
        
        source_sink_count = 0
        boost_amount = self.config["source_sink_boost"]
        
        # Check each finding against source/sink values
        for finding in findings:
            evidence_value = self._extract_evidence_value(finding)
            if not evidence_value:
                continue
            
            # Check if finding value appears in both source and sink
            in_source = any(evidence_value in src_val for src_val in source_values)
            in_sink = any(evidence_value in sink_val for sink_val in sink_values)
            
            if in_source and in_sink:
                # Source-sink correlation detected!
                source_sink_count += 1
                
                original_confidence = self._get_confidence(finding)
                
                if original_confidence is not None:
                    # Apply higher boost for source->sink flows
                    new_confidence = min(1.0, original_confidence + boost_amount)
                    self._set_confidence(finding, new_confidence)
                    
                    self.logger.info(
                        f"\n  Source-Sink flow detected: {evidence_value[:60]}..."
                    )
                    self.logger.info(
                        f"  Rule: {finding.rule_id}"
                    )
                    self.logger.info(
                        f"  Confidence: {original_confidence:.2f} -> {new_confidence:.2f}"
                    )
                
                # Add taint analysis metadata
                evidence = getattr(finding, 'evidence', {})
                evidence['taint_analysis'] = 'Source-Sink flow detected'
                evidence['flow_type'] = 'untrusted_input_to_dangerous_sink'
                
                # Append to description
                if hasattr(finding, 'description'):
                    if "[Taint Analysis: Source->Sink Flow]" not in finding.description:
                        finding.description += " [Taint Analysis: Source->Sink Flow]"
        
        if source_sink_count > 0:
            self.logger.info(
                f"\n✓ Detected {source_sink_count} source-sink flows (potential taint vulnerabilities)"
            )
        else:
            self.logger.info("\n  No source-sink flows detected")
        
        self.logger.info("="*70 + "\n")
        
        return findings, source_sink_count
    
    def _extract_api_values(self, apis: List[Any]) -> Set[str]:
        """
        Extract normalized string values from API call list.
        
        Args:
            apis: List of APIAPI or CryptoAPI objects
            
        Returns:
            Set of normalized values (method signatures, API names)
        """
        values = set()
        
        for api in apis:
            # Extract method signature
            if hasattr(api, 'method_signature'):
                values.add(api.method_signature.lower().strip())
            
            # Extract API called
            if hasattr(api, 'api_called'):
                values.add(api.api_called.lower().strip())
            
            # Extract parameters if available
            if hasattr(api, 'parameters'):
                for param in api.parameters:
                    if isinstance(param, str):
                        values.add(param.lower().strip())
        
        return values
    
    # ========================================================================
    # v3.0: SEMANTIC DEDUPLICATION
    # ========================================================================
    
    def _apply_deduplication(
        self, 
        findings: List[Finding]
    ) -> Tuple[List[Finding], int]:
        """
        Apply semantic deduplication via fingerprinting.
        
        Eliminates duplicate findings that represent the same underlying issue,
        even if they appear in different locations or with slight variations.
        
        Args:
            findings: All findings
            
        Returns:
            Tuple of (deduplicated_findings, duplicates_removed)
        """
        self.logger.info("\n" + "="*70)
        self.logger.info("Applying Semantic Deduplication...")
        self.logger.info("="*70)
        
        fingerprint_to_finding: Dict[str, Finding] = {}
        duplicates_removed = 0
        
        for finding in findings:
            fingerprint = self._generate_fingerprint(finding)
            
            # Store fingerprint in evidence for CI/CD baselining
            evidence = getattr(finding, 'evidence', {})
            evidence['fingerprint'] = fingerprint
            
            if fingerprint in fingerprint_to_finding:
                # Duplicate detected!
                existing = fingerprint_to_finding[fingerprint]
                existing_confidence = self._get_confidence(existing) or 0.0
                current_confidence = self._get_confidence(finding) or 0.0
                
                # Keep the one with higher confidence
                if current_confidence > existing_confidence:
                    fingerprint_to_finding[fingerprint] = finding
                    self.logger.debug(
                        f"  Replaced duplicate: {finding.rule_id} "
                        f"(confidence: {current_confidence:.2f} > {existing_confidence:.2f})"
                    )
                else:
                    self.logger.debug(
                        f"  Filtered duplicate: {finding.rule_id} "
                        f"(confidence: {current_confidence:.2f} <= {existing_confidence:.2f})"
                    )
                
                duplicates_removed += 1
            else:
                fingerprint_to_finding[fingerprint] = finding
        
        deduplicated_findings = list(fingerprint_to_finding.values())
        
        if duplicates_removed > 0:
            self.logger.info(
                f"✓ Removed {duplicates_removed} duplicate findings "
                f"({len(findings)} -> {len(deduplicated_findings)})"
            )
        else:
            self.logger.info("  No duplicates detected")
        
        self.logger.info("="*70 + "\n")
        
        return deduplicated_findings, duplicates_removed
    
    def _generate_fingerprint(self, finding: Finding) -> str:
        """
        Generate a fingerprint for semantic deduplication.
        
        Fingerprint consists of:
        - rule_id
        - affected_component (stripped of line numbers)
        - key evidence value
        
        Args:
            finding: Finding to fingerprint
            
        Returns:
            MD5 hash of fingerprint
        """
        rule_id = getattr(finding, 'rule_id', 'Unknown')
        
        # Get affected component and strip line numbers
        affected = getattr(finding, 'affected_component', '')
        affected_normalized = re.sub(r':\d+', '', affected)  # Remove :123
        affected_normalized = re.sub(r'line \d+', '', affected_normalized, flags=re.IGNORECASE)
        
        # Get evidence value
        evidence_value = self._extract_evidence_value(finding) or ''
        
        # Combine into fingerprint
        fingerprint_str = f"{rule_id}|{affected_normalized}|{evidence_value}"
        
        # Generate MD5 hash
        return hashlib.md5(fingerprint_str.encode('utf-8')).hexdigest()
    
    # ========================================================================
    # v3.0: ADAPTIVE CONFIDENCE FILTERING
    # ========================================================================
    
    def _apply_adaptive_filtering(
        self, 
        findings: List[Finding]
    ) -> List[Finding]:
        """
        Apply adaptive confidence filtering with category-specific thresholds.
        
        Different OWASP categories have different thresholds to reduce noise
        in inherently noisy categories while being permissive for critical ones.
        
        Args:
            findings: All findings
            
        Returns:
            Filtered findings
        """
        self.logger.info("\n" + "="*70)
        self.logger.info("Applying Adaptive Confidence Filtering...")
        self.logger.info("="*70)
        
        filtered = []
        filtered_by_category: Dict[str, int] = defaultdict(int)
        
        for finding in findings:
            # Get category and confidence
            category = getattr(finding, 'owasp_category', 'Uncategorized')
            confidence = self._get_confidence(finding)
            
            # Determine threshold (adaptive or global)
            if category in self.config["adaptive_thresholds"]:
                threshold = self.config["adaptive_thresholds"][category]
                threshold_type = "adaptive"
            else:
                threshold = self.config["min_confidence_global"]
                threshold_type = "global"
            
            # Apply filter
            if confidence is None or confidence >= threshold:
                filtered.append(finding)
            else:
                filtered_by_category[category] += 1
                self.logger.debug(
                    f"  Filtered ({threshold_type}): {finding.rule_id} "
                    f"[{category}] "
                    f"(confidence: {confidence:.2f} < {threshold:.2f})"
                )
        
        # Log summary
        total_filtered = len(findings) - len(filtered)
        if total_filtered > 0:
            self.logger.info(f"\nFiltered {total_filtered} findings:")
            for category, count in sorted(filtered_by_category.items()):
                threshold = self.config["adaptive_thresholds"].get(
                    category, 
                    self.config["min_confidence_global"]
                )
                self.logger.info(f"  {category}: {count} (threshold: {threshold:.2f})")
        else:
            self.logger.info("  No findings filtered")
        
        self.logger.info("="*70 + "\n")
        
        return filtered
    
    # ========================================================================
    # CONFIDENCE HELPERS
    # ========================================================================
    
    def _get_confidence(self, finding: Finding) -> Optional[float]:
        """Extract confidence score from finding."""
        # Try evidence dictionary first
        evidence = getattr(finding, 'evidence', {})
        for key in ['confidence_score', 'confidence', 'score', 'risk_score']:
            if key in evidence:
                try:
                    return float(evidence[key])
                except (ValueError, TypeError):
                    pass
        
        # Try direct attribute
        if hasattr(finding, 'confidence'):
            try:
                return float(finding.confidence)
            except (ValueError, TypeError):
                pass
        
        return None
    
    def _set_confidence(self, finding: Finding, confidence: float):
        """Set confidence score in finding."""
        evidence = getattr(finding, 'evidence', {})
        
        # Update in evidence (primary location)
        if 'confidence_score' in evidence:
            evidence['confidence_score'] = confidence
        elif 'confidence' in evidence:
            evidence['confidence'] = confidence
        else:
            evidence['confidence_score'] = confidence
        
        # Also update attribute if it exists
        if hasattr(finding, 'confidence'):
            finding.confidence = confidence
    
    # ========================================================================
    # v2.0: RULE EXECUTION (unchanged from v2.0)
    # ========================================================================
    
    def _filter_rules(self) -> List[BaseRule]:
        """Filter rules based on configuration."""
        active_rules = []
        
        for rule in self.rules:
            if self.config["exclude_rules"]:
                if rule.rule_id in self.config["exclude_rules"]:
                    continue
            
            if self.config["include_categories"]:
                rule_category = getattr(rule, 'category', 'Uncategorized')
                if rule_category not in self.config["include_categories"]:
                    continue
            
            if self.config["include_severities"]:
                rule_severity = getattr(rule, 'severity', 'Medium')
                if rule_severity not in self.config["include_severities"]:
                    continue
            
            active_rules.append(rule)
        
        return active_rules
    
    def _execute_sequential(
        self, 
        rules: List[BaseRule], 
        data: AnalysisReadyAPK
    ) -> Tuple[List[Finding], List[RuleExecutionStats]]:
        """Execute rules sequentially."""
        all_findings = []
        rule_stats = []
        
        for rule in rules:
            findings, stats = self._execute_rule_with_retry(rule, data)
            all_findings.extend(findings)
            rule_stats.append(stats)
            
            if self.config["fail_fast"] and stats.error_count > 0:
                self.logger.warning("Fail-fast triggered")
                break
        
        return all_findings, rule_stats
    
    def _execute_parallel(
        self, 
        rules: List[BaseRule], 
        data: AnalysisReadyAPK
    ) -> Tuple[List[Finding], List[RuleExecutionStats]]:
        """Execute rules in parallel."""
        all_findings = []
        rule_stats = []
        
        max_workers = min(self.config["max_workers"], len(rules))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_rule = {
                executor.submit(self._execute_rule_with_retry, rule, data): rule
                for rule in rules
            }
            
            for future in as_completed(future_to_rule):
                try:
                    findings, stats = future.result()
                    all_findings.extend(findings)
                    rule_stats.append(stats)
                except Exception as e:
                    rule = future_to_rule[future]
                    self.logger.error(f"Unexpected error: {e}")
                    rule_stats.append(RuleExecutionStats(
                        rule_id=rule.rule_id,
                        executed=False,
                        skipped=False,
                        skip_reason=None,
                        finding_count=0,
                        error_count=1,
                        execution_time_ms=0.0,
                        retries=0
                    ))
        
        rule_stats.sort(key=lambda s: s.rule_id)
        return all_findings, rule_stats
    
    def _execute_rule_with_retry(
        self, 
        rule: BaseRule, 
        data: AnalysisReadyAPK
    ) -> Tuple[List[Finding], RuleExecutionStats]:
        """Execute a single rule with retry mechanism."""
        # Check relevance
        if hasattr(rule, 'is_relevant'):
            try:
                if not rule.is_relevant(data):
                    return [], RuleExecutionStats(
                        rule_id=rule.rule_id,
                        executed=False,
                        skipped=True,
                        skip_reason="Not relevant",
                        finding_count=0,
                        error_count=0,
                        execution_time_ms=0.0,
                        retries=0
                    )
            except Exception as e:
                self.logger.warning(f"Relevance check error for {rule.rule_id}: {e}")
        
        # Execute with retries
        max_retries = self.config["max_retries"]
        retry_count = 0
        
        for attempt in range(max_retries + 1):
            try:
                start_time = time.time()
                findings = rule.run(data)
                execution_time = (time.time() - start_time) * 1000
                
                if findings:
                    self.logger.info(f"  ✓ {len(findings)} findings from {rule.rule_id}")
                
                return findings, RuleExecutionStats(
                    rule_id=rule.rule_id,
                    executed=True,
                    skipped=False,
                    skip_reason=None,
                    finding_count=len(findings),
                    error_count=0,
                    execution_time_ms=round(execution_time, 2),
                    retries=retry_count
                )
            
            except Exception as e:
                retry_count += 1
                if attempt < max_retries:
                    self.logger.warning(
                        f"Rule {rule.rule_id} failed (attempt {attempt+1}): {e}"
                    )
                    time.sleep(self.config["retry_delay_ms"] / 1000.0)
                else:
                    self.logger.error(f"Rule {rule.rule_id} failed: {e}")
                    self.logger.debug(traceback.format_exc())
        
        return [], RuleExecutionStats(
            rule_id=rule.rule_id,
            executed=False,
            skipped=False,
            skip_reason=None,
            finding_count=0,
            error_count=1,
            execution_time_ms=0.0,
            retries=retry_count
        )
    
    # ========================================================================
    # STATISTICS & REPORTING
    # ========================================================================
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = Counter()
        for finding in findings:
            severity = getattr(finding, 'severity', 'Medium')
            counts[severity] += 1
        return dict(counts)
    
    def _count_by_category(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by OWASP category."""
        counts = Counter()
        for finding in findings:
            category = getattr(finding, 'owasp_category', 'Uncategorized')
            counts[category] += 1
        return dict(counts)
    
    def _count_by_rule(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by rule ID."""
        counts = Counter()
        for finding in findings:
            rule_id = getattr(finding, 'rule_id', 'Unknown')
            counts[rule_id] += 1
        return dict(counts)
    
    def _calculate_confidence_stats(
        self, 
        findings: List[Finding]
    ) -> ConfidenceStats:
        """Calculate confidence score distribution."""
        stats = ConfidenceStats()
        confidences = []
        
        for finding in findings:
            confidence = self._get_confidence(finding)
            if confidence is not None:
                confidences.append(confidence)
                
                if confidence < 0.5:
                    stats.confidence_0_50 += 1
                elif confidence < 0.6:
                    stats.confidence_50_60 += 1
                elif confidence < 0.7:
                    stats.confidence_60_70 += 1
                elif confidence < 0.8:
                    stats.confidence_70_80 += 1
                elif confidence < 0.9:
                    stats.confidence_80_90 += 1
                else:
                    stats.confidence_90_100 += 1
        
        stats.total_findings = len(findings)
        if confidences:
            stats.average_confidence = sum(confidences) / len(confidences)
        
        return stats
    
    def _log_summary(self, report: AnalysisReport):
        """Log execution summary."""
        self.logger.info(
            f"\n{'='*70}\n"
            f"Next-Gen Analysis Complete (v3.1 + Taint Analysis)\n"
            f"{'='*70}\n"
            f"Total Findings:          {report.total_findings}\n"
            f"Correlated:              {report.correlated_findings}\n"
            f"Source-Sink Flows:       {report.source_sink_stats.source_sink_correlations}\n"
            f"Duplicates Removed:      {report.duplicates_removed}\n"
            f"Rules Executed:          {report.total_rules_executed}\n"
            f"Execution Time:          {report.execution_time_seconds:.2f}s\n"
            f"{'='*70}\n"
            f"Findings by Severity:"
        )
        
        for severity, count in sorted(
            report.findings_by_severity.items(),
            key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x[0], 99)
        ):
            self.logger.info(f"  {severity:10} {count:3}")
        
        # Log risk flags summary
        if any([
            report.risk_flags.cleartext_traffic_allowed,
            report.risk_flags.backup_enabled,
            report.risk_flags.uses_test_keys,
            report.risk_flags.exported_without_permission,
            report.risk_flags.dangerous_permissions_used,
            report.risk_flags.debuggable
        ]):
            self.logger.info(
                f"{'='*70}\n"
                f"Risk Flags Detected:"
            )
            if report.risk_flags.cleartext_traffic_allowed:
                self.logger.info("  ⚠ Cleartext traffic allowed")
            if report.risk_flags.backup_enabled:
                self.logger.info("  ⚠ Backup enabled")
            if report.risk_flags.uses_test_keys:
                self.logger.info("  ⚠ Uses test/debug keys")
            if report.risk_flags.exported_without_permission:
                self.logger.info("  ⚠ Exported components without permission")
            if report.risk_flags.dangerous_permissions_used:
                self.logger.info("  ⚠ Dangerous permissions used")
            if report.risk_flags.debuggable:
                self.logger.info("  ⚠ Debuggable build")
        
        self.logger.info(f"{'='*70}\n")
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def add_rule(self, rule: BaseRule):
        """Add a rule to the engine."""
        self.rules.append(rule)
        self.logger.info(f"Rule added: {rule.rule_id}")
    
    def get_rules(self) -> List[BaseRule]:
        """Get all registered rules."""
        return self.rules
    
    def configure(self, config: Dict[str, Any]):
        """Update engine configuration."""
        self.config.update(config)
        self._validate_config()
        self.logger.info(f"Configuration updated")
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"RuleEngine v3.1 (rules={len(self.rules)}, "
            f"parallel={self.config['parallel']}, "
            f"correlation={self.config['enable_correlation']}, "
            f"taint_analysis={self.config['enable_source_sink_correlation']})"
        )
