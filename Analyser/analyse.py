"""
APK Security Analysis Orchestrator - Enhanced v5.1

Complete pipeline with full utilization of:
- RuleEngine v3.1: Source-sink taint analysis, cross-rule correlation
- ScopeFilter v2.3: Advanced API bucketing and confidence scoring
- All 32 security rules with adaptive thresholds

Pipeline: Load APK → Filter Scope → Execute Rules → Correlate → Generate Reports

Author: APK Security Analysis
License: MIT
Version: 5.1 - Full Engine v3.1 Integration
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Core pipeline imports
from Analyser.Loader.apk_loader import APKLoader, APKLoaderError
from Analyser.Loader.scope_filter import ScopeFilter, AnalysisReadyAPK
from Analyser.Engine.engine import RuleEngine
from Analyser.Engine.base_rule import BaseRule
from Analyser.Report.manager import FindingManager
from Analyser.Report.report import ReportGenerator

# ============================================================================
# Import ALL 32 rules from rules.py
# ============================================================================

# --- Binary Protection & Environment Detection (4 rules) ---
from Analyser.Engine.rules import (
    DebuggableEnabledRule,          # Rule 1:  android:debuggable=true
    AllowBackupEnabledRule,         # Rule 2:  android:allowBackup=true
    WeakRootDetectionRule,          # Rule 16: Bypassable root/emulator detection
    MissingObfuscationRule,         # Rule 29: Missing ProGuard/R8 obfuscation
)

# --- Network Communication (5 rules) ---
from Analyser.Engine.rules import (
    CleartextTrafficAllowedRule,        # Rule 3:  HTTP traffic allowed
    InsecureNetworkSecurityConfigRule,   # Rule 12: Misconfigured network_security_config
    CertificateValidationBypassRule,    # Rule 21: TrustAllCerts / hostname verifier bypass
    CustomURLSchemeRule,                # Rule 22: Deep link / custom scheme handling
    MissingCertificatePinningRule,      # Rule 25: No certificate pinning (OkHttp/native)
)

# --- Component Exposure (4 rules) ---
from Analyser.Engine.rules import (
    ExportedComponentWithoutPermissionRule,  # Rule 4:  Exported without permission
    InsecureBroadcastRule,                  # Rule 27: sendBroadcast without permission
    UnprotectedContentProviderRule,         # Rule 30: Content provider without read/write perms
    TaskAffinityHijackingRule,              # Rule 31: Task hijacking via affinity
)

# --- Privacy Controls (1 rule) ---
from Analyser.Engine.rules import (
    DangerousPermissionDeclaredRule,     # Rule 5:  Dangerous runtime permissions
)

# --- Credential / Secret Storage (2 rules) ---
from Analyser.Engine.rules import (
    HardcodedSecretRule,            # Rule 6:  API keys, passwords, tokens in code
    HardcodedCryptoKeyRule,         # Rule 23: SecretKeySpec with hardcoded key material
)

# --- Cryptographic Issues (3 rules) ---
from Analyser.Engine.rules import (
    WeakCryptoAlgorithmRule,        # Rule 7:  DES, ECB, MD5, SHA1, RC4, etc.
    StaticIVRule,                   # Rule 13: Hardcoded IvParameterSpec
    InsecureRandomRule,             # Rule 24: java.util.Random instead of SecureRandom
)

# --- WebView / Input Validation (4 rules) ---
from Analyser.Engine.rules import (
    WebViewJavaScriptEnabledRule,   # Rule 8:  setJavaScriptEnabled(true)
    SQLInjectionRiskRule,           # Rule 9:  SQL concat + rawQuery/execSQL
    InsecureWebViewConfigRule,      # Rule 17: addJavascriptInterface, file access, etc.
    PathTraversalRiskRule,          # Rule 18: ../ path traversal patterns
)

# --- Data Storage (8 rules) ---
from Analyser.Engine.rules import (
    InsecureLoggingRule,            # Rule 10: Log.d/v/i with sensitive keywords
    InsecureSharedPreferencesRule,  # Rule 14: Plaintext SharedPrefs (users.xml, score.xml)
    InsecureFileStorageRule,        # Rule 15: External storage, temp files
    InsecureSQLiteDatabaseRule,     # Rule 19: Unencrypted SQLite databases
    KeyboardCacheRule,              # Rule 20: Keyboard autocomplete on password fields
    ClipboardDataLeakageRule,       # Rule 26: ClipboardManager data exposure
    TapjackingRule,                 # Rule 28: Missing filterTouchesWhenObscured
    MissingFlagSecureRule,          # Rule 32: Screenshot capture of sensitive screens
)

# Also import the ALL_RULES registry for validation
from Analyser.Engine.rules import ALL_RULES

# --- Dynamic Code Loading (1 rule) ---
from Analyser.Engine.rules import (
    DynamicCodeLoadingRule,         # Rule 11: DexClassLoader, PathClassLoader
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ============================================================================
# Rule Registry with Categories
# ============================================================================

RULE_CATEGORIES = {
    "Binary Protection & Environment Detection": [
        DebuggableEnabledRule,
        AllowBackupEnabledRule,
        WeakRootDetectionRule,
        MissingObfuscationRule,
    ],
    "Network Communication": [
        CleartextTrafficAllowedRule,
        InsecureNetworkSecurityConfigRule,
        CertificateValidationBypassRule,
        CustomURLSchemeRule,
        MissingCertificatePinningRule,
    ],
    "Component Exposure": [
        ExportedComponentWithoutPermissionRule,
        InsecureBroadcastRule,
        UnprotectedContentProviderRule,
        TaskAffinityHijackingRule,
    ],
    "Privacy Controls": [
        DangerousPermissionDeclaredRule,
    ],
    "Credential & Secret Storage": [
        HardcodedSecretRule,
        HardcodedCryptoKeyRule,
    ],
    "Cryptographic Issues": [
        WeakCryptoAlgorithmRule,
        StaticIVRule,
        InsecureRandomRule,
    ],
    "Input Validation (WebView, SQL, Path)": [
        WebViewJavaScriptEnabledRule,
        SQLInjectionRiskRule,
        InsecureWebViewConfigRule,
        PathTraversalRiskRule,
    ],
    "Data Storage": [
        InsecureLoggingRule,
        InsecureSharedPreferencesRule,
        InsecureFileStorageRule,
        InsecureSQLiteDatabaseRule,
        KeyboardCacheRule,
        ClipboardDataLeakageRule,
        TapjackingRule,
        MissingFlagSecureRule,
    ],
    "Dynamic Code Loading": [
        DynamicCodeLoadingRule,
    ],
}


def _build_all_rules(
    categories: Optional[List[str]] = None,
    exclude_rules: Optional[List[str]] = None,
) -> List[BaseRule]:
    """
    Build the complete list of rule instances.
    
    Args:
        categories: If provided, only include rules from these categories.
                    Use None for all categories.
        exclude_rules: If provided, exclude rules whose rule_id matches.
    
    Returns:
        List of instantiated rule objects.
    """
    rules = []
    seen_ids = set()

    for category_name, rule_classes in RULE_CATEGORIES.items():
        # Category filter
        if categories and category_name not in categories:
            continue

        for rule_cls in rule_classes:
            instance = rule_cls()
            rid = instance.rule_id

            # Dedup guard
            if rid in seen_ids:
                continue
            seen_ids.add(rid)

            # Exclusion filter
            if exclude_rules and rid in exclude_rules:
                continue

            rules.append(instance)

    return rules


# ============================================================================
# Main Analyzer with Full Engine v3.1 Integration
# ============================================================================

class APKSecurityAnalyzer:
    """
    Main orchestrator for APK security analysis with advanced features.

    Coordinates all components of the analysis pipeline:
    1. APK loading (APKLoader)
    2. Scope filtering (ScopeFilter v2.3)
    3. Rule execution (RuleEngine v3.1 with taint analysis)
    4. Finding management (FindingManager with deduplication)
    5. Report generation (ReportGenerator with rich metrics)
    
    New in v5.1:
    - Full source-sink taint analysis integration
    - Cross-rule correlation with confidence boosting
    - Adaptive OWASP category thresholds
    - Risk flags detection and reporting
    - Enhanced logging of advanced metrics
    """

    def __init__(self):
        """Initialize the analyzer."""
        self.logger = logger

    def analyze(
        self,
        apk_path: str,
        output_dir: str = ".",
        report_format: str = "both",
        deduplicate: bool = True,
        verbose: bool = False,
        categories: Optional[List[str]] = None,
        exclude_rules: Optional[List[str]] = None,
        parallel: bool = False,
        workers: int = 4,
        enable_taint_analysis: bool = True,
        enable_correlation: bool = True,
    ) -> Optional[Path]:
        """
        Perform complete APK security analysis with advanced features.

        Args:
            apk_path:               Path to the APK file to analyze
            output_dir:             Directory for output files (default: current directory)
            report_format:          "json", "html", or "both" (default: both)
            deduplicate:            Whether to deduplicate findings (default: True)
            verbose:                Enable verbose logging (default: False)
            categories:             List of rule categories to run (default: all)
            exclude_rules:          List of rule_ids to skip (default: none)
            parallel:               Enable parallel rule execution (default: False)
            workers:                Number of worker threads for parallel execution (default: 4)
            enable_taint_analysis:  Enable source-sink taint analysis (default: True)
            enable_correlation:     Enable cross-rule correlation (default: True)

        Returns:
            Path to the primary output file, or None if analysis failed
        """

        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        self.logger.info("=" * 70)
        self.logger.info("APK Security Analysis - Starting (Enhanced v5.1)")
        self.logger.info("=" * 70)

        # ------------------------------------------------------------------
        # Validate inputs
        # ------------------------------------------------------------------
        apk_file = Path(apk_path)
        if not apk_file.exists():
            self.logger.error(f"APK file not found: {apk_path}")
            return None
        if not apk_file.suffix.lower() == ".apk":
            self.logger.warning(
                f"File does not have .apk extension: {apk_file.name}"
            )

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        try:
            # ==============================================================
            # Step 1: Load APK
            # ==============================================================
            self.logger.info(f"\n[1/5] Loading APK: {apk_file.name}")
            self.logger.debug("Using APKLoader to parse APK file...")

            loader = APKLoader()
            apk_model = loader.load(str(apk_file))

            self.logger.info(
                f"  ✓ APK loaded: {apk_model.manifest.package_name} "
                f"v{apk_model.manifest.version_name}"
            )

            # ==============================================================
            # Step 2: Apply Scope Filter (v2.3 with advanced features)
            # ==============================================================
            self.logger.info("\n[2/5] Applying Scope Filter (v2.3)")
            self.logger.debug(
                "Filtering to app-specific code and analyzing security patterns..."
            )

            scope_filter = ScopeFilter(apk_model)
            analysis_ready: AnalysisReadyAPK = scope_filter.prepare()

            self._log_scope_summary(analysis_ready)

            # ==============================================================
            # Step 3: Create and Run Rule Engine (v3.1 with taint analysis)
            # ==============================================================
            self.logger.info("\n[3/5] Executing Security Rules (Engine v3.1)")

            rules = _build_all_rules(
                categories=categories,
                exclude_rules=exclude_rules,
            )

            self._log_rule_manifest(rules)

            # Build advanced engine configuration
            engine_config = {
                # v3.1: Source-Sink Taint Analysis
                "enable_source_sink_correlation": enable_taint_analysis,
                "source_sink_boost": 0.25,  # Boost confidence for source-sink flows
                
                # v3.0: Cross-Rule Correlation
                "enable_correlation": enable_correlation,
                "correlation_boost": 0.15,  # Boost confidence for correlated findings
                
                # Adaptive thresholds by OWASP category
                "adaptive_thresholds": {
                    "M1: Improper Credential Usage": 0.35,       # Lower threshold for credentials
                    "M10: Insufficient Cryptography": 0.30,       # Lower for crypto issues
                    "M5: Insecure Communication": 0.40,           # Medium for network
                    "default": 0.40,                              # Default threshold
                },
                
                # Performance settings
                "parallel": parallel,
                "max_workers": workers if parallel else 1,
                "max_retries": 2,
                "retry_delay_ms": 100,
                
                # Quality settings
                "min_confidence": 0.30,  # Lower than default to catch more issues
                "max_findings_per_rule": 50,  # Allow more findings per rule
            }

            self.logger.info(
                f"  Engine Configuration:\n"
                f"    • Taint Analysis:    {enable_taint_analysis}\n"
                f"    • Correlation:       {enable_correlation}\n"
                f"    • Parallel:          {parallel} ({workers} workers)\n"
                f"    • Min Confidence:    {engine_config['min_confidence']}\n"
                f"    • Adaptive Thresh:   Enabled"
            )

            engine = RuleEngine(rules, config=engine_config)
            analysis_report = engine.run_all(analysis_ready)

            if report_format == "memory":
                return analysis_report

            # Extract findings from report
            findings = analysis_report.findings

            self.logger.info(
                f"  ✓ Rule execution complete: {len(findings)} finding(s)"
            )
            
            # Log advanced metrics from engine v3.1
            self._log_engine_metrics(analysis_report)

            # ==============================================================
            # Step 4: Manage Findings
            # ==============================================================
            self.logger.info("\n[4/5] Processing Findings")

            manager = FindingManager()
            manager.add_findings(findings)

            if deduplicate:
                before = len(manager.findings)
                self.logger.debug("Deduplicating findings...")
                manager.deduplicate()
                after = len(manager.findings)
                if before != after:
                    self.logger.info(
                        f"  ✓ Deduplicated: {before} → {after} findings "
                        f"({before - after} duplicates removed)"
                    )

            summary = manager.get_summary()
            self._log_severity_summary(summary, manager)

            # ==============================================================
            # Step 5: Generate Reports
            # ==============================================================
            self.logger.info("\n[5/5] Generating Reports")

            generator = ReportGenerator(manager, analysis_ready)
            primary_output = None
            ts = self._timestamp()

            if report_format in ("json", "both"):
                json_path = output_path / f"report_{ts}.json"
                generator.generate_json_report(str(json_path))
                self.logger.info(f"  ✓ JSON report: {json_path}")
                if report_format == "json":
                    primary_output = json_path

            if report_format in ("html", "both"):
                html_path = output_path / f"report_{ts}.html"
                generator.generate_html_report(str(html_path))
                self.logger.info(f"  ✓ HTML report: {html_path}")
                if primary_output is None:
                    primary_output = html_path

            # ==============================================================
            # Final Summary
            # ==============================================================
            self._log_final_summary(
                analysis_ready, 
                summary, 
                primary_output, 
                rules, 
                analysis_report
            )

            return primary_output

        except APKLoaderError as e:
            self.logger.error(f"APK loading failed: {str(e)}")
            return None

        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            if verbose:
                import traceback
                self.logger.error(traceback.format_exc())
            return None

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log_scope_summary(self, data: AnalysisReadyAPK) -> None:
        """Log scope filter results with enhanced metrics."""
        self.logger.info(
            f"  ✓ Filtered to {data.app_classes_count} app classes, "
            f"{data.app_methods_count} app methods"
        )
        
        # API bucket counts (v2.3 feature)
        self.logger.info("  API Buckets:")
        self.logger.info(f"    • Crypto APIs:       {len(data.crypto_apis)}")
        self.logger.info(f"    • Network APIs:      {len(data.network_apis)}")
        self.logger.info(f"    • Storage APIs:      {len(data.storage_apis)}")
        self.logger.info(f"    • WebView APIs:      {len(data.webview_apis)}")
        self.logger.info(f"    • Dynamic Code APIs: {len(data.dynamic_code_apis)}")
        self.logger.info(f"    • Reflection APIs:   {len(data.reflection_apis)}")
        
        # Source APIs (for taint analysis)
        if hasattr(data, 'intent_apis'):
            self.logger.info("  Source APIs (Taint Analysis):")
            self.logger.info(f"    • Intent APIs:      {len(data.intent_apis)}")
            self.logger.info(f"    • User Input APIs:  {len(data.user_input_apis)}")
            self.logger.info(f"    • Web Input APIs:   {len(data.web_input_apis)}")
        
        # Sink APIs (for taint analysis)
        if hasattr(data, 'sql_apis'):
            self.logger.info("  Sink APIs (Taint Analysis):")
            self.logger.info(f"    • SQL APIs:         {len(data.sql_apis)}")
            self.logger.info(f"    • Command Exec:     {len(data.command_exec_apis)}")
            self.logger.info(f"    • File Write APIs:  {len(data.file_write_apis)}")
            self.logger.info(f"    • Crypto Weak APIs: {len(data.crypto_weak_apis)}")
            self.logger.info(f"    • WebView Sink:     {len(data.webview_sink_apis)}")
        
        # String analysis
        self.logger.info(f"  ✓ Suspicious strings: {len(data.strings)} (confidence-scored)")
        self.logger.info(
            f"  ✓ Exported components: {len(data.exported_components)}"
        )
        self.logger.info(
            f"  ✓ Dangerous permissions: {len(data.dangerous_permissions)}"
        )

    def _log_rule_manifest(self, rules: List[BaseRule]) -> None:
        """Log which rules are being executed, grouped by category."""
        self.logger.info(f"  Registered {len(rules)} security rules:")
        for cat_name, cat_rules in RULE_CATEGORIES.items():
            active_in_cat = [
                r for r in rules
                if type(r) in cat_rules
            ]
            if active_in_cat:
                self.logger.info(f"    [{cat_name}]")
                for r in active_in_cat:
                    self.logger.info(f"      • {r.rule_id}")

    def _log_engine_metrics(self, report) -> None:
        """Log advanced metrics from RuleEngine v3.1."""
        if report.correlated_findings > 0:
            self.logger.info(
                f"  ✓ Cross-rule correlation: {report.correlated_findings} finding(s) boosted"
            )
        
        if report.source_sink_stats.source_sink_correlations > 0:
            self.logger.info(
                f"  ✓ Source-sink flows detected: "
                f"{report.source_sink_stats.source_sink_correlations} taint path(s)"
            )
        
        if report.duplicates_removed > 0:
            self.logger.info(
                f"  ✓ Semantic deduplication: {report.duplicates_removed} duplicate(s) removed"
            )
        
        # Log risk flags if any are set
        risk_count = sum([
            report.risk_flags.cleartext_traffic_allowed,
            report.risk_flags.backup_enabled,
            report.risk_flags.uses_test_keys,
            report.risk_flags.exported_without_permission,
            report.risk_flags.dangerous_permissions_used,
            report.risk_flags.debuggable,
        ])
        
        if risk_count > 0:
            self.logger.info(
                f"  ⚠  Configuration risk flags: {risk_count} detected"
            )

    def _log_severity_summary(self, summary: dict, manager: FindingManager) -> None:
        """Log severity breakdown with warnings for critical/high."""
        self.logger.info(
            f"  ✓ Findings processed: "
            f"Critical={summary['Critical']}, "
            f"High={summary['High']}, "
            f"Medium={summary['Medium']}, "
            f"Low={summary['Low']}, "
            f"Total={summary['Total']}"
        )

        if manager.has_critical():
            self.logger.warning(
                "  ⚠  CRITICAL findings detected — immediate action required!"
            )
        if manager.has_high():
            self.logger.warning(
                "  ⚠  HIGH severity findings detected — review before release!"
            )

    def _log_final_summary(
        self,
        data: AnalysisReadyAPK,
        summary: dict,
        primary_output: Optional[Path],
        rules: List[BaseRule],
        analysis_report,
    ) -> None:
        """Print the final analysis summary with enhanced metrics."""
        self.logger.info("\n" + "=" * 70)
        self.logger.info("APK Security Analysis - Complete (v5.1 Enhanced)")
        self.logger.info("=" * 70)
        self.logger.info(f"  Package:     {data.package_name}")
        self.logger.info(f"  Version:     {data.version_name}")
        self.logger.info(
            f"  Target SDK:  {getattr(data, 'target_sdk', 'N/A')}"
        )
        self.logger.info(
            f"  Min SDK:     {getattr(data, 'min_sdk', 'N/A')}"
        )
        self.logger.info(f"  Rules run:   {len(rules)}")
        self.logger.info(
            f"  Findings:    {summary['Total']} "
            f"(Critical: {summary['Critical']}, "
            f"High: {summary['High']}, "
            f"Medium: {summary['Medium']}, "
            f"Low: {summary['Low']})"
        )
        
        # Enhanced metrics
        self.logger.info(f"  Engine:      v3.1 (Next-Gen + Taint Analysis)")
        self.logger.info(
            f"  Exec Time:   {analysis_report.execution_time_seconds:.2f}s"
        )
        self.logger.info(f"  Report:      {primary_output}")

        # OWASP coverage summary
        findings_by_owasp = {}
        for finding in analysis_report.findings:
            cat = finding.owasp_category
            findings_by_owasp[cat] = findings_by_owasp.get(cat, 0) + 1
        
        if findings_by_owasp:
            self.logger.info(
                f"  OWASP cats:  {len(findings_by_owasp)} categories impacted"
            )
        
        self.logger.info("=" * 70)

    @staticmethod
    def _timestamp() -> str:
        """Generate a timestamp string for filenames."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")


# ============================================================================
# CLI
# ============================================================================

def main():
    """Command-line interface for APK security analysis."""
    parser = argparse.ArgumentParser(
        description="APK Security Analysis Tool — OWASP Mobile Top 10 2024 (v5.1 Enhanced)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full analysis with all 32 rules, advanced features enabled
  python analyse.py app.apk

  # JSON report only
  python analyse.py app.apk --format json

  # Save to specific directory
  python analyse.py app.apk --output ./reports

  # Run only network-related rules
  python analyse.py app.apk --categories "Network Communication"

  # Run all rules except obfuscation check
  python analyse.py app.apk --exclude MISSING_OBFUSCATION

  # Enable parallel execution with 8 worker threads
  python analyse.py app.apk --parallel --workers 8

  # Disable advanced features (basic mode)
  python analyse.py app.apk --no-taint-analysis --no-correlation

  # List all available rules and exit
  python analyse.py --list-rules

  # Verbose debugging
  python analyse.py app.apk --verbose

Advanced Features (v5.1):
  • Source-Sink Taint Analysis: Detect untrusted input flows to sensitive sinks
  • Cross-Rule Correlation: Boost confidence when multiple rules flag same data
  • Adaptive Thresholds: Different confidence thresholds per OWASP category
  • Risk Flags Detection: Identify configuration-level security risks
  • Enhanced Metrics: Detailed statistics on correlation and taint flows

Available rule categories:
  • Binary Protection & Environment Detection  (4 rules)
  • Network Communication                      (5 rules)
  • Component Exposure                         (4 rules)
  • Privacy Controls                           (1 rule)
  • Credential & Secret Storage                (2 rules)
  • Cryptographic Issues                       (3 rules)
  • Input Validation (WebView, SQL, Path)      (4 rules)
  • Data Storage                               (8 rules)
  • Dynamic Code Loading                       (1 rule)
        """,
    )

    parser.add_argument(
        "apk_path",
        nargs="?",
        help="Path to the APK file to analyze",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Report format (default: both)",
    )

    parser.add_argument(
        "-o",
        "--output",
        default=".",
        help="Output directory for reports (default: current directory)",
    )

    parser.add_argument(
        "--no-deduplicate",
        action="store_true",
        help="Disable deduplication of findings",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--categories",
        nargs="+",
        metavar="CAT",
        help="Only run rules from specified categories (use quotes for multi-word names)",
    )

    parser.add_argument(
        "--exclude",
        nargs="+",
        metavar="RULE_ID",
        help="Exclude specific rules by their rule_id",
    )

    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Enable parallel rule execution (faster on multi-core systems)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of worker threads for parallel execution (default: 4)",
    )

    parser.add_argument(
        "--no-taint-analysis",
        action="store_true",
        help="Disable source-sink taint analysis (faster but less accurate)",
    )

    parser.add_argument(
        "--no-correlation",
        action="store_true",
        help="Disable cross-rule correlation (faster but less accurate)",
    )

    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List all available rules and exit",
    )

    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List all rule categories and exit",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # List modes (no APK needed)
    # ------------------------------------------------------------------
    if args.list_rules:
        _print_rule_table()
        sys.exit(0)

    if args.list_categories:
        _print_categories()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Analysis mode — APK path required
    # ------------------------------------------------------------------
    if not args.apk_path:
        parser.error("the following arguments are required: apk_path")

    analyzer = APKSecurityAnalyzer()
    result = analyzer.analyze(
        apk_path=args.apk_path,
        output_dir=args.output,
        report_format=args.format,
        deduplicate=not args.no_deduplicate,
        verbose=args.verbose,
        categories=args.categories,
        exclude_rules=args.exclude,
        parallel=args.parallel,
        workers=args.workers,
        enable_taint_analysis=not args.no_taint_analysis,
        enable_correlation=not args.no_correlation,
    )

    sys.exit(0 if result else 1)


# ============================================================================
# Listing helpers
# ============================================================================

def _print_rule_table():
    """Print a formatted table of all available rules."""
    print("\n" + "=" * 78)
    print("  AVAILABLE SECURITY RULES (32 total)")
    print("=" * 78)

    rule_num = 0
    for cat_name, rule_classes in RULE_CATEGORIES.items():
        print(f"\n  ┌─ {cat_name} ({len(rule_classes)} rules)")
        for rule_cls in rule_classes:
            rule_num += 1
            instance = rule_cls()
            rid = instance.rule_id
            doc = (rule_cls.__doc__ or "").strip().split("\n")[0]
            print(f"  │  {rule_num:2d}. {rid:<42s} {doc[:50]}")
        print("  └" + "─" * 60)

    print(f"\n  Total: {rule_num} rules across {len(RULE_CATEGORIES)} categories")
    print("=" * 78 + "\n")


def _print_categories():
    """Print available categories."""
    print("\n  Available Rule Categories:")
    print("  " + "-" * 50)
    for cat_name, rule_classes in RULE_CATEGORIES.items():
        print(f"  • {cat_name:<48s} ({len(rule_classes)} rules)")
    total = sum(len(v) for v in RULE_CATEGORIES.values())
    print(f"\n  Total: {total} rules across {len(RULE_CATEGORIES)} categories\n")


# ============================================================================
# Validation: Ensure ALL_RULES from rules.py matches our registry
# ============================================================================

def _validate_rule_coverage():
    """
    Validate that our RULE_CATEGORIES covers every rule in ALL_RULES.
    Called at import time to catch missing rules early.
    """
    registered_classes = set()
    for cat_rules in RULE_CATEGORIES.values():
        registered_classes.update(cat_rules)

    all_rules_set = set(ALL_RULES)
    missing = all_rules_set - registered_classes
    extra = registered_classes - all_rules_set

    if missing:
        logger.warning(
            f"Rules in ALL_RULES but not in analyse.py RULE_CATEGORIES: "
            f"{[cls.__name__ for cls in missing]}"
        )
    if extra:
        logger.warning(
            f"Rules in analyse.py RULE_CATEGORIES but not in ALL_RULES: "
            f"{[cls.__name__ for cls in extra]}"
        )


# Run validation at import time
_validate_rule_coverage()


if __name__ == "__main__":
    main()


def run_analysis(apk_path: str) -> dict:
    """
    FastAPI wrapper – returns structured analysis data.
    """

    analyzer = APKSecurityAnalyzer()

    analysis_report = analyzer.analyze(
        apk_path=apk_path,
        report_format="memory",
        parallel=True,
        workers=4,
        enable_taint_analysis=True,
        enable_correlation=True,
    )

    if not analysis_report:
        return {
            "app_name": apk_path.split("/")[-1],
            "permissions": [],
            "findings": [],
        }

    return {
        "app_name": apk_path.split("/")[-1],  # safer
        "execution_time": analysis_report.execution_time_seconds,
        "total_findings": len(analysis_report.findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "description": f.description,
                "confidence": f.confidence,
                "owasp_category": f.owasp_category,
            }
            for f in analysis_report.findings
        ],
    }
