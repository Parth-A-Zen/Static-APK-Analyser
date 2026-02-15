"""
APK Security Analysis Orchestrator

Main entry point for the APK security analysis pipeline.

Flow:
1. Load APK using APKLoader
2. Apply ScopeFilter to extract security-relevant data
3. Execute security rules via RuleEngine
4. Manage findings with FindingManager
5. Generate reports (JSON/HTML)

Author: Generated for APK Security Analysis
License: MIT
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Import all components
from Loader.apk_loader import APKLoader, APKLoaderError
from Loader.scope_filter import ScopeFilter, AnalysisReadyAPK
from Engine.engine import RuleEngine
from Report.manager import FindingManager
from Report.report import ReportGenerator

# Import all rules
from Engine.rules import (
    DebuggeableEnabledRule,
    AllowBackupEnabledRule,
    CleartextTrafficAllowedRule,
    ExportedComponentWithoutPermissionRule,
    DangerousPermissionDeclaredRule,
    HardcodedSecretRule,
    WeakCryptoAlgorithmRule,
    WebViewJavaScriptEnabledRule,
    DynamicCodeLoadingRule,
    SQLInjectionRiskRule,
    InsecureNetworkSecurityConfigRule,
    StaticIVRule,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APKSecurityAnalyzer:
    """
    Main orchestrator for APK security analysis.
    
    Coordinates all components of the analysis pipeline:
    - APK loading
    - Scope filtering
    - Rule execution
    - Finding management
    - Report generation
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
        verbose: bool = False
    ) -> Optional[Path]:
        """
        Perform complete APK security analysis.
        
        Args:
            apk_path: Path to the APK file to analyze
            output_dir: Directory for output files (default: current directory)
            report_format: "json", "html", or "both" (default: both)
            deduplicate: Whether to deduplicate findings (default: True)
            verbose: Enable verbose logging (default: False)
            
        Returns:
            Path to the primary output file, or None if analysis failed
        """
        
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        self.logger.info("="*70)
        self.logger.info("APK Security Analysis - Starting")
        self.logger.info("="*70)
        
        # Validate inputs
        apk_file = Path(apk_path)
        if not apk_file.exists():
            self.logger.error(f"APK file not found: {apk_path}")
            return None
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Step 1: Load APK
            self.logger.info(f"\n[1/5] Loading APK: {apk_file.name}")
            self.logger.debug("Using APKLoader to parse APK file...")
            
            loader = APKLoader()
            apk_model = loader.load(str(apk_file))
            
            self.logger.info(
                f"✓ APK loaded: {apk_model.manifest.package_name} "
                f"v{apk_model.manifest.version_name}"
            )
            
            # Step 2: Apply Scope Filter
            self.logger.info(f"\n[2/5] Applying Scope Filter")
            self.logger.debug("Filtering to app-specific code and analyzing security patterns...")
            
            scope_filter = ScopeFilter(apk_model)
            analysis_ready = scope_filter.prepare()
            
            self.logger.info(
                f"✓ Filtered to {analysis_ready.app_classes_count} app classes, "
                f"{analysis_ready.app_methods_count} app methods"
            )
            self.logger.debug(f"  - Crypto APIs: {len(analysis_ready.crypto_apis)}")
            self.logger.debug(f"  - Network APIs: {len(analysis_ready.network_apis)}")
            self.logger.debug(f"  - Storage APIs: {len(analysis_ready.storage_apis)}")
            self.logger.debug(f"  - Reflection APIs: {len(analysis_ready.reflection_apis)}")
            self.logger.debug(f"  - WebView APIs: {len(analysis_ready.webview_apis)}")
            self.logger.debug(f"  - Dynamic Code APIs: {len(analysis_ready.dynamic_code_apis)}")
            self.logger.debug(f"  - Suspicious strings: {len(analysis_ready.strings)}")
            self.logger.debug(f"  - Exported components: {len(analysis_ready.exported_components)}")
            self.logger.debug(f"  - Dangerous permissions: {len(analysis_ready.dangerous_permissions)}")
            
            # Step 3: Create and run Rule Engine
            self.logger.info(f"\n[3/5] Executing Security Rules")
            
            rules = self._create_rules()
            self.logger.debug(f"Registered {len(rules)} security rules")
            
            engine = RuleEngine(rules)
            findings = engine.run_all(analysis_ready)
            
            self.logger.info(f"✓ Rule execution complete: {len(findings)} finding(s)")
            
            # Step 4: Manage Findings
            self.logger.info(f"\n[4/5] Processing Findings")
            
            manager = FindingManager()
            manager.add_findings(findings)
            
            if deduplicate:
                self.logger.debug("Deduplicating findings...")
                manager.deduplicate()
            
            summary = manager.get_summary()
            self.logger.info(
                f"✓ Findings processed: "
                f"Critical={summary['Critical']}, "
                f"High={summary['High']}, "
                f"Medium={summary['Medium']}, "
                f"Low={summary['Low']}"
            )
            
            if manager.has_critical():
                self.logger.warning("⚠  CRITICAL findings detected!")
            if manager.has_high():
                self.logger.warning("⚠  HIGH severity findings detected!")
            
            # Step 5: Generate Reports
            self.logger.info(f"\n[5/5] Generating Reports")
            
            generator = ReportGenerator(manager, analysis_ready)
            primary_output = None
            
            if report_format in ["json", "both"]:
                json_path = output_path / f"report_{self._timestamp()}.json"
                generator.generate_json_report(str(json_path))
                self.logger.info(f"✓ JSON report: {json_path.name}")
                if report_format == "json":
                    primary_output = json_path
            
            if report_format in ["html", "both"]:
                html_path = output_path / f"report_{self._timestamp()}.html"
                generator.generate_html_report(str(html_path))
                self.logger.info(f"✓ HTML report: {html_path.name}")
                if report_format == "html" or primary_output is None:
                    primary_output = html_path
            
            # Summary
            self.logger.info("\n" + "="*70)
            self.logger.info("APK Security Analysis - Complete")
            self.logger.info("="*70)
            self.logger.info(f"Package:     {analysis_ready.package_name}")
            self.logger.info(f"Version:     {analysis_ready.version_name}")
            self.logger.info(f"Findings:    {summary['Total']} "
                           f"(Critical: {summary['Critical']}, "
                           f"High: {summary['High']}, "
                           f"Medium: {summary['Medium']}, "
                           f"Low: {summary['Low']})")
            self.logger.info(f"Report:      {primary_output}")
            self.logger.info("="*70)
            
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
    
    @staticmethod
    def _create_rules() -> list:
        """Create and return all security rules."""
        return [
            DebuggeableEnabledRule(),
            AllowBackupEnabledRule(),
            CleartextTrafficAllowedRule(),
            ExportedComponentWithoutPermissionRule(),
            DangerousPermissionDeclaredRule(),
            HardcodedSecretRule(),
            WeakCryptoAlgorithmRule(),
            WebViewJavaScriptEnabledRule(),
            DynamicCodeLoadingRule(),
            SQLInjectionRiskRule(),
            InsecureNetworkSecurityConfigRule(),
            StaticIVRule(),
        ]
    
    @staticmethod
    def _timestamp() -> str:
        """Generate a timestamp string for filenames."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")


def main():
    """Command-line interface."""
    parser = argparse.ArgumentParser(
        description='APK Security Analysis Tool - OWASP Mobile Top 10 2024',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate both JSON and HTML reports
  python analyze.py app.apk

  # Generate only JSON report
  python analyze.py app.apk --format json

  # Save reports to specific directory
  python analyze.py app.apk --output ./reports

  # Enable verbose debugging
  python analyze.py app.apk --verbose
        """
    )
    
    parser.add_argument(
        'apk_path',
        help='Path to the APK file to analyze'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'both'],
        default='both',
        help='Report format (default: both)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='.',
        help='Output directory for reports (default: current directory)'
    )
    
    parser.add_argument(
        '--no-deduplicate',
        action='store_true',
        help='Disable deduplication of findings'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Run analysis
    analyzer = APKSecurityAnalyzer()
    result = analyzer.analyze(
        apk_path=args.apk_path,
        output_dir=args.output,
        report_format=args.format,
        deduplicate=not args.no_deduplicate,
        verbose=args.verbose
    )
    
    # Return appropriate exit code
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()