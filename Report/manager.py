"""
Finding Manager Module

Manages a collection of findings, providing grouping and deduplication.

Author: Generated for APK Security Analysis
License: MIT
"""

import logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from Analyser.Engine.finding import Finding

logger = logging.getLogger(__name__)


class FindingManager:
    """
    Manages a collection of security findings.
    
    The FindingManager:
    - Stores findings
    - Groups findings by severity or OWASP category
    - Deduplicates findings
    - Provides sorting and filtering
    """
    
    # Severity ordering for sorting (highest to lowest risk)
    SEVERITY_ORDER = {
        'Critical': 0,
        'High': 1,
        'Medium': 2,
        'Low': 3
    }
    
    def __init__(self):
        """Initialize the finding manager."""
        self.findings: List[Finding] = []
        self.logger = logger
        self.logger.info("FindingManager initialized")
    
    def add_findings(self, findings: List[Finding]) -> None:
        """
        Add findings to the manager.
        
        Args:
            findings: List of Finding instances to add
        """
        if not findings:
            return
        
        self.findings.extend(findings)
        self.logger.info(f"Added {len(findings)} finding(s) (total: {len(self.findings)})")
    
    def add_finding(self, finding: Finding) -> None:
        """
        Add a single finding to the manager.
        
        Args:
            finding: Finding instance to add
        """
        self.findings.append(finding)
        self.logger.debug(f"Added finding: {finding.get_summary()}")
    
    def get_all(self) -> List[Finding]:
        """
        Get all findings, sorted by severity.
        
        Returns:
            List[Finding]: All findings sorted by severity (critical first)
        """
        return sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 999)
        )
    
    def get_by_severity(self, severity: str) -> List[Finding]:
        """
        Get findings by severity level.
        
        Args:
            severity: Severity level ('Critical', 'High', 'Medium', 'Low')
            
        Returns:
            List[Finding]: Findings of specified severity
        """
        return [f for f in self.findings if f.severity == severity]
    
    def group_by_severity(self) -> Dict[str, List[Finding]]:
        """
        Group findings by severity level.
        
        Returns:
            Dict[str, List[Finding]]: Findings grouped by severity
        """
        grouped = defaultdict(list)
        
        for finding in self.findings:
            grouped[finding.severity].append(finding)
        
        # Sort each group by severity order
        result = {}
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in grouped:
                result[severity] = grouped[severity]
        
        return result
    
    def group_by_owasp(self) -> Dict[str, List[Finding]]:
        """
        Group findings by OWASP Mobile Top 10 2024 category.
        
        Returns:
            Dict[str, List[Finding]]: Findings grouped by OWASP category
        """
        grouped = defaultdict(list)
        
        for finding in self.findings:
            grouped[finding.owasp_category].append(finding)
        
        # Sort by category name
        result = {}
        for category in sorted(grouped.keys()):
            result[category] = grouped[category]
        
        return result
    
    def group_by_rule(self) -> Dict[str, List[Finding]]:
        """
        Group findings by rule ID.
        
        Returns:
            Dict[str, List[Finding]]: Findings grouped by rule ID
        """
        grouped = defaultdict(list)
        
        for finding in self.findings:
            rule_id = finding.rule_id or "UNKNOWN"
            grouped[rule_id].append(finding)
        
        return dict(grouped)
    
    def deduplicate(self) -> None:
        """
        Remove duplicate findings based on (title, affected_component).
        
        Keeps the first occurrence and removes subsequent duplicates.
        """
        seen: Set[Tuple[str, str]] = set()
        unique_findings = []
        
        for finding in self.findings:
            # Create a unique key from title and component
            key = (finding.title, finding.affected_component or "")
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        removed = len(self.findings) - len(unique_findings)
        if removed > 0:
            self.logger.info(f"Deduplicated {removed} finding(s)")
        
        self.findings = unique_findings
    
    def get_summary(self) -> Dict[str, int]:
        """
        Get a summary of findings by severity.
        
        Returns:
            Dict[str, int]: Count of findings per severity level
        """
        summary = {
            'Total': len(self.findings),
            'Critical': len(self.get_by_severity('Critical')),
            'High': len(self.get_by_severity('High')),
            'Medium': len(self.get_by_severity('Medium')),
            'Low': len(self.get_by_severity('Low'))
        }
        
        return summary
    
    def has_critical(self) -> bool:
        """
        Check if there are any critical findings.
        
        Returns:
            bool: True if there are critical findings
        """
        return len(self.get_by_severity('Critical')) > 0
    
    def has_high(self) -> bool:
        """
        Check if there are any high-severity findings.
        
        Returns:
            bool: True if there are high-severity findings
        """
        return len(self.get_by_severity('High')) > 0
    
    def clear(self) -> None:
        """Clear all findings from the manager."""
        self.findings = []
        self.logger.info("All findings cleared")
    
    def __len__(self) -> int:
        """Return the number of findings."""
        return len(self.findings)
    
    def __repr__(self) -> str:
        """String representation."""
        summary = self.get_summary()
        return (
            f"FindingManager("
            f"total={summary['Total']}, "
            f"critical={summary['Critical']}, "
            f"high={summary['High']}, "
            f"medium={summary['Medium']}, "
            f"low={summary['Low']})"
        )
