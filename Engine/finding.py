"""
Finding Module

Defines the Finding dataclass and related structures for security analysis results.
Each finding represents a security issue discovered during APK analysis.

Author: Generated for APK Security Analysis
License: MIT
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """
    Represents a single security finding from the APK analysis.
    
    Each finding includes:
    - Title and description of the security issue
    - OWASP Mobile Top 10 2024 category mapping
    - Severity level for risk prioritization
    - Remediation guidance for developers
    - Evidence showing what triggered the finding
    - Reference to the rule that generated it
    """
    
    title: str
    """Short title of the finding"""
    
    description: str
    """Detailed description of the security issue"""
    
    owasp_category: str
    """OWASP Mobile Top 10 2024 category (e.g., 'M1: Improper Credential Usage')"""
    
    severity: str
    """Severity level: 'Critical', 'High', 'Medium', or 'Low'"""
    
    remediation: str
    """Guidance on how to remediate the issue"""
    
    affected_component: Optional[str] = None
    """Optional: name of affected component (class, method, permission, etc.)"""
    
    evidence: Dict[str, Any] = field(default_factory=dict)
    """Dictionary containing evidence that triggered this finding"""
    
    rule_id: Optional[str] = None
    """ID of the rule that generated this finding"""
    
    def __post_init__(self):
        """Validate severity level."""
        valid_severities = {'Critical', 'High', 'Medium', 'Low'}
        if self.severity not in valid_severities:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Must be one of: {valid_severities}"
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to JSON-serializable dictionary."""
        return {
            'title': self.title,
            'description': self.description,
            'owasp_category': self.owasp_category,
            'severity': self.severity,
            'remediation': self.remediation,
            'affected_component': self.affected_component,
            'evidence': self.evidence,
            'rule_id': self.rule_id
        }
    
    def __repr__(self) -> str:
        """String representation for logging."""
        return (
            f"Finding("
            f"title='{self.title}', "
            f"severity={self.severity}, "
            f"owasp='{self.owasp_category}', "
            f"rule={self.rule_id})"
        )
    
    def get_summary(self) -> str:
        """Get a one-line summary of the finding."""
        component_str = f" in {self.affected_component}" if self.affected_component else ""
        return f"[{self.severity}] {self.title}{component_str}"
