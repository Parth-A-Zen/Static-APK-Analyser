"""
Base Rule Module

Abstract base class for security rules. Each rule implements a specific security check
against the AnalysisReadyAPK data.

Author: Generated for APK Security Analysis
License: MIT
"""

import logging
from abc import ABC, abstractmethod
from typing import List

# Adjust imports based on your project structure
from Loader.scope_filter import AnalysisReadyAPK
from Engine.finding import Finding

logger = logging.getLogger(__name__)


class BaseRule(ABC):
    """
    Abstract base class for security analysis rules.
    
    Each rule encapsulates a specific security check that can be applied to
    an AnalysisReadyAPK instance. Rules are instantiated by the RuleEngine
    and called via the run() method.
    
    Subclasses must implement:
    - rule_id property: unique identifier for the rule
    - run() method: executes the check and returns findings
    """
    
    @property
    @abstractmethod
    def rule_id(self) -> str:
        """
        Unique identifier for this rule.
        
        Returns:
            str: Rule identifier (e.g., 'DEBUGGABLE_ENABLED')
        """
        pass
    
    @abstractmethod
    def run(self, data: AnalysisReadyAPK) -> List[Finding]:
        """
        Execute the security check on the provided APK data.
        
        Args:
            data: AnalysisReadyAPK instance containing filtered security data
            
        Returns:
            List[Finding]: List of findings (may be empty if no issues found)
        """
        pass
    
    def _log_start(self):
        """Log that rule execution is starting."""
        logger.debug(f"[{self.rule_id}] Starting rule execution")
    
    def _log_finding(self, count: int):
        """Log that findings were discovered."""
        if count > 0:
            logger.info(f"[{self.rule_id}] Found {count} finding(s)")
        else:
            logger.debug(f"[{self.rule_id}] No findings")
    
    def _log_error(self, error: str):
        """Log an error during rule execution."""
        logger.error(f"[{self.rule_id}] Error: {error}")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"Rule({self.rule_id})"
