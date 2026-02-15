"""
Rule Engine Module

Orchestrates the execution of security rules against APK analysis data.

The RuleEngine manages rule execution, error handling, and finding aggregation.

Author: Generated for APK Security Analysis
License: MIT
"""

import logging
import traceback
from typing import List

from Analyser.Engine.base_rule import BaseRule
from Engine.finding import Finding
from Loader.scope_filter import AnalysisReadyAPK

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Orchestrates the execution of security rules.
    
    The RuleEngine:
    - Maintains a collection of rules
    - Executes each rule against APK analysis data
    - Handles exceptions gracefully
    - Collects all findings
    - Tags findings with rule IDs
    """
    
    def __init__(self, rules: List[BaseRule]):
        """
        Initialize the rule engine with a list of rules.
        
        Args:
            rules: List of BaseRule instances to execute
        """
        self.rules = rules
        self.logger = logger
        self.logger.info(f"RuleEngine initialized with {len(rules)} rule(s)")
    
    def run_all(self, data: AnalysisReadyAPK) -> List[Finding]:
        """
        Execute all rules and collect findings.
        
        Each rule is executed independently. If a rule fails, the error is
        logged but execution continues with remaining rules.
        
        Args:
            data: AnalysisReadyAPK instance to analyze
            
        Returns:
            List[Finding]: All findings from all rules
        """
        self.logger.info(f"Starting rule engine execution ({len(self.rules)} rules)")
        
        all_findings = []
        executed = 0
        failed = 0
        
        for rule in self.rules:
            try:
                self.logger.info(f"Executing rule: {rule.rule_id}")
                
                # Run the rule
                findings = rule.run(data)
                
                if findings:
                    all_findings.extend(findings)
                    self.logger.info(
                        f"  → {len(findings)} finding(s) from {rule.rule_id}"
                    )
                
                executed += 1
            
            except Exception as e:
                failed += 1
                self.logger.error(
                    f"Rule {rule.rule_id} failed: {str(e)}"
                )
                self.logger.debug(traceback.format_exc())
        
        # Summary
        self.logger.info(
            f"Rule execution completed: {executed} executed, {failed} failed, "
            f"{len(all_findings)} total findings"
        )
        
        return all_findings
    
    def add_rule(self, rule: BaseRule):
        """
        Add a rule to the engine.
        
        Args:
            rule: BaseRule instance to add
        """
        self.rules.append(rule)
        self.logger.info(f"Rule added: {rule.rule_id}")
    
    def get_rules(self) -> List[BaseRule]:
        """
        Get all registered rules.
        
        Returns:
            List[BaseRule]: All rules in the engine
        """
        return self.rules
    
    def __repr__(self) -> str:
        """String representation."""
        return f"RuleEngine(rules={len(self.rules)})"
