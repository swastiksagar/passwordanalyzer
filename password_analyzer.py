#!/usr/bin/env python3
"""
Password Analyzer Script
Analyzes password strength based on various security criteria
"""

import re
import string
from typing import Dict, List, Tuple


class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123', 
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'sunshine', 'iloveyou', 'princess', 'football'
        }
        
        self.common_patterns = [
            r'(.)\1{2,}',  # Repeated characters (aaa, 111, etc.)
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
            r'(qwerty|asdf|zxcv)',  # Keyboard patterns
        ]
    
    def analyze_password(self, password: str) -> Dict:
        """
        Comprehensive password analysis
        Returns a dictionary with analysis results
        """
        analysis = {
            'password': password,
            'length': len(password),
            'strength_score': 0,
            'strength_level': '',
            'criteria_met': {},
            'issues': [],
            'recommendations': []
        }
        
        # Check basic criteria
        analysis['criteria_met'] = self._check_criteria(password)
        
        # Calculate strength score
        analysis['strength_score'] = self._calculate_score(password, analysis['criteria_met'])
        
        # Determine strength level
        analysis['strength_level'] = self._get_strength_level(analysis['strength_score'])
        
        # Identify issues
        analysis['issues'] = self._identify_issues(password, analysis['criteria_met'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis['criteria_met'], analysis['issues'])
        
        return analysis
    
    def _check_criteria(self, password: str) -> Dict[str, bool]:
        """Check if password meets various security criteria"""
        return {
            'min_length_8': len(password) >= 8,
            'min_length_12': len(password) >= 12,
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_numbers': bool(re.search(r'\d', password)),
            'has_special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'no_common_password': password.lower() not in self.common_passwords,
            'no_repeated_chars': not bool(re.search(r'(.)\1{2,}', password)),
            'no_sequential_chars': not any(re.search(pattern, password.lower()) for pattern in self.common_patterns),
            'no_personal_info': not self._contains_personal_info(password),
        }
    
    def _contains_personal_info(self, password: str) -> bool:
        """Check if password contains obvious personal information patterns"""
        personal_patterns = [
            r'\b(19|20)\d{2}\b',  # Years
            r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b',  # Months
            r'\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b',  # Days
        ]
        
        password_lower = password.lower()
        return any(re.search(pattern, password_lower) for pattern in personal_patterns)
    
    def _calculate_score(self, password: str, criteria: Dict[str, bool]) -> int:
        """Calculate password strength score (0-100)"""
        score = 0
        
        # Length scoring
        if criteria['min_length_8']:
            score += 20
        if criteria['min_length_12']:
            score += 10
        if len(password) >= 16:
            score += 10
        
        # Character type scoring
        if criteria['has_lowercase']:
            score += 10
        if criteria['has_uppercase']:
            score += 10
        if criteria['has_numbers']:
            score += 10
        if criteria['has_special_chars']:
            score += 15
        
        # Security pattern scoring
        if criteria['no_common_password']:
            score += 10
        if criteria['no_repeated_chars']:
            score += 5
        if criteria['no_sequential_chars']:
            score += 5
        if criteria['no_personal_info']:
            score += 5
        
        return min(score, 100)
    
    def _get_strength_level(self, score: int) -> str:
        """Convert score to strength level"""
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Moderate"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
    
    def _identify_issues(self, password: str, criteria: Dict[str, bool]) -> List[str]:
        """Identify specific issues with the password"""
        issues = []
        
        if not criteria['min_length_8']:
            issues.append("Password is too short (less than 8 characters)")
        
        if not criteria['has_lowercase']:
            issues.append("Missing lowercase letters")
        
        if not criteria['has_uppercase']:
            issues.append("Missing uppercase letters")
        
        if not criteria['has_numbers']:
            issues.append("Missing numbers")
        
        if not criteria['has_special_chars']:
            issues.append("Missing special characters")
        
        if not criteria['no_common_password']:
            issues.append("Password is commonly used and easily guessable")
        
        if not criteria['no_repeated_chars']:
            issues.append("Contains repeated characters")
        
        if not criteria['no_sequential_chars']:
            issues.append("Contains sequential or keyboard pattern characters")
        
        if not criteria['no_personal_info']:
            issues.append("May contain personal information (dates, months, etc.)")
        
        return issues
    
    def _generate_recommendations(self, criteria: Dict[str, bool], issues: List[str]) -> List[str]:
        """Generate recommendations for improving password strength"""
        recommendations = []
        
        if not criteria['min_length_12']:
            recommendations.append("Use at least 12 characters for better security")
        
        if not criteria['has_lowercase'] or not criteria['has_uppercase']:
            recommendations.append("Mix uppercase and lowercase letters")
        
        if not criteria['has_numbers']:
            recommendations.append("Include numbers in your password")
        
        if not criteria['has_special_chars']:
            recommendations.append("Add special characters like !@#$%^&*()")
        
        if not criteria['no_common_password']:
            recommendations.append("Avoid common passwords - create something unique")
        
        if not criteria['no_repeated_chars'] or not criteria['no_sequential_chars']:
            recommendations.append("Avoid patterns and repeated characters")
        
        recommendations.append("Consider using a passphrase with random words")
        recommendations.append("Use a password manager to generate and store strong passwords")
        
        return recommendations
    
    def print_analysis(self, analysis: Dict) -> None:
        """Print formatted analysis results"""
        print("=" * 60)
        print("PASSWORD ANALYSIS REPORT")
        print("=" * 60)
        print(f"Password Length: {analysis['length']} characters")
        print(f"Strength Score: {analysis['strength_score']}/100")
        print(f"Strength Level: {analysis['strength_level']}")
        print()
        
        print("CRITERIA CHECKLIST:")
        print("-" * 30)
        criteria_labels = {
            'min_length_8': '✓ At least 8 characters',
            'min_length_12': '✓ At least 12 characters (recommended)',
            'has_lowercase': '✓ Contains lowercase letters',
            'has_uppercase': '✓ Contains uppercase letters',
            'has_numbers': '✓ Contains numbers',
            'has_special_chars': '✓ Contains special characters',
            'no_common_password': '✓ Not a common password',
            'no_repeated_chars': '✓ No excessive repeated characters',
            'no_sequential_chars': '✓ No sequential patterns',
            'no_personal_info': '✓ No obvious personal information'
        }
        
        for criterion, label in criteria_labels.items():
            status = "PASS" if analysis['criteria_met'][criterion] else "FAIL"
            status_symbol = "✅" if analysis['criteria_met'][criterion] else "❌"
            print(f"{status_symbol} {label}: {status}")
        
        if analysis['issues']:
            print("\nISSUES FOUND:")
            print("-" * 30)
            for i, issue in enumerate(analysis['issues'], 1):
                print(f"{i}. {issue}")
        
        if analysis['recommendations']:
            print("\nRECOMMENDATIONS:")
            print("-" * 30)
            for i, rec in enumerate(analysis['recommendations'], 1):
                print(f"{i}. {rec}")
        
        print("=" * 60)


def main():
    """Main function to run the password analyzer"""
    analyzer = PasswordAnalyzer()
    
    print("Password Analyzer")
    print("=" * 40)
    print("This tool analyzes password strength and provides recommendations.")
    print("Note: Your password will not be stored or transmitted anywhere.")
    print()
    
    while True:
        try:
            password = input("Enter a password to analyze (or 'quit' to exit): ")
            
            if password.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if not password:
                print("Please enter a password.")
                continue
            
            # Analyze the password
            analysis = analyzer.analyze_password(password)
            
            # Print results
            analyzer.print_analysis(analysis)
            
            print("\n" + "=" * 60 + "\n")
            
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()