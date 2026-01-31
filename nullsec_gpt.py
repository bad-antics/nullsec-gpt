#!/usr/bin/env python3
"""
NullSec GPT - AI-powered vulnerability scanner & security assistant
"""

import os
import re
import sys
import json
import argparse
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path

# Version
__version__ = "1.0.0"

BANNER = r"""
 ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗███████╗ ██████╗ 
 ████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔════╝██╔════╝ 
 ██╔██╗ ██║██║   ██║██║     ██║     ███████╗█████╗  ██║      
 ██║╚██╗██║██║   ██║██║     ██║     ╚════██║██╔══╝  ██║      
 ██║ ╚████║╚██████╔╝███████╗███████╗███████║███████╗╚██████╗ 
 ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ 
          GPT Security Scanner v{version}
""".format(version=__version__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    line: Optional[int] = None
    column: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'remediation': self.remediation,
            'cwe': self.cwe,
            'owasp': self.owasp
        }


@dataclass
class ScanResult:
    """Results from a security scan"""
    file_path: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_time: float = 0.0
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == 'CRITICAL')
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == 'HIGH')
    
    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)


# =============================================================================
# SECURITY PATTERNS (Pre-AI detection)
# =============================================================================

class SecurityPatterns:
    """Common vulnerability patterns for quick detection"""
    
    PATTERNS = {
        'sqli': {
            'patterns': [
                r'execute\s*\(\s*[f"\'].*\{.*\}',  # f-string in execute
                r'execute\s*\(\s*["\'].*%s.*["\'].*%',  # % formatting
                r'execute\s*\(\s*["\'].*\+.*["\']',  # String concat
                r'cursor\.execute\s*\(\s*[f"\']',
            ],
            'severity': 'CRITICAL',
            'title': 'SQL Injection',
            'cwe': 'CWE-89',
            'owasp': 'A03:2021'
        },
        'xss': {
            'patterns': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'\.html\s*\([^)]*\+',
                r'dangerouslySetInnerHTML',
            ],
            'severity': 'HIGH',
            'title': 'Cross-Site Scripting (XSS)',
            'cwe': 'CWE-79',
            'owasp': 'A03:2021'
        },
        'hardcoded_secret': {
            'patterns': [
                r'(?i)(api[_-]?key|apikey|secret|password|passwd|pwd|token|auth)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key',
                r'(?i)BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY',
                r'sk-[a-zA-Z0-9]{32,}',  # OpenAI key
                r'ghp_[a-zA-Z0-9]{36}',  # GitHub token
            ],
            'severity': 'CRITICAL',
            'title': 'Hardcoded Secret/Credential',
            'cwe': 'CWE-798',
            'owasp': 'A07:2021'
        },
        'command_injection': {
            'patterns': [
                r'os\.system\s*\(',
                r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                r'eval\s*\(',
                r'exec\s*\(',
            ],
            'severity': 'CRITICAL',
            'title': 'Command/Code Injection',
            'cwe': 'CWE-78',
            'owasp': 'A03:2021'
        },
        'path_traversal': {
            'patterns': [
                r'open\s*\([^)]*\+',
                r'os\.path\.join\s*\([^)]*\.\.',
                r'send_file\s*\([^)]*user',
            ],
            'severity': 'HIGH',
            'title': 'Path Traversal',
            'cwe': 'CWE-22',
            'owasp': 'A01:2021'
        },
        'insecure_deserialization': {
            'patterns': [
                r'pickle\.loads?\s*\(',
                r'yaml\.load\s*\([^)]*$',  # yaml.load without Loader
                r'marshal\.loads?\s*\(',
                r'shelve\.open\s*\(',
            ],
            'severity': 'CRITICAL',
            'title': 'Insecure Deserialization',
            'cwe': 'CWE-502',
            'owasp': 'A08:2021'
        },
        'weak_crypto': {
            'patterns': [
                r'(?i)md5\s*\(',
                r'(?i)sha1\s*\(',
                r'DES\.',
                r'RC4',
                r'random\.random\s*\(',  # Not cryptographically secure
            ],
            'severity': 'MEDIUM',
            'title': 'Weak Cryptography',
            'cwe': 'CWE-327',
            'owasp': 'A02:2021'
        },
        'ssrf': {
            'patterns': [
                r'requests\.(get|post|put|delete)\s*\([^)]*\+',
                r'urllib\.request\.urlopen\s*\([^)]*\+',
                r'httpx\.(get|post)\s*\([^)]*\+',
            ],
            'severity': 'HIGH',
            'title': 'Server-Side Request Forgery (SSRF)',
            'cwe': 'CWE-918',
            'owasp': 'A10:2021'
        },
        'xxe': {
            'patterns': [
                r'etree\.parse\s*\(',
                r'xml\.sax\.parse\s*\(',
                r'XMLParser\s*\(\s*\)',
            ],
            'severity': 'HIGH',
            'title': 'XML External Entity (XXE)',
            'cwe': 'CWE-611',
            'owasp': 'A05:2021'
        },
        'debug_enabled': {
            'patterns': [
                r'DEBUG\s*=\s*True',
                r'app\.run\s*\([^)]*debug\s*=\s*True',
                r'FLASK_DEBUG\s*=\s*1',
            ],
            'severity': 'MEDIUM',
            'title': 'Debug Mode Enabled',
            'cwe': 'CWE-489',
            'owasp': 'A05:2021'
        },
    }
    
    @classmethod
    def scan(cls, code: str, filename: str = '') -> List[Vulnerability]:
        """Scan code for known vulnerability patterns"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for vuln_type, config in cls.PATTERNS.items():
            for pattern in config['patterns']:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        vulnerabilities.append(Vulnerability(
                            severity=config['severity'],
                            title=config['title'],
                            description=f"Potential {config['title'].lower()} detected",
                            line=line_num,
                            code_snippet=line.strip(),
                            cwe=config.get('cwe'),
                            owasp=config.get('owasp'),
                            remediation=cls._get_remediation(vuln_type)
                        ))
        
        return vulnerabilities
    
    @classmethod
    def _get_remediation(cls, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediations = {
            'sqli': 'Use parameterized queries or prepared statements',
            'xss': 'Sanitize user input and use Content Security Policy',
            'hardcoded_secret': 'Use environment variables or secret management',
            'command_injection': 'Avoid shell=True, use subprocess with list args',
            'path_traversal': 'Validate and sanitize file paths',
            'insecure_deserialization': 'Use safe serialization formats like JSON',
            'weak_crypto': 'Use SHA-256+ for hashing, AES-256 for encryption',
            'ssrf': 'Validate and whitelist URLs',
            'xxe': 'Disable external entities in XML parser',
            'debug_enabled': 'Disable debug mode in production',
        }
        return remediations.get(vuln_type, 'Review and fix the security issue')


# =============================================================================
# AI SCANNER
# =============================================================================

class AIScanner:
    """AI-powered code scanner using OpenAI/Claude/Ollama"""
    
    SYSTEM_PROMPT = """You are an expert security researcher and code auditor. 
Analyze the provided code for security vulnerabilities.

For each vulnerability found, provide:
1. Severity (CRITICAL, HIGH, MEDIUM, LOW)
2. Vulnerability type
3. Line number(s) affected
4. Explanation of the risk
5. Specific remediation steps

Focus on:
- Injection vulnerabilities (SQL, Command, XSS, XXE)
- Authentication/Authorization issues
- Cryptographic weaknesses
- Sensitive data exposure
- Security misconfigurations
- Insecure deserialization
- Using components with known vulnerabilities

Respond in JSON format:
{
  "vulnerabilities": [
    {
      "severity": "CRITICAL",
      "title": "SQL Injection",
      "line": 45,
      "description": "...",
      "remediation": "..."
    }
  ]
}"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4"):
        self.api_key = api_key or os.environ.get('OPENAI_API_KEY')
        self.model = model
        self._client = None
    
    def _get_client(self):
        """Lazy load OpenAI client"""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
            except ImportError:
                print("Error: openai package not installed")
                print("Install with: pip install openai")
                sys.exit(1)
        return self._client
    
    def analyze(self, code: str, filename: str = '') -> List[Vulnerability]:
        """Analyze code using AI"""
        if not self.api_key:
            print("Warning: No API key found, using pattern-based scanning only")
            return SecurityPatterns.scan(code, filename)
        
        try:
            client = self._get_client()
            
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this code for security vulnerabilities:\n\n```\n{code}\n```"}
                ],
                temperature=0.1,
                max_tokens=4000
            )
            
            content = response.choices[0].message.content
            
            # Parse JSON response
            try:
                # Extract JSON from response
                json_match = re.search(r'\{[\s\S]*\}', content)
                if json_match:
                    data = json.loads(json_match.group())
                    return [
                        Vulnerability(
                            severity=v.get('severity', 'MEDIUM'),
                            title=v.get('title', 'Unknown'),
                            description=v.get('description', ''),
                            line=v.get('line'),
                            remediation=v.get('remediation')
                        )
                        for v in data.get('vulnerabilities', [])
                    ]
            except json.JSONDecodeError:
                pass
            
            # Fallback: pattern-based
            return SecurityPatterns.scan(code, filename)
            
        except Exception as e:
            print(f"AI analysis error: {e}")
            return SecurityPatterns.scan(code, filename)
    
    def chat(self, message: str) -> str:
        """Interactive security chat"""
        if not self.api_key:
            return "Error: API key required for chat mode"
        
        try:
            client = self._get_client()
            
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a helpful security expert. Answer questions about vulnerabilities, exploits, and security best practices."},
                    {"role": "user", "content": message}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"Error: {e}"


# =============================================================================
# SCANNER
# =============================================================================

class SecurityScanner:
    """Main security scanner class"""
    
    SUPPORTED_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', 
        '.php', '.c', '.cpp', '.h', '.cs', '.rs', '.swift', '.kt'
    }
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4", use_ai: bool = True):
        self.use_ai = use_ai and (api_key or os.environ.get('OPENAI_API_KEY'))
        self.ai_scanner = AIScanner(api_key, model) if self.use_ai else None
    
    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file"""
        result = ScanResult(file_path=file_path)
        
        path = Path(file_path)
        if not path.exists():
            result.errors.append(f"File not found: {file_path}")
            return result
        
        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            result.errors.append(f"Unsupported file type: {path.suffix}")
            return result
        
        try:
            code = path.read_text(encoding='utf-8', errors='ignore')
            
            # Pattern-based scan (always)
            pattern_vulns = SecurityPatterns.scan(code, str(path))
            
            # AI scan (if enabled)
            if self.use_ai and self.ai_scanner:
                ai_vulns = self.ai_scanner.analyze(code, str(path))
                # Merge results, deduplicate by line
                seen_lines = {v.line for v in pattern_vulns}
                for v in ai_vulns:
                    if v.line not in seen_lines:
                        pattern_vulns.append(v)
            
            result.vulnerabilities = pattern_vulns
            
        except Exception as e:
            result.errors.append(str(e))
        
        return result
    
    def scan_directory(self, dir_path: str, recursive: bool = True) -> List[ScanResult]:
        """Scan a directory"""
        results = []
        path = Path(dir_path)
        
        if not path.exists():
            return [ScanResult(file_path=dir_path, errors=["Directory not found"])]
        
        pattern = '**/*' if recursive else '*'
        
        for file_path in path.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                # Skip common non-source directories
                if any(skip in str(file_path) for skip in ['node_modules', '.git', '__pycache__', 'venv', '.venv']):
                    continue
                results.append(self.scan_file(str(file_path)))
        
        return results
    
    def chat(self, message: str) -> str:
        """Interactive chat mode"""
        if self.ai_scanner:
            return self.ai_scanner.chat(message)
        return "Chat mode requires an API key"


# =============================================================================
# OUTPUT FORMATTERS
# =============================================================================

class OutputFormatter:
    """Format scan results for output"""
    
    SEVERITY_COLORS = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',      # Yellow
        'MEDIUM': '\033[33m',    # Orange
        'LOW': '\033[94m',       # Blue
        'INFO': '\033[90m',      # Gray
    }
    NC = '\033[0m'
    
    @classmethod
    def format_console(cls, results: List[ScanResult]) -> str:
        """Format results for console output"""
        output = []
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)
        total_all = sum(r.total_count for r in results)
        
        for result in results:
            if result.vulnerabilities:
                output.append(f"\n📁 {result.file_path}")
                output.append("-" * 60)
                
                for vuln in result.vulnerabilities:
                    color = cls.SEVERITY_COLORS.get(vuln.severity, '')
                    output.append(f"{color}⚠️  {vuln.severity}: {vuln.title}{cls.NC}")
                    if vuln.line:
                        output.append(f"    Line: {vuln.line}")
                    if vuln.code_snippet:
                        output.append(f"    Code: {vuln.code_snippet[:80]}")
                    if vuln.description:
                        output.append(f"    Risk: {vuln.description}")
                    if vuln.remediation:
                        output.append(f"    Fix:  {vuln.remediation}")
                    if vuln.cwe:
                        output.append(f"    Ref:  {vuln.cwe}")
                    output.append("")
        
        # Summary
        output.append("\n" + "=" * 60)
        output.append("SUMMARY")
        output.append("=" * 60)
        output.append(f"Files scanned: {len(results)}")
        output.append(f"Total issues:  {total_all}")
        output.append(f"  Critical:    {total_critical}")
        output.append(f"  High:        {total_high}")
        
        return '\n'.join(output)
    
    @classmethod
    def format_json(cls, results: List[ScanResult]) -> str:
        """Format results as JSON"""
        data = {
            'results': [
                {
                    'file': r.file_path,
                    'vulnerabilities': [v.to_dict() for v in r.vulnerabilities],
                    'errors': r.errors
                }
                for r in results
            ],
            'summary': {
                'files_scanned': len(results),
                'total_issues': sum(r.total_count for r in results),
                'critical': sum(r.critical_count for r in results),
                'high': sum(r.high_count for r in results),
            }
        }
        return json.dumps(data, indent=2)
    
    @classmethod
    def format_sarif(cls, results: List[ScanResult]) -> str:
        """Format results as SARIF for GitHub"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "NullSec GPT",
                        "version": __version__,
                        "informationUri": "https://github.com/bad-antics/nullsec-gpt"
                    }
                },
                "results": []
            }]
        }
        
        for result in results:
            for vuln in result.vulnerabilities:
                sarif["runs"][0]["results"].append({
                    "ruleId": vuln.cwe or vuln.title.replace(' ', '-').lower(),
                    "level": "error" if vuln.severity in ('CRITICAL', 'HIGH') else "warning",
                    "message": {"text": vuln.description or vuln.title},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.file_path},
                            "region": {"startLine": vuln.line or 1}
                        }
                    }]
                })
        
        return json.dumps(sarif, indent=2)


# =============================================================================
# CLI
# =============================================================================

def interactive_chat(scanner: SecurityScanner):
    """Run interactive chat mode"""
    print(BANNER)
    print("╔═══════════════════════════════════════╗")
    print("║       NullSec GPT Security Chat       ║")
    print("║       Type 'help' for commands        ║")
    print("╚═══════════════════════════════════════╝\n")
    
    while True:
        try:
            user_input = input("\033[36mYou:\033[0m ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ('exit', 'quit', 'q'):
                print("Goodbye!")
                break
            
            if user_input.lower() == 'help':
                print("""
Commands:
  analyze <code>  - Analyze code snippet for vulnerabilities
  cve <id>        - Explain a CVE
  exit            - Exit chat mode
  
Or just ask any security question!
""")
                continue
            
            response = scanner.chat(user_input)
            print(f"\n\033[32m🤖:\033[0m {response}\n")
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except EOFError:
            break


def main():
    parser = argparse.ArgumentParser(
        description='NullSec GPT - AI-powered vulnerability scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files for vulnerabilities')
    scan_parser.add_argument('target', help='File or directory to scan')
    scan_parser.add_argument('-r', '--recursive', action='store_true', help='Scan recursively')
    scan_parser.add_argument('-o', '--output', help='Output file')
    scan_parser.add_argument('-f', '--format', choices=['console', 'json', 'sarif'], default='console')
    scan_parser.add_argument('--no-ai', action='store_true', help='Disable AI analysis')
    scan_parser.add_argument('--model', default='gpt-4', help='AI model to use')
    
    # Chat command
    chat_parser = subparsers.add_parser('chat', help='Interactive security chat')
    chat_parser.add_argument('--model', default='gpt-4', help='AI model to use')
    
    # Version
    parser.add_argument('-v', '--version', action='version', version=f'NullSec GPT v{__version__}')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        scanner = SecurityScanner(
            use_ai=not args.no_ai,
            model=args.model
        )
        
        print(f"🔍 Scanning {args.target}...")
        
        target = Path(args.target)
        if target.is_file():
            results = [scanner.scan_file(str(target))]
        else:
            results = scanner.scan_directory(str(target), args.recursive)
        
        # Format output
        if args.format == 'json':
            output = OutputFormatter.format_json(results)
        elif args.format == 'sarif':
            output = OutputFormatter.format_sarif(results)
        else:
            output = OutputFormatter.format_console(results)
        
        # Write output
        if args.output:
            Path(args.output).write_text(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
    
    elif args.command == 'chat':
        scanner = SecurityScanner(model=args.model)
        interactive_chat(scanner)
    
    else:
        # Default: show help or interactive mode
        if len(sys.argv) == 1:
            scanner = SecurityScanner()
            interactive_chat(scanner)
        else:
            parser.print_help()


if __name__ == '__main__':
    main()
