## Authentication Bypass
Check for Weak OAuth Implementations: Identify improperly configured OAuth authentication mechanisms.
Detect Authentication Bypass via JWT Manipulation: Scan for JWT vulnerabilities where authentication can be bypassed.
Weak API Key Exposure: Detect weak or publicly exposed API keys leading to authentication bypass.
JWT Token Tampering Detection: Identify authentication bypass vulnerabilities due to weak JWT token implementations.
Weak Login Bypass: Identify login pages vulnerable to authentication bypass.

## Broken Access Control
Privilege Escalation via Direct URL Access: Identify cases where unauthorized users can access privileged resources by modifying URLs.
Detect Forced Browsing Exploits: Scan for access control vulnerabilities that allow unauthorized access.
Broken Access Control Detection: Detect improper user authorization and privilege escalation vulnerabilities.

## Command Injection
Command Injection Scan: Identify user input fields allowing shell command execution.

## Directory Traversal
Detect PHP File Inclusion via Traversal: Check for traversal vulnerabilities allowing PHP file inclusion.
Detect Windows Path Traversal: Identify directory traversal vulnerabilities using Windows-style file paths.
Absolute Path Traversal: Find vulnerabilities where absolute file paths can be exploited for unauthorized access.
Detect ../ Directory Traversal: Identify directory traversal vulnerabilities allowing access to sensitive files.
Directory Traversal Exploit: Detect sensitive files exposed via traversal attacks.

## File Inclusion (LFI/RFI)
File Inclusion Scan: Detect local and remote file inclusion vulnerabilities.

## Hardcoded Credentials
Check for Hardcoded Credentials in Code: Identify hardcoded credentials in source code.
Detect Exposed API Keys: Identify API keys hardcoded in configuration files.
Scan for Hardcoded Passwords: Find password strings embedded in application code.
Detect Hardcoded Database Credentials: Identify database credentials stored insecurely.
Identify Hardcoded Secrets: Scan for secrets in source code.
Hardcoded Credential Detection: Identify potential hardcoded credentials vulnerabilities.
Static Credential Exposure Scan: Scan for static credentials in application binaries.

## HTTP Request Smuggling
HTTP Request Smuggling Detection: Identify vulnerabilities in HTTP request processing that can lead to request smuggling.

## Insecure Direct Object References (IDOR)
Find IDOR Issues: Detect insecure direct object references exposing unauthorized data.

## JWT Token Vulnerabilities
JWT Token Analysis: Check for weak JWT implementations and misconfigurations.

## Race Condition
Detect Race Condition Issues: Identify vulnerabilities where multiple parallel processes can manipulate shared resources.

# Remote Code Execution (RCE)
RCE Detection via File Upload Exploitation: Scan for insecure file upload mechanisms that allow RCE.
Detect RCE via Unsafe Function Calls: Identify unsafe function calls that may lead to remote command execution.
RCE via File Upload: Detect RCE vulnerabilities through insecure file upload mechanisms.
Command Injection Detection for RCE: Identify potential command injection vulnerabilities in input fields leading to RCE.
Basic RCE Detection: Find potential remote command execution in input fields.

## Security Misconfiguration
Detect Security Misconfigurations: Identify vulnerabilities resulting from insecure default configurations.
Scan for Unsecured Admin Interfaces: Identify unsecured admin pages or interfaces.
Identify Exposed Configuration Files: Detect configuration files exposed to the public.
Detect Misconfigured HTTP Headers: Identify improper HTTP header configurations.
Security Settings Audit: Evaluate security settings and detect misconfigurations.

## Server-Side Request Forgery (SSRF)
Detect SSRF Vulnerabilities: Identify server-side request forgery vulnerabilities in web applications.
Scan for Internal Network Access via SSRF: Identify SSRF vulnerabilities that expose internal networks.
Identify SSRF via Redirects: Detect SSRF vulnerabilities using URL redirects.
Check SSRF in Image Fetchers: Identify SSRF vulnerabilities in services that fetch images.
Analyze SSRF Attack Surfaces: Evaluate potential SSRF attack vectors.

## SQL Injection
Detect SQL Injection Vulnerabilities: Identify potential SQL injection points in web applications.
Scan for Blind SQL Injection: Identify blind SQL injection vulnerabilities.
Detect Error-Based SQL Injection: Identify error-based SQL injection vulnerabilities.
Identify Time-Based SQL Injection: Detect SQL injection using time delays.
Parameterized Query Analysis: Ensure SQL queries use parameterized statements.
Check for Union-Based SQL Injection: Identify union-based SQL injection vulnerabilities.
Automated SQL Injection Scan: Use automated tools to detect SQL injection vulnerabilities.

## XML External Entity (XXE)
Detect XXE Vulnerabilities: Identify XML External Entity vulnerabilities in XML parsers.

## XSS (Cross-Site Scripting)
Detect Reflected XSS: Identify reflected cross-site scripting vulnerabilities.
Scan for Stored XSS: Identify stored cross-site scripting vulnerabilities.
Detect DOM-Based XSS: Identify DOM-based XSS vulnerabilities.
Identify XSS via Script Injection: Detect XSS vulnerabilities through injected scripts.
Check for AngularJS XSS: Identify XSS vulnerabilities in AngularJS applications.
Automated XSS Scanner: Use automated scanning to detect XSS vulnerabilities.
