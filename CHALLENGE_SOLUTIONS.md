# RatPetShop Challenge Solutions Guide

This guide provides hints and solutions for all 18 challenges in RatPetShop. This is an educational tool - use it to learn!

## ⚠️ Spoiler Warning
This document contains solutions to all challenges. Try solving them yourself first!

---

## 🟢 Easy Challenges (100 points each)

### Challenge 1: Broken Access Control - Easy
**Objective**: Access the admin panel without proper authorization.

**Solution**:
1. Visit the challenge page to get the link
2. Navigate to `/admin` directly
3. The flag is displayed on the admin panel page

**Learning**: This demonstrates missing authentication checks on sensitive endpoints.

---

### Challenge 4: Cryptographic Failures - Easy
**Objective**: Find sensitive data in plain text.

**Solution**:
1. Visit `/secret-page`
2. View the page source (Ctrl+U or right-click → View Page Source)
3. Look for the flag in HTML comments or JavaScript variables

**Learning**: Sensitive data should never be stored in client-side code.

---

### Challenge 7: SQL Injection - Easy
**Objective**: Bypass login using SQL injection.

**Solution**:
1. Visit `/vuln-login`
2. Enter username: `admin' OR '1'='1`
3. Enter any password
4. Submit the form to get the flag

**Learning**: Never concatenate user input directly into SQL queries. Use parameterized queries instead.

---

### Challenge 10: Security Misconfiguration - Easy
**Objective**: Find exposed configuration files.

**Solution**:
1. Navigate to `/.env`
2. The flag is displayed in the exposed configuration file

**Learning**: Configuration files should never be publicly accessible.

---

### Challenge 11: Authentication Failures - Easy
**Objective**: Exploit weak password policy.

**Solution**:
1. Visit `/weak-auth`
2. Try common weak passwords like: `password`, `password123`, `admin`, or `admin123`
3. The flag appears after successful login with a weak password

**Learning**: Implement strong password policies and reject common passwords.

---

## 🟡 Medium Challenges (200 points each)

### Challenge 2: Broken Access Control - Medium
**Objective**: Access another user's profile data (IDOR).

**Solution**:
1. Visit `/profile/2` (the test user's profile)
2. The flag is displayed for accessing another user's data
3. Try other user IDs to see different profiles

**Learning**: Always verify that the authenticated user has permission to access the requested resource.

---

### Challenge 5: Cryptographic Failures - Medium
**Objective**: Decrypt weakly encrypted data.

**Solution**:
1. Visit `/encrypted-data`
2. Copy the encrypted flag
3. Use an online ROT13 decoder (or Python: `import codecs; codecs.decode('text', 'rot13')`)
4. Submit the decrypted flag

**Learning**: ROT13 is not encryption - use proper encryption algorithms like AES.

---

### Challenge 8: SQL Injection - Medium
**Objective**: Extract data using UNION-based SQL injection.

**Solution**:
1. Visit `/search`
2. Try query: `' UNION SELECT fs.id, f.name, fs.value FROM flags f JOIN flag_secrets fs ON f.id = fs.flag_id--`
3. Look through the results to find flag values
4. Submit the flag for Challenge 8

**Learning**: SQL injection can be used to extract entire databases. Always use parameterized queries. Note: Flag values are now stored in a separate table to make this challenge more realistic.

---

### Challenge 12: Data Integrity - Medium
**Objective**: Manipulate session data.

**Solution**:
1. Visit `/session-check`
2. Add `?admin=true` to the URL
3. The flag is displayed when admin parameter is true

**Learning**: Never trust client-side data or URL parameters for authorization decisions.

---

## 🔴 Hard Challenges (300 points each)

### Challenge 3: Broken Access Control - Hard
**Objective**: Exploit IDOR to access sensitive files.

**Solution**:
1. Visit `/files/1` and `/files/2` to see available files
2. Try `/files/3` to access the secret file
3. The flag is displayed in the secret file content

**Learning**: Implement proper access control for all resources, not just obvious ones.

---

### Challenge 6: Cryptographic Failures - Hard
**Objective**: Exploit weak password hashing.

**Solution**:
1. Visit `/user-hashes`
2. Copy the MD5 hashes
3. Use an online hash cracker like CrackStation or rainbow tables
4. The hashes crack to common passwords
5. The flag is visible on the page once you understand the vulnerability

**Learning**: MD5 is not secure for password hashing. Use bcrypt, scrypt, or Argon2.

---

### Challenge 9: SQL Injection - Hard
**Objective**: Use blind SQL injection.

**Solution**:
1. Visit `/check-user`
2. Try: `admin' AND SUBSTR((SELECT value FROM flags WHERE id=9),1,1)='F'--`
3. If it returns "exists", the first character is 'F'
4. Repeat for each character to extract the full flag
5. This is tedious but demonstrates blind SQLi techniques

**Learning**: Even without visible output, SQL injection can extract data through timing or boolean responses.

---

### Challenge 13: SSRF - Hard
**Objective**: Exploit SSRF to access internal resources.

**Solution**:
1. Visit `/fetch-url`
2. Enter URL: `http://localhost:5000/admin`
3. The server fetches the internal admin page
4. The flag is displayed after accessing localhost

**Learning**: Always validate and sanitize URLs. Implement allow-lists for external resources.

---

### Challenge 14: Insecure Design - Medium
**Objective**: Exploit business logic flaw in password reset.

**Solution**:
1. Visit `/reset-password`
2. Enter username "admin"
3. Note the reset token generated
4. Analyze the token - it's the MD5 hash of the username
5. Generate token for any user: `echo -n "admin" | md5sum`
6. Enter the predicted token to get the flag

**Learning**: Password reset tokens must be cryptographically secure and unpredictable.

---

### Challenge 15: Outdated Components - Easy
**Objective**: Identify vulnerable dependencies.

**Solution**:
1. Visit `/dependencies`
2. Review the list of outdated packages with known CVEs
3. The flag is displayed on the page
4. Submit the flag

**Learning**: Always keep dependencies updated and use tools like Dependabot or Snyk.

---

### Challenge 16: Logging Failures - Medium
**Objective**: Exploit insufficient logging.

**Solution**:
1. Visit `/sensitive-action`
2. Select "Delete All Data" action
3. Notice the action executes without any logging
4. The flag is displayed after performing the action

**Learning**: Critical actions must be logged for security monitoring and forensics.

---

### Challenge 17: XSS - Medium
**Objective**: Exploit Cross-Site Scripting vulnerability.

**Solution**:
1. Visit `/comment`
2. Post a comment with XSS payload: `<script>alert(window.flagData)</script>`
3. The flag is stored in JavaScript and can be extracted via XSS
4. Copy the flag from the alert and submit it

**Learning**: Always sanitize user input and use Content Security Policy headers.

---

### Challenge 18: Path Traversal - Hard
**Objective**: Exploit path traversal to access restricted files.

**Solution**:
1. Visit `/download`
2. Try parameter: `?file=../secret.txt` or `?file=secret.txt`
3. The application doesn't validate file paths
4. Access the secret file to get the flag

**Learning**: Always validate and sanitize file paths. Use whitelists for allowed files.

---

## 🏆 Tips for Success

1. **Read the descriptions carefully** - They contain important hints
2. **Click the hint buttons** - They provide step-by-step guidance
3. **Use browser developer tools** - Inspect network requests, view source, check console
4. **Try variations** - If something doesn't work, try different payloads
5. **Learn from each challenge** - Understand why each vulnerability is dangerous

---

## 🎓 Further Learning

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

---

## ⚠️ Ethical Reminder

These techniques are for **educational purposes only**. Never use them on systems without explicit permission. Practice ethical hacking and responsible disclosure.

**Happy Learning! 🎉**
