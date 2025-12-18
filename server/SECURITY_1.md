# Security Guide

## ⚠️ Security Vulnerabilities Fixed

This document outlines the security vulnerabilities that have been identified and fixed in the UEBA platform.

## Critical Vulnerabilities Fixed

### 1. Hardcoded Credentials ✅ FIXED
**Issue**: Elasticsearch password was hardcoded in `server_config.yaml`

**Fix**: 
- Removed hardcoded password from config file
- Added environment variable support (`ES_USERNAME`, `ES_PASSWORD`)
- Added security warnings when passwords are found in config

**Action Required**: Set `ES_USERNAME` and `ES_PASSWORD` environment variables

### 2. Authentication Bypass ✅ FIXED
**Issue**: Agent token authentication was disabled in dev mode by default

**Fix**:
- Changed to require explicit `DEV_MODE=true` environment variable
- Added security warnings when dev mode is enabled
- Production mode now requires valid agent tokens

**Action Required**: Never set `DEV_MODE=true` in production

### 3. JWT Secret Management ✅ FIXED
**Issue**: JWT secret was randomly generated, invalidating tokens on restart

**Fix**:
- Added support for `JWT_SECRET` environment variable
- Added warning when secret is not set
- Tokens will persist across restarts if secret is set

**Action Required**: Set `JWT_SECRET` environment variable in production

### 4. Plain Text Password Storage ⚠️ WARNING
**Issue**: Endpoint passwords are stored in plain text in database

**Status**: Added security warnings. Full encryption requires credential vault integration.

**Recommendation**: 
- Use encrypted storage or credential vault (e.g., HashiCorp Vault, AWS Secrets Manager)
- Consider removing password storage if not needed
- Use SSH key-based authentication instead

### 5. Default Admin Credentials ⚠️ WARNING
**Issue**: Default admin/admin credentials are created automatically

**Status**: Added security warnings. Password should be changed immediately.

**Action Required**: Change default admin password immediately after first login

### 6. TLS Disabled by Default ⚠️ WARNING
**Issue**: TLS encryption is disabled by default for agent communication

**Status**: Configuration allows enabling TLS

**Action Required**: Enable TLS in production:
```yaml
tls:
  enabled: true
  cert_path: "config/server.crt"
  key_path: "config/server.key"
```

### 7. Security Headers ✅ ADDED
**Fix**: Added security headers middleware:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security
- Content-Security-Policy
- Referrer-Policy

## Security Best Practices

### Environment Variables
All sensitive configuration should use environment variables:

```bash
# Required for production
export JWT_SECRET="your-secret-key-here"
export ES_USERNAME="elastic"
export ES_PASSWORD="your-password-here"

# Optional
export AI_SERVER_API_KEY="your-api-key"
export N8N_WEBHOOK_URL="https://your-webhook-url"
export SECURE_COOKIES="true"  # Set to true if using HTTPS
```

### Production Checklist

- [ ] Set `JWT_SECRET` environment variable
- [ ] Set `ES_USERNAME` and `ES_PASSWORD` environment variables
- [ ] Remove hardcoded credentials from config files
- [ ] Change default admin password
- [ ] Enable TLS for agent communication
- [ ] Set `SECURE_COOKIES=true` if using HTTPS
- [ ] Never set `DEV_MODE=true` in production
- [ ] Review and restrict firewall rules
- [ ] Enable rate limiting on API endpoints
- [ ] Implement credential vault for endpoint passwords
- [ ] Regular security audits and updates
- [ ] Monitor logs for security events

### SQL Injection Protection
All SQL queries use parameterized queries to prevent SQL injection attacks.

### Input Validation
- Pydantic models validate all API inputs
- Type checking on all endpoints
- Length limits on string inputs

### Authentication
- JWT tokens with expiration
- Refresh token mechanism
- Agent token authentication (required in production)
- Password hashing with bcrypt (cost factor 12)

## Reporting Security Issues

If you discover a security vulnerability, please:
1. Do NOT create a public issue
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow time for a fix before public disclosure

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
