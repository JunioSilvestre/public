# ================================
#  SECURITY STRUCTURE GENERATOR
#  Creates folders and empty files
# ================================

# Base folder
$basePath = "src/security"

# Create base folder
New-Item -ItemType Directory -Force -Path $basePath | Out-Null

# -------------------------------
# middleware/
# -------------------------------
$middleware = @(
    "securityMiddleware.ts",
    "rateLimit.ts",
    "ipFilter.ts",
    "csrfProtection.ts",
    "cors.ts",
    "securityHeaders.ts",
    "requestSanitizer.ts",
    "botProtection.ts",
    "ddosProtection.ts",
    "sessionGuard.ts",
    "tenantIsolationMiddleware.ts",
    "geoBlock.ts",
    "userAgentFilter.ts",
    "requestIntegrity.ts"
)

New-Item -ItemType Directory -Force -Path "$basePath/middleware" | Out-Null
foreach ($file in $middleware) {
    New-Item -ItemType File -Force -Path "$basePath/middleware/$file" | Out-Null
}

# -------------------------------
# validators/
# -------------------------------
$validators = @(
    "inputValidator.ts",
    "headerValidator.ts",
    "payloadValidator.ts",
    "schemaValidator.ts",
    "fileUploadValidator.ts",
    "queryParamValidator.ts",
    "routeAccessValidator.ts",
    "apiKeyValidator.ts"
)

New-Item -ItemType Directory -Force -Path "$basePath/validators" | Out-Null
foreach ($file in $validators) {
    New-Item -ItemType File -Force -Path "$basePath/validators/$file" | Out-Null
}

# -------------------------------
# network/
# -------------------------------
$network = @(
    "firewallRules.ts",
    "ipBlocklist.ts",
    "ipAllowlist.ts",
    "vpnEnforcement.ts",
    "networkPolicies.ts",
    "dnsProtection.ts",
    "portRestrictions.ts",
    "trafficInspection.ts"
)

New-Item -ItemType Directory -Force -Path "$basePath/network" | Out-Null
foreach ($file in $network) {
    New-Item -ItemType File -Force -Path "$basePath/network/$file" | Out-Null
}

# -------------------------------
# tests/
# -------------------------------
New-Item -ItemType Directory -Force -Path "$basePath/tests" | Out-Null
New-Item -ItemType Directory -Force -Path "$basePath/tests/penetration" | Out-Null
New-Item -ItemType Directory -Force -Path "$basePath/tests/fuzzing" | Out-Null
New-Item -ItemType Directory -Force -Path "$basePath/tests/securityRegression" | Out-Null

$penetration = @(
    "sqlInjection.test.ts",
    "xss.test.ts",
    "csrf.test.ts",
    "authBypass.test.ts"
)

foreach ($file in $penetration) {
    New-Item -ItemType File -Force -Path "$basePath/tests/penetration/$file" | Out-Null
}

New-Item -ItemType File -Force -Path "$basePath/tests/fuzzing/fuzzInputs.test.ts" | Out-Null
New-Item -ItemType File -Force -Path "$basePath/tests/securityRegression/regressionSuite.test.ts" | Out-Null

# -------------------------------
# types/
# -------------------------------
$types = @(
    "security.types.ts",
    "auth.types.ts",
    "audit.types.ts",
    "tenant.types.ts"
)

New-Item -ItemType Directory -Force -Path "$basePath/types" | Out-Null
foreach ($file in $types) {
    New-Item -ItemType File -Force -Path "$basePath/types/$file" | Out-Null
}

# -------------------------------
# config/
# -------------------------------
$config = @(
    "csp.config.ts",
    "hsts.config.ts",
    "cors.config.ts",
    "rateLimit.config.ts",
    "auth.config.ts",
    "encryption.config.ts"
)

New-Item -ItemType Directory -Force -Path "$basePath/config" | Out-Null
foreach ($file in $config) {
    New-Item -ItemType File -Force -Path "$basePath/config/$file" | Out-Null
}

# -------------------------------
# cache/
# -------------------------------
$cache = @(
    "cacheIsolation.ts",
    "cacheEncryption.ts",
    "cachePolicies.ts"
)

New-Item -ItemType Directory -Force -Path "$basePath/cache" | Out-Null
foreach ($file in $cache) {
    New-Item -ItemType File -Force -Path "$basePath/cache/$file" | Out-Null
}

Write-Host "Security folder structure created successfully!"
