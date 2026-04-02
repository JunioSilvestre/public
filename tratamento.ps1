# Cria estrutura base dentro de /src/utils

# Base path

$basePath = "src/utils"

# Lista de pastas

$folders = @(
"$basePath/format",
"$basePath/validation",
"$basePath/mask",
"$basePath/parse",
"$basePath/sanitize",
"$basePath/constants",
"$basePath/helpers",
"$basePath/guards",
"$basePath/transform"
)

# Criar pastas

foreach ($folder in $folders) {
New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

# =========================

# FORMAT

# =========================

New-Item "$basePath/format/document.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/format/date.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/format/number.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/format/currency.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/format/string.ts" -ItemType File -Force | Out-Null

# =========================

# VALIDATION

# =========================

New-Item "$basePath/validation/document.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/validation/email.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/validation/password.ts" -ItemType File -Force | Out-Null

# =========================

# MASK

# =========================

New-Item "$basePath/mask/document.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/mask/phone.ts" -ItemType File -Force | Out-Null

# =========================

# PARSE

# =========================

New-Item "$basePath/parse/number.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/parse/date.ts" -ItemType File -Force | Out-Null

# =========================

# SANITIZE

# =========================

New-Item "$basePath/sanitize/string.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/sanitize/html.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/sanitize/object.ts" -ItemType File -Force | Out-Null

# =========================

# CONSTANTS

# =========================

New-Item "$basePath/constants/regex.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/constants/format.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/constants/limits.ts" -ItemType File -Force | Out-Null

# =========================

# HELPERS

# =========================

New-Item "$basePath/helpers/debounce.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/helpers/throttle.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/helpers/deepClone.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/helpers/generateId.ts" -ItemType File -Force | Out-Null

# =========================

# GUARDS

# =========================

New-Item "$basePath/guards/isString.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/guards/isNumber.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/guards/isObject.ts" -ItemType File -Force | Out-Null

# =========================

# TRANSFORM

# =========================

New-Item "$basePath/transform/apiToClient.ts" -ItemType File -Force | Out-Null
New-Item "$basePath/transform/clientToApi.ts" -ItemType File -Force | Out-Null

Write-Host "Estrutura de utils criada com sucesso dentro de /src/utils" -ForegroundColor Green
