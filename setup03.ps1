# ============================================
#  GIT STRUCTURE INSIDE /git
#  Creates folders and files inside git/
# ============================================

$root = "git"

# Create main git folder
New-Item -ItemType Directory -Force -Path $root | Out-Null

# -------------------------------
# Root files inside git/
# -------------------------------
$rootFiles = @(
    ".gitignore",
    ".gitattributes",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    ".gitkeep"
)

foreach ($file in $rootFiles) {
    New-Item -ItemType File -Force -Path "$root/$file" | Out-Null
}

# -------------------------------
# Root folders inside git/
# -------------------------------
$rootFolders = @(
    ".github",
    "scripts",
    "docs",
    "src",
    "tests",
    "config",
    "public",
    "assets",
    "infra",
    "tools"
)

foreach ($folder in $rootFolders) {
    New-Item -ItemType Directory -Force -Path "$root/$folder" | Out-Null
}

# -------------------------------
# .github structure
# -------------------------------
New-Item -ItemType Directory -Force -Path "$root/.github/workflows" | Out-Null
New-Item -ItemType Directory -Force -Path "$root/.github/ISSUE_TEMPLATE" | Out-Null

# Workflow files
$workflowFiles = @(
    "ci.yml",
    "cd.yml",
    "security.yml"
)

foreach ($file in $workflowFiles) {
    New-Item -ItemType File -Force -Path "$root/.github/workflows/$file" | Out-Null
}

# Issue templates
$issueTemplates = @(
    "bug_report.md",
    "feature_request.md",
    "security_issue.md"
)

foreach ($file in $issueTemplates) {
    New-Item -ItemType File -Force -Path "$root/.github/ISSUE_TEMPLATE/$file" | Out-Null
}

# Pull request template
New-Item -ItemType File -Force -Path "$root/.github/PULL_REQUEST_TEMPLATE.md" | Out-Null

# -------------------------------
# Config files inside git/
# -------------------------------
$configFiles = @(
    ".editorconfig",
    ".prettierrc",
    ".eslintrc.json",
    "commitlint.config.js",
    ".npmrc",
    ".yarnrc",
    ".env.example"
)

foreach ($file in $configFiles) {
    New-Item -ItemType File -Force -Path "$root/$file" | Out-Null
}

Write-Host "Git folder structure created successfully inside /git!"
