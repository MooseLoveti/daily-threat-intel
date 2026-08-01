# Pull a completed daily brief into the local Obsidian vault.
# --ff-only refuses to overwrite local work or create an automatic merge.
$ErrorActionPreference = 'Stop'

$vaultRoot = Split-Path -Parent $PSScriptRoot
git -C $vaultRoot pull --ff-only --quiet
