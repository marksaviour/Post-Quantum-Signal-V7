# Copyright 2026 Mark Saviour Farrugia.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Executes one block of the Chapter 4.3 measurement schedule.
#
# One Criterion invocation per case, in the block's rotated order, with
# CRITERION_HOME pointed at evidence/criterion/ so each invocation's output
# lands in its own directory named for artefact, features, case, block,
# position, and machine. Every invocation is appended to a CSV log.
#
# Case names are passed to Criterion as anchored regexes, because an unanchored
# filter such as "initiate session and encrypt first message" also matches
# "initiate session and encrypt first message, last-resort only".
#
# Usage, from the repository root:
#   ./evidence/schedule/run-block.ps1 -Block 1 -Artefact v2
#
# -Artefact selects which cells are applicable to the tree currently checked
# out. Positions are numbered against the full 30-cell rotation, so they stay
# comparable when a block is executed in per-artefact passes.
#
# -RepoRoot runs the block against a tree other than the one holding this
# script, which is how the v1 and baseline worktrees are measured.

param(
    [ValidateRange(1, 5)][int]$Block = 1,
    [ValidateSet('v1', 'v2', 'baseline', 'all')][string]$Artefact = 'v2',
    [string]$Machine = $env:COMPUTERNAME,
    [string]$RepoRoot = ''
)

# Cargo writes progress to stderr, which PowerShell would treat as a terminating
# error under 'Stop'. Exit codes are checked explicitly instead.
$ErrorActionPreference = 'Continue'

$repoRoot = if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    Resolve-Path (Join-Path $PSScriptRoot '..\..')
} else {
    Resolve-Path $RepoRoot
}
Push-Location $repoRoot
try {
    # Cell table. Canonical order matches run-schedule.md.
    $cells = @(
        @{ Id = 'P01'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'HQC256_generate' }
        @{ Id = 'P02'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'HQC256_encapsulate' }
        @{ Id = 'P03'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'HQC256_decapsulate' }
        @{ Id = 'P04'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'MLKEM1024_generate' }
        @{ Id = 'P05'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'MLKEM1024_encapsulate' }
        @{ Id = 'P06'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'MLKEM1024_decapsulate' }
        @{ Id = 'P07'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'Kyber1024_generate' }
        @{ Id = 'P08'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'Kyber1024_encapsulate' }
        @{ Id = 'P09'; Artefact = 'v2'; Target = 'kem'; Features = 'hqc256 mlkem1024'; Case = 'Kyber1024_decapsulate' }
        @{ Id = 'P10'; Artefact = 'v2'; Target = 'mldsa'; Features = ''; Case = 'MLDSA87_generate' }
        @{ Id = 'P11'; Artefact = 'v2'; Target = 'mldsa'; Features = ''; Case = 'MLDSA87_sign' }
        @{ Id = 'P12'; Artefact = 'v2'; Target = 'mldsa'; Features = ''; Case = 'MLDSA87_verify' }
        @{ Id = 'C1'; Artefact = 'baseline'; Target = 'classical'; Features = ''; Case = 'X25519_generate' }
        @{ Id = 'C2'; Artefact = 'baseline'; Target = 'classical'; Features = ''; Case = 'X25519_agree' }
        @{ Id = 'C3'; Artefact = 'baseline'; Target = 'classical'; Features = ''; Case = 'XEdDSA_sign' }
        @{ Id = 'C4'; Artefact = 'baseline'; Target = 'classical'; Features = ''; Case = 'XEdDSA_verify' }
        @{ Id = 'H2a'; Artefact = 'v2'; Target = 'session'; Features = ''; Case = 'initiate session and encrypt first message' }
        @{ Id = 'H2b'; Artefact = 'v2'; Target = 'session'; Features = ''; Case = 'initiate session and encrypt first message, last-resort only' }
        @{ Id = 'H2c'; Artefact = 'v2'; Target = 'session'; Features = ''; Case = 'session decrypt first message, full mode' }
        @{ Id = 'H2d'; Artefact = 'v2'; Target = 'session'; Features = ''; Case = 'session decrypt first message, last-resort only' }
        @{ Id = 'H1a'; Artefact = 'v1'; Target = 'session'; Features = ''; Case = 'initiate session and encrypt first message' }
        @{ Id = 'H1b'; Artefact = 'v1'; Target = 'session'; Features = ''; Case = 'initiate session and encrypt first message, last-resort only' }
        @{ Id = 'H1c'; Artefact = 'v1'; Target = 'session'; Features = ''; Case = 'session decrypt first message, full mode' }
        @{ Id = 'H1d'; Artefact = 'v1'; Target = 'session'; Features = ''; Case = 'session decrypt first message, last-resort only' }
        @{ Id = 'B1'; Artefact = 'baseline'; Target = 'baseline_pqxdh'; Features = ''; Case = 'baseline initiate session and encrypt first message' }
        @{ Id = 'B2'; Artefact = 'baseline'; Target = 'baseline_pqxdh'; Features = ''; Case = 'baseline initiate session and encrypt first message, no one-time curve key' }
        @{ Id = 'B3'; Artefact = 'baseline'; Target = 'baseline_pqxdh'; Features = ''; Case = 'baseline decrypt first message' }
        @{ Id = 'I1'; Artefact = 'v1';       Target = 'session';        Features = ''; Case = 'session establishment and first exchange' }
        @{ Id = 'I2'; Artefact = 'v2';       Target = 'session';        Features = ''; Case = 'session establishment and first exchange' }
        @{ Id = 'IB'; Artefact = 'baseline'; Target = 'baseline_pqxdh'; Features = ''; Case = 'baseline session establishment and first exchange' }
    )

    # Rotate left by 5 * (Block - 1), wrapping at the cell count.
    $offset = (5 * ($Block - 1)) % $cells.Count
    $rotated = @()
    for ($i = 0; $i -lt $cells.Count; $i++) {
        $rotated += $cells[($i + $offset) % $cells.Count]
    }

    $commit = (git rev-parse HEAD).Trim()
    $dirty = -not [string]::IsNullOrWhiteSpace((git status --porcelain))
    $commitLabel = if ($dirty) { "$commit (working tree dirty)" } else { $commit }
    $branch = (git rev-parse --abbrev-ref HEAD).Trim()

    # The output directory is not tracked, so it may be absent on a fresh clone.
    $criterionRoot = Join-Path $repoRoot 'evidence\criterion'
    if (-not (Test-Path $criterionRoot)) {
        New-Item -ItemType Directory -Force -Path $criterionRoot | Out-Null
    }

    $logPath = Join-Path $criterionRoot 'run-log.csv'
    if (-not (Test-Path $logPath)) {
        'timestamp,machine,block,position,cell_id,artefact,branch,harness_commit,features,target,case,command,exit_code,output_dir' |
            Out-File -FilePath $logPath -Encoding utf8
    }

    Write-Host "Block $Block, artefact filter '$Artefact', machine '$Machine'"
    Write-Host "Harness commit: $commitLabel"
    if ($dirty) {
        Write-Warning 'Working tree is dirty. Chapter 4 admits results only from a clean harness commit; treat this run as provisional.'
    }

    $position = 0
    foreach ($cell in $rotated) {
        $position++
        if ($Artefact -ne 'all' -and $cell.Artefact -ne $Artefact) { continue }

        $outputName = "{0}_block{1}_pos{2:d2}_{3}_{4}" -f $Machine, $Block, $position, $cell.Id, $cell.Target
        $outputDir = Join-Path $repoRoot "evidence\criterion\$outputName"

        $featureArgs = if ([string]::IsNullOrWhiteSpace($cell.Features)) { @() } else { @('--features', $cell.Features) }
        $filter = '^' + [regex]::Escape($cell.Case) + '$'
        $cargoArgs = @('bench', '-p', 'libsignal-protocol') + $featureArgs + @('--bench', $cell.Target, '--', $filter)
        $commandText = 'cargo ' + ($cargoArgs -join ' ')

        Write-Host ("[{0}/{1}] pos {2} {3}: {4}" -f $position, $rotated.Count, $position, $cell.Id, $cell.Case)

        $env:CRITERION_HOME = $outputDir
        & cargo @cargoArgs 2>&1 | Tee-Object -FilePath (Join-Path $repoRoot "evidence\criterion\$outputName.log")
        $exit = $LASTEXITCODE
        Remove-Item Env:\CRITERION_HOME -ErrorAction SilentlyContinue

        $row = [pscustomobject]@{
            timestamp      = (Get-Date).ToString('o')
            machine        = $Machine
            block          = $Block
            position       = $position
            cell_id        = $cell.Id
            artefact       = $cell.Artefact
            branch         = $branch
            harness_commit = $commitLabel
            features       = $cell.Features
            target         = $cell.Target
            case           = $cell.Case
            command        = $commandText
            exit_code      = $exit
            output_dir     = "evidence/criterion/$outputName"
        }
        ($row | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1) |
            Out-File -FilePath $logPath -Encoding utf8 -Append

        if ($exit -ne 0) { Write-Warning "$($cell.Id) exited with $exit" }
    }

    Write-Host "Block $Block complete. Log: evidence/criterion/run-log.csv"
}
finally {
    Remove-Item Env:\CRITERION_HOME -ErrorAction SilentlyContinue
    Pop-Location
}
