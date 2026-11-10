#!/usr/bin/env python3
"""Offline source-order and fail-closed wiring tests; PowerShell execution is separate."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent


def validate(sweep, profile):
    validator = profile.split('fn profile_dir(', 1)[1].split('\nfn switch_profile', 1)[0]
    assert validator.index('anyhow::ensure!') < validator.index('config::control_roots()?')
    use = profile.split('fn account_use(', 1)[1].split('\npub(crate) fn ', 1)[0]
    assert use.index('profile_dir(name)?') < use.index('switch_profile(name, &dir, true)?')
    space = profile.split('fn space_use(', 1)[1].split('\npub(crate) fn ', 1)[0]
    assert space.index('std::fs::metadata(&dir)') < space.index('switch_profile(name, &dir, false)?')
    assert space.index('return Err(respire_client_host::input_error::InputError') < space.index('switch_profile(name, &dir, false)?')
    space_assertion = next(x for x in sweep.splitlines() if x.startswith("Assert-Smoke 'space-live-rejected-restores-service'"))
    for term in ('Test-RuntimeUnchanged', '$spaceRejectedReadback.Ok', 'entry.id -ceq $spaceEntryId', 'entry.content -ceq $spaceMarker', '-ceq $spaceRejectionSnapshot', '$spaceRejected.Exit -eq 2', 'invalid_input', 'error_type', '-not (Test-Path'):
        assert term in space_assertion
    assert 'Test-RuntimeChanged' not in space_assertion and '-or' not in space_assertion
    for name in ('space-live-main-takeover', 'space-live-return-takeover'):
        assert 'Test-RuntimeChanged' in next(x for x in sweep.splitlines() if x.startswith(f"Assert-Smoke '{name}'"))
    helper = sweep.split('function Test-RuntimeUnchanged(', 1)[1].split('\nfunction ', 1)[0]
    for field in ('pid', 'data_dir', 'account_id', 'instance_id', 'generation', 'exe', 'bin', 'runtime_version'):
        assert f'$Before.{field}' in helper and f'$After.{field}' in helper
    assert '-or' not in helper
    assert '$Before.store_ready -eq $true -and $After.store_ready -eq $true' in helper
    assert 'Get-Process -Id ([int]$Before.pid)' in helper
    assertion = next(x for x in sweep.splitlines() if x.startswith("Assert-Smoke 'account-live-rejected-restores-service'"))
    for term in ('Test-RuntimeUnchanged', '$rejectedStatus.Ok', 'session.user -ceq $otherUser', 'summary.unlocked -eq $true', 'Get-AccountRejectionSnapshot', '-ceq $rejectionSnapshot', '-ceq [Convert]::ToBase64String($profileConfig)'):
        assert term in assertion
    assert 'Test-RuntimeChanged' not in assertion and '-or' not in assertion
    assert sweep.index("-Name 'account-live-rejected-status-readback'") < sweep.index('$rejectedHealth = Get-OwnedRuntimeHealth')
    for name in ('account-live-main-takeover','account-live-shorthand-takeover','account-live-restore-main-takeover','config-live-profile-takeover','config-live-restore-main-takeover'):
        assert 'Test-RuntimeChanged' in next(x for x in sweep.splitlines() if x.startswith(f"Assert-Smoke '{name}'"))


class RejectionSourceTests(unittest.TestCase):
    def setUp(self):
        self.sweep = (ROOT / 'scripts/dev-release-sweep.ps1').read_text()
        self.profile = (ROOT / 'cli/src/profile_control.rs').read_text()

    def test_source_and_gates(self):
        validate(self.sweep, self.profile)

    def test_identity_and_readiness_gate_mutations(self):
        for token in ('$Before.pid', '$After.data_dir', '$After.account_id', '$After.instance_id', '$After.generation', '$After.exe', '$After.bin', '$After.runtime_version', '$After.store_ready', '$rejectedStatus.Ok', 'summary.unlocked -eq $true', '-ceq $rejectionSnapshot', '$spaceRejectedReadback.Ok', 'entry.id -ceq $spaceEntryId', 'entry.content -ceq $spaceMarker', '-ceq $spaceRejectionSnapshot'):
            with self.subTest(token=token), self.assertRaises(AssertionError):
                validate(self.sweep.replace(token, 'REMOVED'), self.profile)

    def test_rotation_regression(self):
        with self.assertRaises(AssertionError):
            validate(self.sweep.replace('(Test-RuntimeUnchanged $switchedHealth', '(Test-RuntimeChanged $switchedHealth'), self.profile)

    def test_workflow_runs_actual_powershell_contract(self):
        self.assertIn('& ./scripts/test-account-rejection-contract.ps1', (ROOT / '.github/workflows/ci.yml').read_text())


if __name__ == '__main__':
    unittest.main()
