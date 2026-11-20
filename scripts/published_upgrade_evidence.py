"""Validate the saved process evidence for one published historical source."""
from published_upgrade_policy import DATABASE_DEV_CHECKPOINTS


def validate_upgrade_result(checks, *, tag, formal, upgrade_contract, candidate_sha256,
                            runtime_sha256, runtime_version, report_path, client2_sha256=None):
    assert isinstance(checks,list) and len(checks)==1,'expected one candidate upgrade report'
    check=checks[0]
    assert isinstance(check,dict) and all(check.get(name) is True for name in [
        'passed','real_model','distinct_vault_keys',
        'original_records_preserved','original_sync_work_preserved','urk_preserved',
        'old_records_decrypted','post_upgrade_recall_checked','encrypted_tombstones_preserved',
    ]),'required real upgrade checks missing or failed'
    assert check.get('seed_vault_versions')==[1,3] and all(type(value) is int for value in check['seed_vault_versions']), 'historical v1/v3 session coverage missing'
    if tag in DATABASE_DEV_CHECKPOINTS:
        checkpoint=check.get('database_dev_checkpoint')
        assert isinstance(checkpoint,dict) and checkpoint.get('tag')==tag \
            and checkpoint.get('special_state_seeded') is True \
            and checkpoint.get('special_state_preserved') is True \
            and checkpoint.get('verified_accounts')==['main','alternate'], 'database checkpoint-specific state was not verified'
        if upgrade_contract=='standalone-v1':
            assert checkpoint.get('post_sync_special_state_preserved') is True \
                and checkpoint.get('sync_verified_accounts')==['main'], 'database checkpoint state was not verified after real sync'
    assert check.get('historical_credential_migration_actor')=='fixture', 'explicit fixture credential migration missing'
    custody=check.get('host_credential_custody')
    assert isinstance(custody,dict) and custody.get('required') is True and custody.get('cleanup_passed') is True, 'historical credential custody or cleanup unconfirmed'
    accounts=custody.get('verified_accounts')
    assert isinstance(accounts,list) and len(accounts)==2 and all(isinstance(item,dict) for item in accounts), 'historical account custody evidence missing'
    assert [(item.get('account'),item.get('vault_version')) for item in accounts]==[('main',1),('alternate',3)], 'historical credential account coverage differs'
    assert all(item.get('urk_preserved') is True for item in accounts), 'historical credential custody changed a data key'
    cleanup=check.get('native_credential_cleanup')
    assert isinstance(cleanup,dict) and cleanup.get('passed') is True and cleanup.get('remaining_entries')==[], 'native credential cleanup unconfirmed'
    assert check.get('upgrade_contract')==upgrade_contract,'unknown, missing or incompatible upgrade contract'
    if upgrade_contract=='standalone-v1':
        assert all(check.get(name) is True for name in [
            'standalone_runtime_evidence','runtime_artifact_reused','normal_reopen_checked','stale_endpoint_archived',
        ]),'required standalone upgrade checks missing or failed'
        assert all(check.get(name) is False for name in [
            'old_rpc_checked','forced_restart_checked','live_owner_restart_rejected','safe_restart_checked',
            'supervised_worker_checked','in_process_checked','global_engine_preserved',
        ]),'database upgrade must not claim delegated host or legacy checks'
        assert check.get('legacy_handoff_actor') is None, 'database upgrade must not require a running legacy host'
        assert check.get('coverage_scope')=='historical-database', 'historical database coverage scope missing'
        assert check.get('host_checks_delegated_to')=='resident-concurrency', 'current host checks must remain in the resident fixture'
        assert check.get('post_upgrade_sync_checked') is True, 'historical schema synchronization or cleanup was not verified'
        sync=check.get('post_upgrade_sync')
        assert isinstance(sync,dict) and all(sync.get(field) is True for field in ('original_urk_preserved',
            'existing_keys_registered','source_push','independent_pull_decrypted','reverse_marker_source_pull',
            'original_active_preserved','tombstones_propagated','pending_work_acknowledged')), 'historical bidirectional sync evidence incomplete'
        assert isinstance(check.get('cloud_cleanup'),dict) and check['cloud_cleanup'].get('passed') is True \
            and check['cloud_cleanup'].get('remaining_users')==[], 'historical sync cloud cleanup unconfirmed'
        assert check.get('runtime_mode')=='standalone_runtime','standalone Runtime mode missing'
        assert check.get('runtime_binary_sha256')==runtime_sha256,'upgrade Runtime digest differs'
        assert check.get('runtime_version')==runtime_version,'upgrade Runtime version differs'
        receipts=check.get('runtime_identity_receipts')
        assert isinstance(receipts,list) and receipts and all(isinstance(item,dict) for item in receipts),\
            'upgrade Runtime identity receipts missing'
    else:
        assert all(check.get(name) is True for name in [
            'forced_restart_checked','old_rpc_checked','supervised_worker_checked','global_engine_preserved',
        ]),'required legacy shim upgrade checks missing or failed'
    assert check.get('binary_sha256')==candidate_sha256,'candidate changed during upgrade validation'
    assert check.get('client2_sha256')==client2_sha256,'desktop upgrade actor differs'
    if client2_sha256:
        assert check.get('client2_native_credential_migration') is True, 'desktop native credential migration was not exercised'
    assert check.get('engine')=='cpu','upgrade did not verify real CPU inference'
    sequence=check.get('sequence')
    assert isinstance(sequence,list) and [step['account'] for step in sequence]==['main','alternate','main'],'upgrade account sequence differs'
    for step in sequence:
        rows=step.get('model_rows')
        assert isinstance(rows,dict) and set(rows)=={'embedder','model index'} and all(
            row.get('status')=='ok' for row in rows.values()),'upgrade model readiness checks missing or failed'
    return {'version':tag[1:],'formal':formal,'passed':True,'upgrade_contract':upgrade_contract,
            'database_dev_checkpoint':check.get('database_dev_checkpoint'),
            'coverage_scope':check.get('coverage_scope'),
            'normal_reopen_checked':check.get('normal_reopen_checked') is True,
            'stale_endpoint_archived':check.get('stale_endpoint_archived') is True,
            'client2_sha256':check.get('client2_sha256'),
            'host_checks_delegated_to':check.get('host_checks_delegated_to'),
            'post_upgrade_sync_checked':check.get('post_upgrade_sync_checked') is True,
            'report':str(report_path)}
