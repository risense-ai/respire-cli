"""Branch-only command receipt; never emit product responses or credential text."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


REASONS = frozenset({
    'runtime_error', 'invalid_input', 'request_outcome_unknown', 'runtime_unavailable',
    'runtime_locked', 'locked', 'key_required', 'memory_off', 'not_installed',
    'model_not_ready', 'model_preparation_failed', 'unsupported', 'outcome_unknown',
})
ERROR_TYPES = frozenset({
    'runtime', 'user', 'outcome_unknown', 'identity_write_recovery_required',
    'handoff_pending', 'configuration', 'network', 'model', 'locked',
})
# Only fixed source-backed markers may leave captured stdout/stderr.
MARKERS = {
    'host_runtime_exited_before_readiness': 'host runtime exited before readiness',
    'host_runtime_not_ready': 'host runtime did not become ready',
    'runtime_locked': 'supply private key material from the CLI or Client2 before accessing the library',
    'compatibility_host_startup_failed': 'owned compatibility host startup failed',
    'compatibility_startup_pipe_failed': 'compatibility startup pipe failed',
    'owned_runtime_exited_before_readiness': 'owned Runtime exited before readiness',
    'runtime_readiness_uncertain': 'Runtime readiness is uncertain',
    'runtime_readiness_identity_mismatch': 'Runtime readiness does not match the selected child and installation',
    'runtime_credential_confirmation': 'Runtime credential confirmation',
    'host_plugin_channel_closed': 'host plugin channel closed',
    'host_plugin_parent_channel_closed': 'host plugin parent channel closed',
    'private_model_plan_rejected': 'private Runtime model plan was rejected',
    'runtime_drain_failed': 'runtime drain stop request failed',
    'runtime_roots_mismatch': 'owner roots do not match this installation',
    'runtime_start_identity_mismatch': 'runtime process start identity does not match health',
    'windows_file_not_found': 'os error 2',
    'windows_path_not_found': 'os error 3',
    'windows_access_denied': 'os error 5',
    'windows_invalid_image': 'os error 193',
    'windows_missing_module': 'os error 126',
    'windows_connection_refused': 'os error 10061',
}
STAGES = frozenset({
    'runtime_install', 'model_install_m3', 'runtime_stop',
    'copy_tokenizer', 'copy_quantized_model', 'copy_cpu_container',
    'download_legacy_fp16', 'verify_model_bytes',
})


def environment_receipt():
    home = Path(os.environ['HOME'])
    profile = Path(os.environ['USERPROFILE'])
    root = Path(os.environ['RSRS_DATA_DIR'])
    installed = root / 'bin/runtime.json'
    result = {
        'home_absolute': home.is_absolute(),
        'home_exists': home.is_dir(),
        'home_userprofile_same': home.resolve() == profile.resolve(),
        'home_under_runner_temp': home.resolve().is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve()),
        'data_under_runner_temp': root.resolve().is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve()),
        'runtime_override_present': bool(os.environ.get('RSRS_RUNTIME_BIN')),
        'cpu_environment_selected': os.environ.get('RSRS_ENGINE') == 'cpu',
        'private_key_environment_present': any(
            os.environ.get(prefix + suffix)
            for prefix in ('RSRS_', 'ONEMEMORY_', 'RESPIRE_')
            for suffix in ('SUPER', 'SECRET', 'WRAPPED_URK')),
        'database_present': (root / 'rsrs.db').is_file(),
        'session_present': (root / 'session.json').is_file(),
        'managed_manifest_present': installed.is_file(),
    }
    if installed.is_file():
        try:
            manifest = json.loads(installed.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError):
            result['managed_manifest_state'] = 'invalid_json'
        else:
            result['managed_manifest_state'] = 'parsed'
            result['managed_version_matches'] = manifest.get('version') == os.environ['NATIVE_RUNTIME_VERSION']
            binary = root / 'bin/runtime' / os.environ['NATIVE_RUNTIME_VERSION'] / 'rsrs-runtime.exe'
            result['managed_binary_present'] = binary.is_file()
            if binary.is_file():
                with binary.open('rb') as stream:
                    result['managed_binary_matches'] = hashlib.file_digest(stream, 'sha256').hexdigest() == os.environ['NATIVE_RUNTIME_SHA256']
    return result


def cpu_receipt_checks(response):
    if not isinstance(response, dict):
        return {'receipt_shape_valid': False}
    try:
        details = response['details']
        assets = details['assets']
        backend = details['backend_load']
        evidence = backend['evidence']
        hashes = {
            'bge-m3-tokenizer': '6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790',
            'bge-m3-cpu-ort': '7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff',
        }
        return {
            'status_ok': response['status'] == 'ok',
            'assets_complete': details['complete'] is True and details['missing'] == [],
            'exact_cpu_assets': len(assets) == len(hashes) and {a['name'] for a in assets} == set(hashes),
            'asset_hashes_verified': all(a['state'] == 'complete' and a['sha256'] == hashes[a['name']]
                and a['actual_sha256'] == hashes[a['name']] for a in assets),
            'backend_loaded': backend['state'] == 'loaded' and backend.get('reason') is None,
            'contract_verified': evidence['contract'] == 1 and evidence['status'] == 'loaded',
            'cpu_selected': evidence['engine'] == 'cpu' and evidence['selected'] == 'CPU'
                and evidence['backend'] == 'onnx' and evidence['provider'] == 'CPUExecutionProvider',
            'fresh_inference_completed': evidence['ready'] is True and evidence['fresh_session'] is True
                and evidence['inference_completed'] is True and evidence['dimensions'] == 1024,
        }
    except (KeyError, TypeError):
        return {'receipt_shape_valid': False}


def main():
    stage, *command = sys.argv[1:]
    if stage not in STAGES or not command:
        raise ValueError('Unknown preparation stage or missing command')
    path = Path('db-model-preparation.json')
    report = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {'diagnostic_only': True, 'commands': []}
    if any(row['stage'] == stage for row in report['commands']):
        raise ValueError('Preparation stage must not be replayed')
    row = {'stage': stage, 'direct_forwarding_requested': '--direct' in command, 'before': environment_receipt()}
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        row.update(exit_code=None, launch_errno=error.errno, result='launch_failed')
        exit_code = 1
    else:
        exit_code = completed.returncode
        row.update(exit_code=exit_code, result='ok' if exit_code == 0 else 'failed')
        try:
            response = json.loads(completed.stdout)
        except (ValueError, UnicodeError):
            row['response_shape'] = 'not_json'
            if stage == 'model_install_m3' and exit_code == 0:
                row.update(result='receipt_validation_failed', receipt_shape_valid=False)
                exit_code = 1
        else:
            row['response_shape'] = 'object' if isinstance(response, dict) else 'not_object'
            if isinstance(response, dict):
                for parent, key, allowed in [('summary', 'reason', REASONS), ('details', 'error_type', ERROR_TYPES)]:
                    container = response.get(parent)
                    if isinstance(container, dict) and key in container:
                        value = container[key]
                        row[key] = value if isinstance(value, str) and value in allowed else 'not_allowlisted'
                status = response.get('status')
                if status in ('ok', 'warn', 'fail', 'skip'):
                    row['status'] = status
            if stage == 'model_install_m3' and exit_code == 0:
                row['cpu_receipt_checks'] = cpu_receipt_checks(response)
                if not all(row['cpu_receipt_checks'].values()) or os.environ.get('RSRS_ENGINE') != 'cpu':
                    row['result'] = 'receipt_validation_failed'
                    exit_code = 1
        text = (completed.stdout + completed.stderr).decode('utf-8', errors='replace')
        row['error_markers'] = [name for name, marker in MARKERS.items() if marker in text]
        if row['result'] == 'receipt_validation_failed':
            row['error_class'] = 'cpu_preparation_receipt_invalid'
        elif exit_code != 0 and not row['error_markers']:
            row['error_class'] = 'unclassified_command_failure'
    row['after'] = environment_receipt()
    report['commands'].append(row)
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(row, sort_keys=True), flush=True)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
