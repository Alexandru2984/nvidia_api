#!/usr/bin/python3
"""Detect high-signal AI Chat Hub security/backup conditions and alert Telegram.

The monitor sends only fixed event names and counts. It never forwards log lines,
IP addresses, usernames, prompts, credentials, or attachment names.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DUMP_RE = re.compile(r'^nvidia_db_\d{8}_\d{6}(?:_\d+)?\.sql\.gz$')
BACKUP_MAX_AGE_SECONDS = 30 * 60 * 60
RESTORE_MAX_AGE_SECONDS = 8 * 24 * 60 * 60
JOURNAL_WINDOW = '6 minutes ago'


def read_journal():
    result = subprocess.run(
        ['journalctl', '--unit=aichat-backend.service', '--unit=aichat-maintenance.service',
         f'--since={JOURNAL_WINDOW}',
         '--output=cat', '--no-pager', '--quiet'],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if result.returncode:
        raise RuntimeError('journal query failed')
    return result.stdout


def evaluate(backup_dir, restore_log, journal, now=None):
    now = now or time.time()
    issues = {}
    backup_dir = Path(backup_dir)
    restore_log = Path(restore_log)

    if not backup_dir.is_dir() or backup_dir.is_symlink():
        issues['backup_missing'] = 'Backup directory is missing or unsafe.'
    else:
        if stat.S_IMODE(backup_dir.stat().st_mode) & 0o077:
            issues['backup_directory_permissions'] = 'Backup directory has group/other permissions.'
        dumps = [path for path in backup_dir.iterdir()
                 if DUMP_RE.fullmatch(path.name) and path.is_file() and not path.is_symlink()]
        if not dumps:
            issues['backup_missing'] = 'No valid database backup was found.'
        else:
            latest = max(dumps, key=lambda path: path.stat().st_mtime)
            info = latest.stat()
            age_hours = max(0, int((now - info.st_mtime) // 3600))
            if now - info.st_mtime > BACKUP_MAX_AGE_SECONDS:
                issues['backup_stale'] = f'Newest database backup is {age_hours} hours old.'
            if stat.S_IMODE(info.st_mode) & 0o077:
                issues['backup_permissions'] = 'Newest database backup has group/other permissions.'

    if not restore_log.is_file() or restore_log.is_symlink():
        issues['restore_missing'] = 'No successful restore-drill log was found.'
    else:
        info = restore_log.stat()
        age_days = max(0, int((now - info.st_mtime) // 86400))
        if now - info.st_mtime > RESTORE_MAX_AGE_SECONDS:
            issues['restore_stale'] = f'Last restore drill is {age_days} days old.'
        try:
            tail = restore_log.read_text(encoding='utf-8', errors='replace')[-4096:]
        except OSError:
            tail = ''
        lines = [line for line in tail.splitlines() if line.strip()]
        if not lines or 'restore drill ok:' not in lines[-1]:
            issues['restore_failed'] = 'Latest restore-drill log has no success marker.'
        if stat.S_IMODE(info.st_mode) & 0o077:
            issues['restore_log_permissions'] = 'Restore-drill log has group/other permissions.'

    auth_failures = journal.count('event=auth_failed')
    rate_limits = journal.count('event=rate_limit')
    admin_denied = journal.count('event=admin_access_denied')
    admin_changes = journal.count('event=admin_change')
    unmetered_usage = journal.count('event=ai_usage_unmetered')
    token_overruns = journal.count('event=ai_token_reservation_exceeded')
    invite_rejections = journal.count('event=registration_invite_rejected')
    invite_consumed = journal.count('event=registration_invite_consumed')
    registrations_verified = journal.count('event=registration_verified')
    internal_errors = journal.count('Internal Server Error:') + journal.count('[ERROR]')
    if auth_failures >= int(os.environ.get('AUTH_FAILURE_ALERT_THRESHOLD', '10')):
        issues['auth_burst'] = f'{auth_failures} failed logins were detected in six minutes.'
    if rate_limits >= int(os.environ.get('RATE_LIMIT_ALERT_THRESHOLD', '20')):
        issues['rate_limit_burst'] = f'{rate_limits} rate-limit events were detected in six minutes.'
    if admin_denied >= int(os.environ.get('ADMIN_DENIED_ALERT_THRESHOLD', '10')):
        issues['admin_probe_burst'] = f'{admin_denied} denied admin requests were detected in six minutes.'
    if 'event=admin_access ' in journal or 'event=admin_login ' in journal:
        issues['admin_access'] = 'A successful Django admin access was detected.'
    if admin_changes:
        issues['admin_change'] = f'{admin_changes} privileged admin changes were detected.'
    if 'event=admin_audit_integrity_failed' in journal:
        issues['admin_audit_integrity'] = 'The privileged-change audit trail failed integrity checks.'
    if 'event=two_factor_disabled' in journal:
        issues['two_factor_disabled'] = 'Two-factor authentication was disabled for an account.'
    if 'event=ai_budget_blocked scope=global' in journal:
        issues['global_budget'] = 'The service-wide daily AI budget was exhausted.'
    if unmetered_usage >= int(os.environ.get('UNMETERED_USAGE_ALERT_THRESHOLD', '3')):
        issues['unmetered_ai_usage'] = (
            f'{unmetered_usage} AI calls had no valid provider usage in six minutes.'
        )
    if token_overruns:
        issues['token_reservation_overrun'] = (
            f'{token_overruns} AI calls exceeded their token reservation in six minutes.'
        )
    if invite_rejections >= int(os.environ.get('INVITE_REJECTION_ALERT_THRESHOLD', '5')):
        issues['invite_rejection_burst'] = (
            f'{invite_rejections} invalid invitation attempts were detected in six minutes.'
        )
    if invite_consumed:
        issues['registration_invite_consumed'] = (
            f'{invite_consumed} registration invitations were consumed in six minutes.'
        )
    if registrations_verified:
        issues['registration_verified'] = (
            f'{registrations_verified} new accounts completed verification in six minutes.'
        )
    if internal_errors >= int(os.environ.get('INTERNAL_ERROR_ALERT_THRESHOLD', '3')):
        issues['error_burst'] = f'{internal_errors} backend errors were detected in six minutes.'
    return issues


def parse_monitor_credentials(path):
    wanted = {'BOT_TOKEN', 'CHAT_ID'}
    values = {}
    for raw in Path(path).read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if key not in wanted:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    if not values.get('BOT_TOKEN') or not values.get('CHAT_ID'):
        raise RuntimeError('monitor notification credentials are missing')
    return values


def send_telegram(credentials_path, text):
    credentials = parse_monitor_credentials(credentials_path)
    data = urllib.parse.urlencode({
        'chat_id': credentials['CHAT_ID'],
        'text': text,
        'disable_web_page_preview': 'true',
    }).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{credentials['BOT_TOKEN']}/sendMessage",
        data=data,
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError('notification service returned a non-200 response')
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'notification service returned HTTP {exc.code}') from None
    except urllib.error.URLError:
        raise RuntimeError('notification service could not be reached') from None


def load_state(path):
    try:
        if path.is_symlink():
            raise RuntimeError('monitor state must not be a symlink')
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise TypeError
        return data
    except FileNotFoundError:
        return {'active': [], 'last_sent': {}}
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError('monitor state is invalid') from None


def save_state(path, state):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode='w', encoding='utf-8', dir=path.parent, prefix='.state.', delete=False,
    ) as handle:
        json.dump(state, handle, sort_keys=True)
        handle.write('\n')
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    temporary.replace(path)


def alert_text(issues, resolved=False):
    title = 'AI Chat Hub security monitor recovered' if resolved else 'AI Chat Hub security alert'
    lines = [title, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')]
    lines.extend(f'- {key}: {value}' for key, value in sorted(issues.items()))
    lines.append('Runbook: /home/micu/nvidia/docs/INCIDENT_RESPONSE.md')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--test-notification', action='store_true')
    parser.add_argument('--backup-dir', default='/home/micu/backups/nvidia_db')
    parser.add_argument('--restore-log', default='/home/micu/backups/nvidia_db/restore-drill.log')
    parser.add_argument('--journal-file')
    parser.add_argument('--state-dir', default='/var/lib/aichat-security-monitor')
    parser.add_argument('--credentials', default='/home/micu/scripts/.env')
    args = parser.parse_args()

    try:
        if args.test_notification:
            text = (
                'AI Chat Hub security monitor test\n'
                + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                + '\nNotification path is working; no incident is declared.'
            )
            send_telegram(args.credentials, text)
            print('test notification sent')
            return 0
        journal = Path(args.journal_file).read_text(encoding='utf-8') if args.journal_file else read_journal()
        issues = evaluate(args.backup_dir, args.restore_log, journal)
        if args.dry_run:
            print(json.dumps(issues, indent=2, sort_keys=True))
            return 1 if issues else 0

        state_path = Path(args.state_dir) / 'state.json'
        state = load_state(state_path)
        previous = set(state.get('active', []))
        last_sent = state.get('last_sent', {})
        now = int(time.time())
        cooldown = int(os.environ.get('ALERT_COOLDOWN_SECONDS', '1800'))
        notify = {
            key: message for key, message in issues.items()
            if key not in previous or now - int(last_sent.get(key, 0)) >= cooldown
        }
        resolved_keys = previous - set(issues)

        if notify:
            send_telegram(args.credentials, alert_text(notify))
            for key in notify:
                last_sent[key] = now
        if resolved_keys:
            resolved = {key: 'Condition is no longer present.' for key in resolved_keys}
            send_telegram(args.credentials, alert_text(resolved, resolved=True))

        state['active'] = sorted(issues)
        state['last_sent'] = last_sent
        save_state(state_path, state)
        return 0
    except Exception as exc:  # noqa: BLE001 - final CLI boundary must fail closed
        print(f'security monitor failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
