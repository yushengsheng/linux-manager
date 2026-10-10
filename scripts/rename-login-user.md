# In-place Linux login rename

`rename-login-user.sh` changes an existing account's login name and password;
it does not create a second administrator. It preserves the account's UID,
supplementary groups, home contents, SSH authorized keys, and sudo rights.

Run it on the server as root:

```bash
sudo bash rename-login-user.sh
```

Or prefill only the non-secret names:

```bash
sudo bash rename-login-user.sh --old-user ubuntu --new-user your_new_name
```

It then prompts for the current password, a new password, and confirmation. It
keeps a root-only backup under `/root/account-rename-backups/` before changing
account or SSH/cloud-init configuration.

When invoked over SSH, the tool schedules a short-lived root systemd task. It
then closes the old account's session before calling `usermod`; this is needed
because Linux refuses to rename an account that owns an active SSH process.
The GUI waits and verifies the new SSH login automatically.

For macOS, double-click `run_rename_account.command` in this folder. Its GUI
uses the recovery SSH key and passes passwords through standard input, never
in an SSH command line. The `打开服务器终端` button opens Terminal and connects
using the currently selected SSH account and recovery key. The GUI stores only
the host, SSH username, and key path in an owner-only local state file; it never
stores either account password.

After the command completes, verify a fresh SSH login using the new account
name before ending the existing session. The script requires a minimum
16-character new password and refuses to rename `root` or overwrite an
existing user or group.

This tool is intended for the Ubuntu server audited in this session. It makes
no changes to x-ui, Xray, or proxy port 30043.
