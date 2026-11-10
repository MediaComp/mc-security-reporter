Version 0.2.1

- Preserves explicit no-store headers through WordPress 6.4 AJAX termination, including anonymous credential-action errors with PHP output buffering enabled.

- Integrates public stable releases with native WordPress update checks and plugin details.
- Downloads only version-specific packages from the dedicated release repository, with bounded redirects, size and SHA-256 validation.
- Respects WordPress automatic-update settings; no forced updates.
- Normal upgrades preserve site UUID, token hash, enabled API state and rotation timestamp.
- No inventory data, inventory credentials, site URLs or GitHub credentials are sent by the updater.
- Versions before 0.2.0 require one manual installation to acquire the updater.
