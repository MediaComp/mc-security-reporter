=== MC Security Reporter ===
Requires at least: 6.4
Requires PHP: 8.1
Stable tag: 0.2.2

Read-only WordPress inventory for MC Security Monitor. Development version; not approved for live rollout.

== Description ==
Reports Core and all regular plugins/themes, including inactive components. Requires HTTPS and a site-specific header token. API starts disabled. Only a SHA-256 token hash is stored. It makes no outbound inventory requests or component updates. Mu-plugins, drop-ins and multisite are excluded.

Settings > MC Security Monitor provides generate/rotate/disable and explicit clone identity reset. Rotation immediately revokes the previous token. The plaintext token is shown once; reload before another action. Deactivation disables API and clears its token. Reactivation requires a new token. Uninstall deletes owned settings and identity. Reinstallation after uninstall creates a new identity.

== Development and operations ==
See the English repository documentation in docs/en/REPORTER.md. Do not deploy to real test/client/production sites before separate owner authorization. A reproducible runtime-only ZIP is built by scripts/build-plugin.py. Project code licensing remains an owner decision; no WordPress.org publication is authorized.

== Updates ==
WordPress checks public release metadata at https://raw.githubusercontent.com/MediaComp/mc-security-reporter/main/update.json when its normal plugin update checks run. Only stable packages from https://github.com/MediaComp/mc-security-reporter/releases are accepted. Downloads are bounded and checked against the published SHA-256 and size. This integrity check does not protect against compromise of the publishing account itself. The service receives the request IP and a generic plugin user agent; no site URL, inventory, inventory token or GitHub credential is sent by this updater. GitHub privacy statement: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement .

The updater uses native WordPress update UI and respects the site's automatic-update choices; it does not force updates. Hosting policy may disable installation or outbound requests. An update failure leaves the inventory credentials unchanged. Normal upgrades preserve site identity and token; explicit deactivation still revokes the token. Version 0.1.3 and earlier need one manual installation of a version containing the updater. No published release is assumed to exist until the owner explicitly enables publication.
