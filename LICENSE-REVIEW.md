# Licensing and release gate

This directory is a newly written implementation of a general-purpose single-password OpenConnect supervisor. No source files, company settings or Git history were copied into this project from the reference repository. The authoring process inspected the reference README and selected connection/health modules to understand its responsibilities; this is not a formal clean-room legal certification.

The reference README states “MIT License”, but a root LICENSE file was not available in the inspected snapshot. That statement alone is not treated here as proof of the rights to distribute all reference material.

Before public release, the rights holder must:

1. Confirm ownership/permission for this new code and any relevant employment or contribution obligations.
2. Verify the copyright attribution in LICENSE. The user selected MIT on 2026-11-11; LICENSE and package metadata now apply MIT to this implementation, with attribution “Copyright (c) 2026 xchen-zhao”. The account attribution is not independent verification of legal ownership.
3. Review the complete release tree for credentials and organization-specific information. Do not publish a private repository's history.
4. Observe the separate licenses of OpenConnect, vpnc-scripts and optional vpn-slice. They are invoked as external programs, not bundled here.
5. Validate against an authorized test VPN and document supported versions before claiming production compatibility.

The MIT selection does not establish rights to third-party code, waive employment/contribution obligations, or replace this pre-release review. External dependencies retain their own licenses.
