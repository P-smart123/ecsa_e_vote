# Production acceptance and security checklist

## Must complete before a real election

- [ ] Implement a candidate photo delivery endpoint using an opaque candidate ID and R2 object lookup. The current starter upload route stores the photo key, but the public photo route is intentionally not yet wired into the frontend.
- [ ] Implement candidate editing controls in the admin interface and test that editing is blocked once the election starts.
- [ ] Add password reset/first-login password change. Surname passwords are guessable and should not be used for a real election.
- [ ] Add rate limiting and bot protection for registration and both login endpoints.
- [ ] Review CORS origin against the exact GitHub Pages origin.
- [ ] Add database backup/export and R2 retention procedures.
- [ ] Review vote receipt + ballot insertion transaction behavior against the current Cloudflare D1 runtime and perform simultaneous-request tests. Do not assume a UI disable is a security control.
- [ ] Have an independent reviewer inspect the secret-ballot model, database access, administrator controls and audit trail.
- [ ] Test that neither admin can access voter identity-to-candidate mappings. The schema separates receipts from ballots, but timing and privileged database access can still create correlation risk.
- [ ] Add accessible keyboard navigation, screen-reader labels and low-bandwidth image handling.
- [ ] Decide whether officials are allowed to vote as ordinary students; this starter does not grant admin sessions student voting rights.
- [ ] Decide whether election eligibility is restricted to a verified voter roll. The current registration endpoint accepts any unique matric number/email; it does not verify AAUA enrollment.
- [ ] Publish election dates, eligibility, dispute procedure, privacy notice and data-retention policy.

## Core tests

1. Unauthenticated user cannot call `/api/admin/*`.
2. Student session cannot call `/api/admin/*`.
3. Public cannot call `/api/setup-admin` without the setup secret.
4. Duplicate matric/email registration is rejected by database uniqueness constraints.
5. 11th candidate for a position is rejected server-side.
6. Candidate registration is blocked after voting begins.
7. Vote for a candidate outside the active election is rejected.
8. Duplicate voter-position receipt cannot be created.
9. Results remain hidden when configured as confidential and unpublished.
10. Audit events are recorded for administrative changes.
