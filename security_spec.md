# ECSA Online E-Voting Security Specification (Phase 0 TDD)

## 1. Data Invariants

1. **Identity & Role Integrity**: Only verified users (`request.auth != null && request.auth.token.email_verified == true`) can write to Firestore. Only bootstrapped administrators (`progressgodson3@gmail.com`, `psmartprogress@gmail.com`) or active records in `/admins/{uid}` (`president`, `election_chairman`) can manage elections, positions, candidates, eligible voters, or view audit logs. Students cannot self-register as administrators.
2. **PII Isolation**: Student profiles (`/students/{uid}`) contain PII (`email`, `matric`, `fullName`) and are readable ONLY by the document owner (`uid == request.auth.uid`) or an active administrator. Blanket `list` on `/students` is forbidden for non-admins.
3. **Unique Student Credentials**: No two students can claim the same 9-digit matriculation number (`/matricIndex/{matric}`) or email hash (`/emailIndex/{emailHash}`). Creation must occur atomically alongside `/students/{uid}`.
4. **Maximum 10 Aspirants Per Position**: Every `/positions/{positionId}` enforces `0 <= candidateCount <= 10`. Creating a candidate atomically increments `candidateCount` by 1 and fails if the resulting count exceeds 10. Candidates can only be added, edited, or deleted while the parent election has `status == 'not_started'`.
5. **One Vote Per Student Per Position & Secret Ballot Separation**:
   - `/voteReceipts/{electionId}_{positionId}_{voterUid}` stores no `candidateId`, is immutable (`update/delete: false`), and can only be created once when election `status == 'ongoing'` by a registered non-admin student.
   - `/tallies/{candidateId}` can ONLY be incremented by `+1` atomically in the same transaction that creates the voter's `/voteReceipts` document. Administrators cannot modify vote counts (`votes`, `affirmVotes`, `rejectVotes`), only `resultsVisible`.
   - `/ballots/{ballotId}` stores no `voterUid`, `matric`, or `email`, is immutable (`update/delete: false`), and can only be created atomically alongside a new `/voteReceipts` document.
6. **Confidentiality of Unpublished Results**: `/tallies/{candidateId}` is readable by non-admins ONLY when `resource.data.resultsVisible == true`.
7. **Temporal & Schema Integrity**: Every create/update validates strict keys (`hasAll` + `hasOnly` / `affectedKeys().hasOnly()`), strict string size bounds, regex patterns, immutable fields, and server timestamps (`request.time`).

---

## 2. The "Dirty Dozen" Adversarial Payloads

| # | Attack Vector | Collection & Operation | Adversarial Payload / Condition | Expected Result |
|---|---|---|---|---|
| 1 | **Admin Self-Promotion** | `CREATE /admins/{studentUid}` | Ordinary student sends `{ uid: studentUid, role: "president", active: true, ... }` without an invite | `PERMISSION_DENIED` |
| 2 | **Unverified Email Spoof** | `CREATE /elections/{id}` | Attacker with `email: "psmartprogress@gmail.com"` and `email_verified: false` | `PERMISSION_DENIED` |
| 3 | **Shadow Field Injection** | `CREATE /students/{uid}` | Student includes extra ghost field `"isAdmin": true` in profile | `PERMISSION_DENIED` |
| 4 | **Student PII Scraping** | `GET /students/{otherUid}` or `LIST /students` | Authenticated student tries to read another student's profile or list all students | `PERMISSION_DENIED` |
| 5 | **Invalid Matric Poisoning** | `CREATE /students/{uid}` | Student submits `"matric": "12345"` (not 9 digits) or 2KB junk string | `PERMISSION_DENIED` |
| 6 | **11th Aspirant Overflow** | `CREATE /candidates/{id}` | Admin tries to add an 11th candidate when position `candidateCount == 10` | `PERMISSION_DENIED` |
| 7 | **Post-Start Candidate Tampering** | `UPDATE /candidates/{id}` | Admin attempts to edit or delete a candidate while election `status == "ongoing"` | `PERMISSION_DENIED` |
| 8 | **Admin Ballot Stuffing** | `UPDATE /tallies/{candidateId}` | Admin attempts to modify `votes` count on a tally document | `PERMISSION_DENIED` |
| 9 | **Double Voting / Receipt Rewrite** | `UPDATE /voteReceipts/{id}` or `CREATE /tallies` | Student attempts to modify their receipt or increment a tally without a new receipt | `PERMISSION_DENIED` |
| 10 | **Ballot Mutation / Deletion** | `UPDATE /ballots/{id}` or `DELETE /ballots/{id}` | Admin or student tries to alter or delete a submitted ballot | `PERMISSION_DENIED` |
| 11 | **Confidential Results Peek** | `GET /tallies/{id}` or `LIST /tallies` | Student queries tallies while `resultsVisible == false` | `PERMISSION_DENIED` |
| 12 | **Admin Voting Privilege Abuse** | `CREATE /voteReceipts/{id}` | President or Election Chairman tries to cast a vote with their admin session | `PERMISSION_DENIED` |
