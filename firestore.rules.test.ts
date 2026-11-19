/**
 * Security Rules Verification Suite (Phase 0 TDD — Dirty Dozen Payloads)
 *
 * Documents the 12 adversarial payloads and validates blueprint constraints +
 * rule invariants statically. Can also be executed against the Firebase Emulator
 * Suite with `@firebase/rules-unit-testing`.
 */

export interface DirtyDozenCase {
  id: number;
  name: string;
  collection: string;
  operation: 'create' | 'update' | 'delete' | 'get' | 'list';
  actor: 'student' | 'unverified_spoof' | 'admin';
  payload: Record<string, unknown>;
  expectedOutcome: 'PERMISSION_DENIED';
  enforcedByRule: string;
}

export const DIRTY_DOZEN_PAYLOADS: DirtyDozenCase[] = [
  {
    id: 1,
    name: 'Admin Self-Promotion',
    collection: '/admins/student_uid_001',
    operation: 'create',
    actor: 'student',
    payload: {
      uid: 'student_uid_001',
      email: 'attacker@aaua.edu.ng',
      fullName: 'Attacker Student',
      role: 'president',
      active: true,
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'admins.create requires isAdmin() or verified matching adminInvites/{role}',
  },
  {
    id: 2,
    name: 'Unverified Email Admin Spoof',
    collection: '/elections/el_spoof',
    operation: 'create',
    actor: 'unverified_spoof',
    payload: {
      electionId: 'el_spoof',
      title: 'Spoofed Election',
      status: 'ongoing',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'isBootstrappedAdmin() mandates request.auth.token.email_verified == true',
  },
  {
    id: 3,
    name: 'Shadow Field Injection on Student Profile',
    collection: '/students/student_uid_001',
    operation: 'create',
    actor: 'student',
    payload: {
      uid: 'student_uid_001',
      fullName: 'John Michael Adewale',
      matric: '220227814',
      email: 'john@aaua.edu.ng',
      level: '400',
      department: 'Early Childhood Education',
      isAdmin: true,
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'isValidStudent enforces data.keys().hasOnly([...]) rejecting ghost fields',
  },
  {
    id: 4,
    name: 'Student PII Scraping Across Accounts',
    collection: '/students/victim_uid_002',
    operation: 'get',
    actor: 'student',
    payload: {},
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'students.get strictly restricts access to isOwner(uid) || isAdmin()',
  },
  {
    id: 5,
    name: 'Invalid Matriculation Number Poisoning',
    collection: '/students/student_uid_001',
    operation: 'create',
    actor: 'student',
    payload: {
      uid: 'student_uid_001',
      matric: '12345',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'isValidMatric enforces size() == 9 && matches("^[0-9]{9}$")',
  },
  {
    id: 6,
    name: '11th Aspirant Per Position Overflow',
    collection: '/candidates/cand_11',
    operation: 'create',
    actor: 'admin',
    payload: {
      candidateId: 'cand_11',
      positionId: 'pos_president',
      fullName: 'Eleventh Candidate',
      politicalName: 'Overflow',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'candidates.create enforces position.candidateCount < 10 && isValidPosition candidateCount <= 10',
  },
  {
    id: 7,
    name: 'Post-Start Candidate Tampering',
    collection: '/candidates/cand_01',
    operation: 'update',
    actor: 'admin',
    payload: {
      fullName: 'Modified After Voting Started',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'candidates.update/delete checks parent election.status == "not_started"',
  },
  {
    id: 8,
    name: 'Admin Ballot / Tally Count Manipulation',
    collection: '/tallies/cand_01',
    operation: 'update',
    actor: 'admin',
    payload: {
      votes: 999,
      affirmVotes: 999,
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'tallies.update Tier 1 Admin affectedKeys().hasOnly(["resultsVisible"])',
  },
  {
    id: 9,
    name: 'Double Voting / Receipt Overwrite',
    collection: '/voteReceipts/el_2026_pos_pres_student_uid_001',
    operation: 'update',
    actor: 'student',
    payload: {
      positionId: 'pos_vp',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'voteReceipts.update and voteReceipts.delete are strictly false',
  },
  {
    id: 10,
    name: 'Submitted Ballot Tampering or Deletion',
    collection: '/ballots/ballot_uuid_01',
    operation: 'delete',
    actor: 'admin',
    payload: {},
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'ballots.update and ballots.delete are strictly false for all actors including admins',
  },
  {
    id: 11,
    name: 'Confidential Results Peek Before Publication',
    collection: '/tallies',
    operation: 'list',
    actor: 'student',
    payload: {},
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'tallies.list requires resource.data.resultsVisible == true || isAdmin()',
  },
  {
    id: 12,
    name: 'Admin Voting Privilege Abuse',
    collection: '/voteReceipts/el_2026_pos_pres_admin_uid',
    operation: 'create',
    actor: 'admin',
    payload: {
      receiptId: 'el_2026_pos_pres_admin_uid',
      electionId: 'el_2026',
      positionId: 'pos_pres',
      voterUid: 'admin_uid',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcedByRule: 'voteReceipts.create and ballots.create enforce !isAdmin()',
  },
];
