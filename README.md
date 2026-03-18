A Clarity smart contract for managing temporary access permissions on the Stacks blockchain.

Overview

This contract allows the owner or authorized admins to issue, renew, and revoke time-limited access passes for users. Each pass is valid until a specified block height and can be used for scenarios such as:

Subscription trials
Gated services
Time-limited event access
API access permissions

Features
Access Pass Registry: Issue, renew, and revoke temporary access passes for users.
Admin Management: Owner can add or remove admins who can manage passes.
Emergency Pause: Owner can pause/unpause the contract to disable pass modifications.
Access Validation: Check if a user currently has valid access.
Reason Codes: Optionally attach a reason code to each pass.

Data Structures
Access Pass:

expires-at (uint): Block height when access expires
issuer (principal): Who issued the pass
reason ((optional uint)): Optional reason code
Admins:

enabled (bool): Whether the admin is active

Public Functions
issue-pass (user principal) (duration uint) (reason (optional uint))
Issue a new access pass for a user.

renew-pass (user principal) (extra-duration uint)
Extend an existing access pass.

revoke-pass (user principal)
Remove a user's access pass.

add-admin (admin principal)
Add a new admin (owner only).

remove-admin (admin principal)
Remove an admin (owner only).

pause / unpause
Pause or unpause the contract (owner only).

Read-Only Functions
is-paused
Returns whether the contract is paused.

get-access-pass (user principal)
Returns the access pass record for a user.

has-valid-access (user principal)
Checks if a user currently has valid access.

get-expiration (user principal)
Returns the expiration block height for a user's pass.

Error Codes
u100: Unauthorized
u101: Contract is paused
u102: No access pass found
u103: Invalid duration
Usage
Deploy the contract to the Stacks blockchain.
Owner can add admins using add-admin.
Admins/Owner can issue, renew, or revoke passes for users.
Anyone can check access status using the read-only functions.
