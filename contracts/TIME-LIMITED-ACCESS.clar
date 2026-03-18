;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; TEMPORARY ACCESS PASS REGISTRY
;;
;; DESCRIPTION
;; ----------------------------------------------------------------------------
;; This contract manages temporary access permissions for users.
;;
;; Access passes are issued by the contract owner or authorized admins
;; and remain valid until a specified block height.
;;
;; Each pass stores:
;; - expiration block height
;; - issuer of the pass
;; - optional reason code
;;
;; The contract also supports:
;; - Admin management
;; - Emergency pause
;; - Access revocation
;; - Pass renewal
;; - Access validation checks
;;
;; This design can be used for:
;; - subscription trials
;; - gated services
;; - time-limited event access
;; - API access permissions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;



;; ============================================================================
;; SECTION 1 - CONTRACT OWNERSHIP
;; ============================================================================

(define-data-var contract-owner principal tx-sender)



;; ============================================================================
;; SECTION 2 - ADMIN REGISTRY
;; ============================================================================

;; Admins can issue and revoke access passes.

(define-map admins
  { admin: principal }
  { enabled: bool }
)



;; ============================================================================
;; SECTION 3 - GLOBAL PAUSE CONTROL
;; ============================================================================

;; When paused, issuing or modifying passes is disabled.

(define-data-var paused bool false)



;; ============================================================================
;; SECTION 4 - ACCESS PASS REGISTRY
;; ============================================================================

;; Each user may have a temporary access pass.

(define-map access-passes
  { user: principal }
  {
    expires-at: uint,
    issuer: principal,
    reason: (optional uint)
  }
)



;; ============================================================================
;; SECTION 5 - ERROR CONSTANTS
;; ============================================================================

(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-PAUSED (err u101))
(define-constant ERR-NO-PASS (err u102))
(define-constant ERR-INVALID-DURATION (err u103))



;; ============================================================================
;; SECTION 6 - INTERNAL HELPERS
;; ============================================================================

(define-private (is-owner (who principal))
  (is-eq who (var-get contract-owner))
)

(define-private (is-admin (who principal))
  (or
    (is-owner who)
    (default-to false
      (get enabled
        (map-get? admins { admin: who })
      )
    )
  )
)

(define-private (not-paused)
  (not (var-get paused))
)

(define-private (get-pass (user principal))
  (map-get? access-passes { user: user })
)



;; ============================================================================
;; SECTION 7 - READ ONLY FUNCTIONS
;; ============================================================================

;; Returns whether contract is paused

(define-read-only (is-paused)
  (var-get paused)
)

;; Returns pass record

(define-read-only (get-access-pass (user principal))
  (get-pass user)
)

;; Checks whether user currently has valid access

(define-read-only (has-valid-access (user principal))

  (let ((pass (get-pass user)))

    (if (is-none pass)

        false

        (let (
              (expires (get expires-at (unwrap-panic pass)))
             )

          (> expires stacks-block-height)
        )
    )
  )
)

;; Returns expiration height

(define-read-only (get-expiration (user principal))

  (match (get-pass user)

    pass (get expires-at pass)

    u0
  )
)



;; ============================================================================
;; SECTION 8 - ISSUE ACCESS PASS
;; ============================================================================

;; Admins or owner can grant temporary access.

(define-public (issue-pass
  (user principal)
  (duration uint)
  (reason (optional uint))
)

  (begin

    (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)
    (asserts! (not-paused) ERR-PAUSED)
    (asserts! (> duration u0) ERR-INVALID-DURATION)

    (let
      (
        (expiration (+ stacks-block-height duration))
      )

      (map-set access-passes
        { user: user }
        {
          expires-at: expiration,
          issuer: tx-sender,
          reason: reason
        }
      )

      (ok expiration)
    )
  )
)



;; ============================================================================
;; SECTION 9 - RENEW ACCESS PASS
;; ============================================================================

;; Extends an existing pass.

(define-public (renew-pass
  (user principal)
  (extra-duration uint)
)

  (begin

    (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)
    (asserts! (not-paused) ERR-PAUSED)

    (let ((pass (get-pass user)))

      (asserts! (is-some pass) ERR-NO-PASS)

      (let
        (
          (current-expiry (get expires-at (unwrap-panic pass)))
          (new-expiry (+ current-expiry extra-duration))
        )

        (map-set access-passes
          { user: user }
          {
            expires-at: new-expiry,
            issuer: (get issuer (unwrap-panic pass)),
            reason: (get reason (unwrap-panic pass))
          }
        )

        (ok new-expiry)
      )
    )
  )
)



;; ============================================================================
;; SECTION 10 - REVOKE ACCESS PASS
;; ============================================================================

;; Removes access immediately.

(define-public (revoke-pass (user principal))

  (begin

    (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)

    (map-delete access-passes { user: user })

    (ok true)
  )
)



;; ============================================================================
;; SECTION 11 - ADMIN MANAGEMENT
;; ============================================================================

(define-public (add-admin (admin principal))

  (begin

    (asserts! (is-owner tx-sender) ERR-UNAUTHORIZED)

    (map-set admins
      { admin: admin }
      { enabled: true }
    )

    (ok true)
  )
)

(define-public (remove-admin (admin principal))

  (begin

    (asserts! (is-owner tx-sender) ERR-UNAUTHORIZED)

    (map-delete admins { admin: admin })

    (ok true)
  )
)



;; ============================================================================
;; SECTION 12 - EMERGENCY CONTROLS
;; ============================================================================

(define-public (pause)

  (begin

    (asserts! (is-owner tx-sender) ERR-UNAUTHORIZED)

    (var-set paused true)

    (ok true)
  )
)

(define-public (unpause)

  (begin

    (asserts! (is-owner tx-sender) ERR-UNAUTHORIZED)

    (var-set paused false)

    (ok true)
  )
)