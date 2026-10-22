# Identity & Email Detection Idioms (Entra ID, M365, MDO)

Structural idioms that recur in the best identity/email content. Not a query catalogue — each
entry is the shape plus the pitfalls. Table deltas (Sentinel vs XDR) are in `kql-gotchas.md` §2.

## 1. Sign-in result codes: classify, don't just test `== 0`

```kql
// Credential was VALID (password accepted, then interrupted) vs INVALID. Keep the sets disjoint.
let CredValid   = dynamic(["0", "50074", "50076", "53000", "53001", "53003", "50158", "50129", "50140", "50097", "50072", "50005", "50173"]);
let CredInvalid = dynamic(["50126", "50053"]);
SigninLogs
| where TimeGenerated > ago(1h)
| summarize ValidUsers = dcountif(UserPrincipalName, ResultType in (CredValid)),
            InvalidUsers = dcountif(UserPrincipalName, ResultType in (CredInvalid)),
            Failures = countif(ResultType in (CredInvalid)), Successes = countif(ResultType == "0") by IPAddress
| where InvalidUsers >= 5 and Failures > Successes     // failures > successes self-tunes corporate egress
```
Interrupt codes (MFA required, CA blocked, device registration) mean the **password was right** —
a spray that reaches them succeeded at credential validation. Keep the lists as a watchlist
(`ResultType-SignInLogsErrorCodes`: ResultType, Description, Notes tags `[Success]`, `[Expired]`).
A code in both lists (50055 in several public queries) double-counts.

Spray shape: `dcount(UserPrincipalName) by IPAddress, bin_at(TimeGenerated, 1h, now())`; XDR OAuth
variant: `IdentityLogonEvents | where ActionType == "LogonFailed" and LogonType == "OAuth2:Token"`.
Compound thresholds: unique accounts > N **and** failures per account ≤ M (more than ~3 per account
is brute force, not spray) **and** success×ratio < failures.

## 2. Flow fingerprinting (AiTM, device code, MFA fatigue)

- Group a sign-in **flow** by `CorrelationId` (+ UPN), collect `make_set(ResultType)`, test
  `has_all(...)`: AiTM ≈ `0 + 50140 + 50074` with ≥ 2 session/token ids and `RiskLevels has_any ("50","100")`
  (XDR: `Application == "OfficeHome"`, `isempty(AadDeviceId)`); device code ≈ `0 + 50199`
  (XDR: `EndpointCall == "Cmsi:Cmsi"`; Sentinel: `AuthenticationProtocol == "deviceCode"`).
  Known benign: Microsoft Authentication Broker app id, Teams rooms/phones, headless CLIs.
- MFA fatigue: `mv-expand todynamic(AuthenticationDetails)`, `authenticationStepResultDetail` in the
  deny set (`"MFA denied; user declined..."`, `"...did not respond..."`, `"...did not select the correct number"`),
  `make_list` per `CorrelationId` **and** per `UserPrincipalName, 10m` (attacker may start a new
  flow each attempt); user-reported fraud = `ResultType 500121` + `SuspiciousActivityReported` /
  `AADUserRiskEvents RiskEventType == "userReportedSuspiciousActivity"`.
- To alert: re-select raw rows and `arg_min(TimeGenerated, *) by CorrelationId` (first event = alert time).
- Legacy auth: `ClientAppUsed !in ("Mobile Apps and Desktop clients", "Browser") and isnotempty(ClientAppUsed)` —
  the `isnotempty` matters (non-interactive rows are often blank).

## 3. Token replay / session hijack

- **Replay**: `MicrosoftGraphActivityLogs | join kind=inner (union AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs)
  on $left.SignInActivityId == $right.UniqueTokenIdentifier | where ActivityIpAddress != SignInIpAddress and isnotempty(SignInIpAddress)`;
  classify the activity IP with Azure service-tag `externaldata` + `ipv4_lookup`.
- **Hijack**: new IP / ASN / UA appearing inside an existing `SessionId`
  (`set_difference(IPs, PreviousIPs)` per session); device-code success → `join kind=rightsemi`
  on `CorrelationId, UserId` to all sign-in tables → per-session diff.
- **FOCI refresh-token abuse**: `AADNonInteractiveUserSignInLogs | where HomeTenantId == ResourceTenantId and AppId in (FociClients)`
  (`externaldata` of the known-FOCI list), `IncomingTokenType == "none"` followed by `!= "none"` on the
  same `SessionId`; PRT replay = overlapping Windows Hello sessions for one device.
- Schema drift: `DeviceDetail = iff(isempty(DeviceDetail_dynamic), todynamic(DeviceDetail_string), DeviceDetail_dynamic)`
  (same for `ConditionalAccessPolicies_*`, `TokenProtectionStatusDetails_*`); `UniqueTokenIdentifier`
  is the cross-table key when `SessionId` is missing.
- MDE cross-check: user's `DeviceInfo.PublicIP` set vs sign-in `IPAddress` on the same session.

## 4. Audit log parsing: compute *what changed*

```kql
AuditLogs
| where TimeGenerated > ago(1h) and Category == "ApplicationManagement"
| mv-apply mp = TargetResources[0]["modifiedProperties"] on (
    summarize Props = make_bag(bag_pack(tostring(mp["displayName"]),
        bag_pack("old", trim(@'[\"\s]+', tostring(mp["oldValue"])), "new", trim(@'[\"\s]+', tostring(mp["newValue"])))))
| where isnotempty(Props["KeyDescription"])
| extend Added   = set_difference(todynamic(tostring(Props["KeyDescription"]["new"])), todynamic(tostring(Props["KeyDescription"]["old"]))),
         Removed = set_difference(todynamic(tostring(Props["KeyDescription"]["old"])), todynamic(tostring(Props["KeyDescription"]["new"])))
| extend Initiator = iif(isnotempty(InitiatedBy["app"]), tostring(InitiatedBy["app"]["displayName"]), tostring(InitiatedBy["user"]["userPrincipalName"])),
         InitiatorIP = tostring(InitiatedBy[tostring(bag_keys(InitiatedBy)[0])]["ipAddress"])
```
- Never `TargetResources[2].displayName` / `AdditionalDetails[4].value` positional indexing.
- Strip quotes on `newValue` (`trim(@'[\"\s]+', ...)`); role names arrive JSON-quoted.
- Initiator normalisation (app vs user, key-agnostic IP) belongs in one shared function.
- Conditional Access weakening: `array_length()` diffs of include/exclude lists in `newValue` vs
  `oldValue`, plus a separate "all → specific" check the count diff misses; PIM justification via
  `parse AdditionalDetails with * "{\"key\":\"Justification\",\"value\":\"" J "\"" *`.
- Role changes: normalise PIM once (`Category == "RoleManagement" and LoggedByService == "PIM"`),
  derive booleans (`ActivateOperation = OperationName has_any ("activation", "deactivate")`,
  `OperationName has "eligible"`); "outside of PIM" (`OperationName startswith "Add member to role outside of PIM"`)
  is a single-table, high-fidelity **NRT** candidate; role lists as `datatable(RoleName, RoleGuid)` or a regex
  watchlist assembled with `strcat_array`.
- Privilege of actor < privilege of target (credential added to a control-plane app by a lower-tier
  user) is the condition that matters, computed from a role-tier classification (watchlist / `externaldata`).
- Severity from the affected tier in KQL (`Severity = iff(Tier == "ControlPlane", "High", "Medium")`)
  with `alertSeverityColumnName`; a `DetectionReason` column so the alert says why it fired.
- Zero-target events: `mv-expand T = iff(array_length(TargetResources) == 0, dynamic([""]), TargetResources)`.
- Actor-token / service-identity abuse: `InitiatedBy.user.displayName has_any ("Office 365 Exchange Online", "Skype for Business Online", ...)`
  from an IP outside the M365 ranges feed, minus the legitimate group-management operations those services perform.
- Graph enumeration: `RequestUri has_any ("$skip=", "$skiptoken=", "$nextLink", "$top=999", "getByIds")`,
  normalise GUIDs/tokens before `reduce kind=source`.

## 5. Email (MDO) chains

- Everything joins on `NetworkMessageId`; it is **many-to-one** (URLs, attachments, recipients per
  message) → always `kind=inner`/`leftouter`, never bare `join`; `project-away *1` after joins.
- Delivery ≠ open: bridge mail → endpoint on attachment `SHA256` to `DeviceFileEvents`, or
  `UrlClickEvents` (`ActionType == "ClickAllowed"`, `IsClickedThrough`) → `DeviceEvents BrowserLaunchedToOpenUrl`
  on `RemoteUrl == Url`; unfold redirectors with `mv-expand todynamic(UrlChain)`.
- Rare-sender baseline: `dcount(NetworkMessageId) by SenderObjectId < N` over 7 d ending at `ago(1d)`.
- Campaign clustering: `EmailClusterId` + `make_set(SenderFromAddress)`; personalised subjects:
  `dcount(Subject) >= 10 by first three words, SenderFromAddress`.
- Recipient-in-URL: `base64_encode_tostring(RecipientEmailAddress)` then `Url contains B64`.
- Direct-Send abuse: `SenderMailFromAddress == RecipientEmailAddress`, SPF/DMARC `fail` from
  `parse_json(AuthenticationDetails)`, `isempty(Connectors)`, sender geo vs the user's 7-day sign-in countries.
- Post-delivery drift: `EmailEvents` × `EmailPostDeliveryEvents` on `NetworkMessageId, RecipientEmailAddress`
  where `DeliveryLocation != PostDeliveryLocation`.
- Typosquat: `jaccard_index(unicode_codepoints_from_string(Domain), unicode_codepoints_from_string(tolower(SenderFromDomain))) between (0.75 .. 0.99)`.
- Inbox rules: rule name `matches regex @"^[^a-zA-Z0-9]*$"` (punctuation-only) after `isnotempty`;
  forwarding via `Set-Mailbox` `ForwardingSmtpAddress` read by name with `mv-apply`, not `Parameters[1]`.
- OAuth posture: `OAuthAppInfo | summarize arg_max(Timestamp,*) by OAuthAppId | mv-expand Permissions`;
  consent phishing = `CloudAppEvents ActionType == "Add service principal."` (trailing period — use `has`)
  within a bounded, directed window of a risk event; risky scopes list hoisted.

## 6. Alert → blast radius pivots

`SecurityAlert`/`AlertEvidence` → entity (`AlertEvidence | where EntityType == "Ip" | extend IP = tostring(AdditionalFields.Address)`;
`Entities` → `Files[].FileHashes[].Value`; `RequestId`/`SessionId` → `AADUserRiskEvents`) → raw
tables over a **widened** window (alert tables lag). Chain: `SecurityAlert` → `AADUserRiskEvents`
(UPN + `RequestId`) → `SigninLogs` (`CorrelationId`). Dedup alerts with `arg_max(TimeGenerated, *) by SystemAlertId` first.
