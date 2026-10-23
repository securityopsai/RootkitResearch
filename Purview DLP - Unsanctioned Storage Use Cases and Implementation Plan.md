# Microsoft Purview Endpoint DLP: Preventing Copy/Paste and Upload of Labeled Data to Unsanctioned Storage

**Use cases and implementation plan**

| Item | Value |
| --- | --- |
| Status | Draft v0.1 for review |
| Date | 2026-10-23 |
| Target platform | Microsoft Purview Data Loss Prevention (Endpoint DLP), with Microsoft Defender for Cloud Apps as a complementary control |
| Decision basis | Sensitivity labels applied by Microsoft Purview |
| Devices in scope | Windows 10/11 and macOS endpoints onboarded to Purview |
| Facts verified against | Microsoft Learn, as published on 2026-10-23 (links in section 13) |

Fields marked **`[TBD]`** are intentionally blank. They need input from the business or the infrastructure team before the build phase starts. Section 12 lists all of them in one place.

---

## 1. Summary

Users must not move labeled documents, or text copied out of them, to storage the organization has not sanctioned. Unsanctioned storage includes local NAS devices on the LAN (reached over SMB/CIFS, a web interface, or FTP/SFTP), consumer and third-party cloud storage, and arbitrary websites.

Sanctioned storage today is Microsoft 365 (SharePoint Online, OneDrive for Business, Teams, Exchange Online). A number of local NAS devices and their shares will also be sanctioned. Their names, paths, and addresses are not yet known and are left blank in this document.

The decision "is this file protected" is made by the sensitivity label on the file. The decision "is this destination allowed" is made by allow lists configured in Purview Endpoint DLP settings: network share groups, service domains, sensitive service domain groups, and restricted app groups.

The control point is the endpoint itself. Purview Endpoint DLP runs inside Microsoft Defender on the device and intercepts the egress activity (copy to share, upload in browser, copy to clipboard, paste to browser, FTP transfer) at the moment it happens. No network appliance or proxy is required for the core use cases.

The plan runs in six phases: prerequisites and discovery, design sign-off, build, simulation, block-with-override pilot, and enforced rollout with ongoing operations.

---

## 2. Scope and assumptions

### 2.1 In scope

- Labeled files on onboarded Windows 10/11 and macOS devices.
- Egress to: SMB/CIFS network shares (including NAS), NAS web interfaces on the LAN, cloud storage websites, generic websites (paste), FTP/SFTP servers, and desktop sync clients.
- Clipboard copy out of labeled files, and paste of sensitive text into browsers.

### 2.2 Out of scope (for this phase)

- Linux endpoints, iOS, Android, and unmanaged (BYOD) devices. Endpoint DLP does not run there.
- Data at rest already sitting on NAS devices. That is a job for the Purview Information Protection scanner and on-premises repository DLP, not Endpoint DLP.
- Email and Teams message egress. Covered by Exchange and Teams DLP locations, which are separate policies.
- Screenshots, photos of screens, and retyping. No DLP product prevents these reliably.

### 2.3 Assumptions and flagged uncertainties

1. **"Microsoft Defender for Cloud" is assumed to mean "Microsoft Defender for Cloud Apps".** Defender for Cloud is Azure workload protection and has no role here. Defender for Cloud Apps (formerly MCAS) provides shadow IT discovery, unsanctioned app blocking, and session controls for SaaS apps. This document treats it as a complementary control, not the primary one. Confidence that this is the intended product: high, but please confirm.
2. **Labels are applied and reliable.** Endpoint DLP can only enforce label-based rules on files that carry a label. If labeling coverage is partial, sensitive files without labels pass through. Section 10 proposes a mitigation (sensitive information types as a second condition, default labels, and the "document could not be scanned" rule).
3. **Licensing exists.** Endpoint DLP requires Microsoft 365 E5/A5, Microsoft 365 E5 Compliance, or Microsoft 365 E5 Information Protection and Governance for every user in scope. Defender for Cloud Apps requires its own license (included in Microsoft 365 E5 and EMS E5). Confidence: high.
4. **Devices are already onboarded to Microsoft Defender for Endpoint, or can be.** Onboarding to Defender for Endpoint also onboards devices to Purview; only "Turn on device monitoring" is then needed. macOS devices need Intune, Jamf Pro, or another MDM. Confidence: high.
5. **Microsoft Edge is the primary browser, or Chrome/Firefox can be managed.** Full browser coverage on Windows needs Edge, or Chrome/Firefox with the Microsoft Purview extension deployed and pinned by policy. On macOS the Chrome/Firefox extension is not available; Safari and Edge are supported natively. Confidence: high.
6. **The NAS devices to be sanctioned are reachable by stable UNC paths and stable IP addresses or hostnames.** If NAS addresses change (DHCP), the allow lists will break. Confidence that this assumption holds: unknown, to be checked.

---

## 3. Definitions

| Term | Meaning in this document |
| --- | --- |
| Protected item | A file carrying a sensitivity label in a protected tier (see 4.1). Endpoint DLP treats it as "sensitive". |
| Egress activity | Any action that moves a protected item or its content off the device: copy to network share, upload in browser, copy to clipboard, paste to browser, FTP/SFTP transfer, copy to USB, print, RDP transfer, Bluetooth transfer. |
| Sanctioned destination | A destination on an allow list: a network share group with action Allow, a service domain in the Allow list, or an app in an allowed restricted app group. |
| Unsanctioned destination | Any destination not on an allow list. The default stance is deny. |
| NAS | Network-attached storage on the LAN. Reachable over SMB/CIFS (as a UNC path or mapped drive), over HTTP/HTTPS (vendor web UI such as Synology DSM, QNAP QTS, TrueNAS), and sometimes over FTP/SFTP or WebDAV. |
| Block | The action is stopped. The user sees a notification. An audit event and optionally an alert are generated. |
| Block with override | The action is stopped, but the user can click through with a business justification. The override is logged and alerted. On Windows the override allows the action for 1 minute. |
| Audit only | The action is allowed and logged. Used in early phases. |
| Allow | The action is allowed and logged with no alert. Used for sanctioned destinations. Available only for the Devices location. |
| Simulation mode | Policy runs as if enforced, but no action is taken. Results appear in a separate dashboard. Replaces the old "Test" modes. |

---

## 4. Sanction model (the lists that drive every decision)

### 4.1 Sensitivity label tiers

The label taxonomy in the tenant is not yet documented here. Fill the table. The tier decides which action applies.

| Tier | Purpose | Default action for egress to unsanctioned destinations | Label name(s) in tenant |
| --- | --- | --- | --- |
| Tier 3 | Highest sensitivity. Must never leave sanctioned storage. | **Block** | `[TBD]` (e.g. Highly Confidential and its sublabels) |
| Tier 2 | Confidential business data. Leaving sanctioned storage requires a justified exception. | **Block with override** (justification required, alert on override) | `[TBD]` (e.g. Confidential and its sublabels) |
| Tier 1 | Internal data. Monitor only. | **Audit only** | `[TBD]` (e.g. General / Internal) |
| Tier 0 | Public / unlabeled. No restriction from label rules. | None | `[TBD]` (e.g. Public) |

Design note: start with two enforced tiers. More tiers mean more policies, more exceptions, and slower rollout. Recommendation is Tier 3 = Block and Tier 2 = Block with override for the first six months, then review override volume and tighten.

### 4.2 Sanctioned cloud service domains (upload allow list)

Used by the **Service domains** setting in Allow mode. Maximum 50 entries. Only Microsoft 365 is sanctioned today.

| Service | Domain pattern | Notes |
| --- | --- | --- |
| SharePoint Online and OneDrive for Business | `*.sharepoint.com` | Covers `tenant.sharepoint.com` and `tenant-my.sharepoint.com`. Replace with the exact tenant hostnames if the wildcard is judged too broad: `[TBD tenant].sharepoint.com`, `[TBD tenant]-my.sharepoint.com`. |
| Microsoft Teams (web) | `teams.microsoft.com`, `*.teams.microsoft.com`, `teams.cloud.microsoft` | File attach in Teams web goes to SharePoint/OneDrive but the upload is initiated from the Teams domain. |
| Outlook on the web | `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft` | Attaching a file to a mail is a browser upload. Exchange DLP handles the mail content itself. |
| Microsoft 365 portal and Office web apps | `*.office.com`, `*.cloud.microsoft`, `*.microsoft365.com` | Office for the web upload entry points. |
| Other sanctioned SaaS | `[TBD]` | None known today. |

**Caution.** Do not add consumer Microsoft domains such as `onedrive.live.com`, `outlook.live.com`, or `login.live.com` to the allow list. They are personal storage and are unsanctioned. The exact Microsoft 365 hostnames in use should be validated in a pilot in simulation mode before enforcement, because Microsoft periodically adds new `cloud.microsoft` endpoints. Confidence in the list above as a starting point: medium.

### 4.3 Sanctioned network shares (SMB/CIFS allow list)

Used by a **Network share group** with action **Allow**. Paths are matched by prefix and support `*` wildcards. Every other share is implicitly unsanctioned and falls under the global "Copy to a network share" action.

| Share | UNC path prefix | Owner | Protocol | Notes |
| --- | --- | --- | --- | --- |
| `[TBD]` corporate file server | `\\[TBD]\` | `[TBD]` | SMB | |
| `[TBD]` sanctioned NAS 1 | `\\[TBD hostname or IP]\` | `[TBD]` | SMB/CIFS | Add both hostname and IP forms if users connect either way. |
| `[TBD]` sanctioned NAS 2 | `\\[TBD]\` | `[TBD]` | SMB/CIFS | |

**Caution.** If a NAS is reached via a mapped drive letter, Endpoint DLP still sees the underlying UNC path. Add the UNC prefix, not the drive letter. If the same NAS is reachable by DNS name and by IP address, add both. If NAS addresses are dynamic, fix them first.

### 4.4 Sanctioned NAS web interfaces and other LAN web upload targets

Used by a **Sensitive service domain group** with match type URL, IP address, or IP address range, assigned the **Allow** action in policy. Everything else on the LAN is unsanctioned and is caught by the Service domains Allow-mode default (any site not on the allow list is restricted).

| Device | Web UI address | Match type | Notes |
| --- | --- | --- | --- |
| `[TBD]` sanctioned NAS 1 | `[TBD hostname]` or `[TBD IP]` | URL or IP address | |
| `[TBD]` sanctioned NAS 2 | `[TBD]` | | |

**Platform note.** Upload blocking keyed on an IP address or IP range is supported on Windows only. On macOS, use a DNS hostname for the NAS web UI and match by URL. Confidence: high (documented).

### 4.5 Unsanctioned destinations that need an explicit entry

In Allow mode, unlisted websites are restricted automatically, so most unsanctioned cloud storage needs no entry. Two categories still need explicit configuration.

| Category | Mechanism | Entries |
| --- | --- | --- |
| Desktop sync clients for cloud storage and NAS (they bypass the browser) | Restricted app group "Unsanctioned sync clients" with Auto-quarantine | Windows: `Dropbox.exe`, `GoogleDriveFS.exe`, `Box.exe`, `iCloudDrive.exe`, `MEGAsync.exe`, Synology `cloud-drive-ui.exe` / `cloud-drive-daemon.exe`, QNAP `Qsync.exe`, `[TBD others found in discovery]`. macOS: `/Applications/Dropbox.app/Contents/MacOS/Dropbox`, `/Applications/Google Drive.app/Contents/MacOS/Google Drive`, `/Applications/Box.app/Contents/MacOS/Box`, `System/Library/PrivateFrameworks/CloudDocsDaemon.framework/Versions/A/Support/bird` (iCloud), `[TBD]`. Executable names must be verified against installed versions. |
| Unsanctioned LAN subnets hosting NAS web UIs (for an explicit Block group, useful in Block mode or for alerts) | Sensitive service domain group "Unsanctioned LAN storage" with IP range match | `[TBD]` e.g. `10.0.0.0-10.255.255.255`, `192.168.0.0-192.168.255.255`, `172.16.0.0-172.31.255.255`, excluding sanctioned NAS addresses. |

### 4.6 Browsers

| Browser | Windows | macOS | Required deployment step |
| --- | --- | --- | --- |
| Microsoft Edge | Native, all actions | Native | None |
| Google Chrome | Upload and paste control via Microsoft Purview extension | Not supported via extension | Deploy and force-install the extension via Intune/GPO on Windows. Add to Unallowed browsers only if the extension cannot be deployed. |
| Mozilla Firefox | Upload and paste control via Microsoft Purview extension | Not supported via extension | Same as Chrome. |
| Safari | n/a | Native | None |
| Any other browser (Brave, Opera, Vivaldi, Tor, etc.) | Add executable name to **Unallowed browsers** | Add full app path to Unallowed browsers | Blocked from opening protected files; user is redirected to Edge. |

---

## 5. Use cases

Each use case uses the same shape: who does what, what must happen, which Purview control does it, where it works, how to test it, and what it does not cover. Confidence grades: **High** = behavior documented by Microsoft and verified on 2026-10-23. **Medium** = documented but in preview, platform-limited, or dependent on configuration details. **Low** = inferred, needs lab validation.

### UC-01 Copy a labeled file to an unsanctioned network share (SMB/CIFS NAS)

- **Story.** A user plugs the laptop into the office LAN, opens `\\nas-unknown\share`, and drags a Tier 3 file into it.
- **Expected result.** The copy is blocked. The user sees a DLP notification. An alert is raised. For a Tier 2 file the user can override with a justification.
- **Purview control.** DLP policy, Devices location, condition "Content contains → Sensitivity label ∈ Tier 3". Action "Audit or restrict activities on devices → File activities for all apps → Copy to a network share = Block". The sanctioned share group (4.3) is assigned action Allow in the same rule, so sanctioned shares are exempt.
- **Platform.** Windows and macOS. Network share groups require the Windows KBs listed in Microsoft Learn (KB 5018482 / KB 5018483 or later).
- **Test.** Create `test-tier3.docx`, apply the Tier 3 label, save locally. Copy to an unsanctioned UNC path via File Explorer, via Save As in Word, and via `copy` in a command prompt. All three must fail. Repeat with Tier 2 (expect override prompt). Repeat to a sanctioned share (expect success, no alert).
- **Not covered.** Files already stored on the NAS. Files whose label is from another tenant (not detected). Confidence: **High**.

### UC-02 Copy a labeled file to a sanctioned network share

- **Story.** Same user copies the same Tier 3 file to `\\[TBD sanctioned NAS]\projects`.
- **Expected result.** The copy succeeds silently. An audit event is logged. No alert.
- **Purview control.** Network share group "Sanctioned shares" assigned action **Allow** inside the UC-01 rule.
- **Platform.** Windows and macOS.
- **Test.** As in UC-01, final step. Also test a mapped drive letter pointing at the sanctioned share.
- **Not covered.** A sanctioned share whose UNC prefix is not in the group (e.g., reached via IP when only the hostname is listed) will be blocked. Keep both forms in the group. Confidence: **High**.

### UC-03 Upload a labeled file through a NAS web interface on the LAN

- **Story.** A user opens `http://192.168.1.50:5000` (a NAS web UI), navigates to File Station, and uploads a Tier 3 file.
- **Expected result.** The upload is blocked in the browser. The user sees a DLP notification.
- **Purview control.** Endpoint setting **Service domains = Allow** with the Microsoft 365 domains from 4.2. Policy action "Service domain and browser activities → Upload to a restricted cloud service domain or access from an unallowed browser = Block". Because the NAS address is not on the Allow list, it is restricted by default. Sanctioned NAS web UIs (4.4) are placed in a sensitive service domain group assigned action Allow.
- **Platform.** Windows (IP and URL matching). macOS (URL matching only; IP-based upload control is Windows only). Browsers per 4.6.
- **Test.** Upload via the web UI's file picker and via drag-and-drop, in Edge and in Chrome with the extension. Repeat against a sanctioned NAS web UI (expect success).
- **Not covered.** A NAS web UI reached only by IP from a Mac. Mitigation: give sanctioned NAS devices DNS names and use URL match; unsanctioned NAS on macOS are still caught by the Allow-mode default as long as the browser is supported. Confidence: **High** for Windows, **Medium** for macOS.

### UC-04 Upload a labeled file to unsanctioned cloud storage in a browser

- **Story.** A user drags a Tier 2 file into `drive.google.com`, `dropbox.com`, `wetransfer.com`, or any file-sharing website.
- **Expected result.** Tier 3: blocked. Tier 2: blocked with override and justification. Upload to `[tenant].sharepoint.com` succeeds.
- **Purview control.** Same as UC-03. The Allow-mode Service domains list is the single source of truth for sanctioned cloud storage.
- **Platform.** Windows and macOS, supported browsers only.
- **Test.** Attempt uploads to three unsanctioned sites and to SharePoint and Outlook on the web. Confirm Outlook attachment of a Tier 3 file is allowed by this rule (mail content is then governed by Exchange DLP).
- **Not covered.** Uploads from unsupported browsers (see UC-05). Native desktop apps that upload directly (see UC-06). Confidence: **High**.

### UC-05 Open or upload a labeled file from an unallowed browser

- **Story.** A user installs Brave and tries to upload a Tier 3 file to any website.
- **Expected result.** Brave is blocked from accessing the file. A toast tells the user to use Microsoft Edge.
- **Purview control.** Endpoint setting **Unallowed browsers** (executable names on Windows, full paths on macOS). Takes effect when the upload action in the policy is Block or Block with override.
- **Platform.** Windows and macOS.
- **Test.** Install one unallowed browser on a pilot device and attempt the upload.
- **Not covered.** A browser not on the list and without the extension. Mitigation: use Intune or AppLocker to restrict browser installation, and review Defender for Endpoint software inventory monthly for new browsers. Confidence: **High**.

### UC-06 Sync a labeled file through a desktop cloud or NAS sync client

- **Story.** A user drops a Tier 3 file into the local Dropbox folder, or into a Synology Drive Client sync folder. No browser is involved.
- **Expected result.** The sync client is denied access to the file. The file is moved to a quarantine folder and replaced with a `.txt` placeholder explaining what happened. One notification, not a loop.
- **Purview control.** Endpoint setting **Restricted apps and app groups**: group "Unsanctioned sync clients" (4.5) with **Auto-quarantine** enabled. Policy action "File activities for apps in restricted app groups → Apply a restriction to all activity = Block".
- **Platform.** Windows and macOS.
- **Test.** Install one unsanctioned sync client on a pilot device. Copy a labeled file into its folder. Confirm the placeholder appears and the original is in the quarantine path. Confirm the sanctioned OneDrive client still syncs the same file.
- **Not covered.** Sync clients not in the group. Mitigation: discovery in Phase 0 (Defender for Cloud Apps Cloud Discovery plus Defender for Endpoint software inventory), and consider the "block all apps except allowed" pattern later. Confidence: **High**.

### UC-07 Copy content out of a labeled file to the clipboard

- **Story.** A user opens a Tier 3 Word document, selects a table, and presses Ctrl+C intending to paste it into a personal email, Notepad, or a web form.
- **Expected result.** The copy is blocked at the moment of copying. Pasting within the same document still works. Tier 2: block with override.
- **Purview control.** Policy action "File activities for all apps → Copy to clipboard = Block".
- **Platform.** Windows and macOS. Also applies to redirected clipboards in Azure Virtual Desktop / Windows 365.
- **Test.** Copy within the same Word file (allowed). Copy from the Tier 3 file into a new Word file (blocked). Copy into Notepad (blocked). Copy from an unlabeled file while the Tier 3 file is open in the same app (expect blocked, see behavior note).
- **Behavior notes and gaps.** Enforcement happens at copy time, not at paste time; Endpoint DLP cannot allow the copy and then block only certain paste destinations in desktop apps. While a blocked file is open, copying from any other file in the same application is also restricted. This will generate user friction for Tier 3; keep Tier 3 small. Confidence: **High**.

### UC-08 Paste sensitive text into an unsanctioned website

- **Story.** A user has sensitive text on the clipboard (from any source, including a sanctioned web app or an unlabeled file) and pastes it into a webmail, a chat site, a public AI assistant, or a NAS web UI note field.
- **Expected result.** The paste is blocked or warned, depending on the destination group. Paste into Microsoft 365 web apps is allowed.
- **Purview control.** Policy action "Service domain and browser activities → Paste to supported browsers". Requires **sensitive service domain groups**: group "Sanctioned web apps" (Microsoft 365 domains) = Allow, group "Unsanctioned LAN storage" (IP ranges) = Block, the built-in "Generative AI websites" group = Block or Block with override, and a catch-all stance decided in design.
- **Important limitation.** Paste to browser evaluates the clipboard content against **sensitive information types only, not sensitivity labels**. It ignores text shorter than 30 characters, inspects only the first 4 MB, and adds about 2 seconds of latency. IP-range groups do not support the paste action; use URL match for paste rules. So this use case protects *content that matches a sensitive information type*, not *content that came from a labeled file*. For "text copied from a labeled file", UC-07 is the control.
- **Platform.** Windows (Edge, Chrome and Firefox with extension). macOS in preview.
- **Test.** Paste a test credit card number string into an unsanctioned site (blocked) and into SharePoint (allowed). Paste a 20-character string (not evaluated).
- **Design dependency.** The organization must define which sensitive information types matter (e.g., built-in financial SITs, custom SITs for internal identifiers, Exact Data Match). Confidence: **High** on behavior, **Medium** on fit to the "labeled data" requirement.

### UC-09 Transfer a labeled file to a NAS over FTP or SFTP

- **Story.** A user opens WinSCP or FileZilla and uploads a Tier 3 file to the NAS FTP service.
- **Expected result.** The transfer is blocked with a notification.
- **Purview control.** Policy action "File activities for all apps → FTP and SFTP transfers = Block". This activity reached general availability in October 2026.
- **Platform.** Windows (documented as managed Windows devices). macOS: not documented, treat as not covered.
- **Test.** Use two FTP clients. Confirm block and that Activity explorer shows "File transfer by FTP/SFTP".
- **Not covered.** FTP from macOS. WebDAV (treated as either a network share via Windows WebClient or a browser upload; needs lab validation). Confidence: **Medium** (new feature, limited field experience).

### UC-10 Move a file Endpoint DLP cannot scan to an unsanctioned destination

- **Story.** A user zips a Tier 3 file with a password, or renames it to an unsupported extension, and copies it to the NAS.
- **Expected result.** The copy is blocked with override and a justification is required, because the content cannot be inspected.
- **Purview control.** Separate rule with condition **Document could not be scanned**, action Copy to a network share = Block with override, Copy to USB = Block with override, with "Apply restrictions to only unsupported file extensions" selected. Known harmless extensions can be excluded in endpoint settings.
- **Platform.** Windows and macOS.
- **Test.** Password-protected zip and a renamed `.bin` file to an unsanctioned share.
- **Notes.** Office and PDF files are detected by MIME type even after renaming. Labels embedded in Office files survive zipping, and archives are a monitored type, but encrypted archives cannot be read. Confidence: **High** on the rule, **Medium** on exactly which files land in the "could not be scanned" bucket.

### UC-11 Egress of a file that has not been classified yet

- **Story.** A user creates a new file, applies a Tier 3 label, and within seconds copies it to the NAS before Endpoint DLP has finished evaluating it.
- **Expected result.** The egress is held until evaluation completes, then the normal verdict applies.
- **Purview control.** **Just-in-time protection** enabled in Purview settings, scoped to the pilot users, with network share coverage enabled so JIT also applies to files on mapped drives. Fallback action on classification failure: Block (after pilot).
- **Platform.** Windows and macOS (offline-device behavior is Windows only).
- **Test.** Create and immediately copy. Observe the "evaluation in progress" notification.
- **Notes.** JIT adds friction when classification is slow. Keep "Control copying to clipboard" under JIT off until the impact is measured. Confidence: **High**.

### UC-12 Visibility, alerting, and evidence

- **Story.** The security team must see every blocked or overridden egress, who did it, from which device, to which destination, and in Tier 3 cases obtain a copy of the file.
- **Expected result.** Events appear in Activity explorer and DLP alerts (also surfaced in Microsoft Defender XDR incidents). Overrides include the user's justification. For Tier 3, the original file is collected as evidence.
- **Purview control.** Alerts configured per rule (single-event alerts for Tier 3, aggregated for Tier 2). Evidence collection for file activities on devices enabled, with Microsoft-managed or customer Azure storage. Optional: forward alerts to Microsoft Sentinel via the Defender XDR connector.
- **Platform.** All.
- **Test.** Trigger UC-01 and confirm the alert, the Activity explorer event with destination path, and the evidence file.
- **Notes.** Evidence collection has storage cost and privacy implications; agree retention with legal. Confidence: **High**.

---

## 6. Control mapping

| Use case | Egress path | Purview setting (Endpoint DLP settings) | Policy action | Tier 3 | Tier 2 | Windows | macOS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| UC-01 | SMB/CIFS to unsanctioned share | Network share coverage enabled | Copy to a network share | Block | Block w/ override | Yes | Yes |
| UC-02 | SMB/CIFS to sanctioned share | Network share group "Sanctioned shares" | Group action Allow | Allow | Allow | Yes | Yes |
| UC-03 | Browser upload to LAN NAS web UI | Service domains = Allow (M365 listed); SSD group "Sanctioned NAS web UIs" | Upload to restricted cloud service domain | Block | Block w/ override | Yes | URL only |
| UC-04 | Browser upload to unsanctioned cloud | Service domains = Allow | Upload to restricted cloud service domain | Block | Block w/ override | Yes | Yes |
| UC-05 | Unallowed browser | Unallowed browsers list | (same action as UC-04) | Redirect to Edge | Redirect to Edge | Yes | Yes |
| UC-06 | Desktop sync client | Restricted app group + Auto-quarantine | File activities for apps in restricted app groups: all activity | Block + quarantine | Block + quarantine | Yes | Yes |
| UC-07 | Copy out of labeled file | None | Copy to clipboard | Block | Block w/ override | Yes | Yes |
| UC-08 | Paste sensitive text to website | SSD groups (URL match) | Paste to supported browsers (SIT-based) | Block per group | Block w/ override per group | Yes | Preview |
| UC-09 | FTP/SFTP | None | FTP and SFTP transfers | Block | Block w/ override | Yes | Not documented |
| UC-10 | Unscannable file | Unsupported file extension exclusions | Document could not be scanned → network share, USB | Block w/ override | Block w/ override | Yes | Yes |
| UC-11 | Not yet classified | Just-in-time protection | n/a (holds egress) | Hold | Hold | Yes | Yes |
| UC-12 | Visibility | Evidence collection; Always audit file activity | Alerts, incident reports | Alert + evidence | Aggregated alert | Yes | Yes |

Also recommended in the same rules, because the configuration cost is near zero: Copy to USB removable device = Block (Tier 3) / Block with override (Tier 2), Print = Block with override, Copy or move using RDP = Block with override, Copy or move using unallowed Bluetooth app = Block. These are outside the stated requirement and can be dropped if the business objects.

---

## 7. Policy design

### 7.1 Endpoint DLP settings (tenant-wide, configured once)

| Setting | Value |
| --- | --- |
| Device monitoring | On for all onboarded devices |
| Advanced classification scanning and protection | On (required for labels in some scenarios, trainable classifiers, EDM); set bandwidth limit |
| Always audit file activity for devices | On |
| Network share coverage and exclusions | On; exclusions: `[TBD]` (e.g., software deployment shares, roaming profile shares) |
| Just-in-time protection | On, scoped to pilot group first; fallback = Audit in pilot, Block after |
| Restricted apps and app groups | Group "Unsanctioned sync clients" per 4.5, Auto-quarantine on, quarantine path `%homedrive%%homepath%\Microsoft DLP\Quarantine` (Windows) and `[TBD]` (macOS), placeholder text with `%%FileName%%`, `%%PolicyName%%`, `%%QuarantinePath%%` |
| Unallowed browsers | Per 4.6 |
| Service domains | **Allow** mode; entries per 4.2 (max 50) |
| Sensitive service domain groups | "Sanctioned M365 web apps" (URL), "Sanctioned NAS web UIs" (URL/IP), "Unsanctioned LAN storage" (IP ranges), built-in "Generative AI websites" |
| Network share groups | "Sanctioned shares" per 4.3 |
| Printer groups, Removable USB device groups | Optional; `[TBD]` if the extra activities in section 6 are adopted |
| VPN settings | Optional; `[TBD]` if behavior should differ on corporate VPN (Windows only) |
| Business justification in policy tips | On; customize justification options |
| Evidence collection for file activities on devices | On; storage `[TBD Microsoft-managed or customer Azure Blob]`; retention `[TBD]` |
| File path exclusions | Default plus `[TBD]` build/output folders that generate noise |

### 7.2 DLP policies (Devices location only, Admin unit = Full directory)

| Policy | Rule | Condition | Actions |
| --- | --- | --- | --- |
| **EDLP-01 Tier 3 Block** | R1 | Content contains → Sensitivity label ∈ Tier 3 labels | Copy to network share = Block, "Sanctioned shares" group = Allow; Upload to restricted cloud service domain = Block, "Sanctioned NAS web UIs" group = Allow; Copy to clipboard = Block; FTP/SFTP = Block; restricted app group "Unsanctioned sync clients" = Block all activity; USB = Block; Print, RDP = Block with override; Bluetooth = Block. User notification on, policy tip on. Alert: every event, severity High. Evidence collection on. |
| **EDLP-02 Tier 2 Block with override** | R1 | Content contains → Sensitivity label ∈ Tier 2 labels | Same activities as EDLP-01 but Block with override; business justification required. Alert: aggregated (e.g., 5 events / 60 min per user), severity Medium. |
| **EDLP-03 Unscannable** | R1 | Document could not be scanned; Apply restrictions to only unsupported file extensions | Copy to network share = Block with override, "Sanctioned shares" = Allow; Copy to USB = Block with override. Alert: aggregated. |
| **EDLP-04 Paste to browser (SIT)** | R1 | Content contains → Sensitive info types `[TBD list]` (high confidence, min count 1) | Paste to supported browsers: "Sanctioned M365 web apps" = Allow; "Generative AI websites" = Block; "Unsanctioned LAN storage" (URL-match entries only) = Block; default for other sites = Block with override. |
| **EDLP-05 Tier 1 Audit** | R1 | Content contains → Sensitivity label ∈ Tier 1 labels | All activities = Audit only. No user notification. Feeds baselining. |

Rule ordering: EDLP-01 before EDLP-02. Enable "stop processing more rules" only after simulation confirms no unintended overlap (it does not work in simulation mode).

Optional hardening for the label-coverage gap: add a second rule to EDLP-01 and EDLP-02 with condition "Content contains → Sensitive info types `[TBD]` AND Content is not labeled", so highly sensitive content that someone forgot to label is still caught. This increases false positives; evaluate in simulation.

### 7.3 Scoping

Policies are scoped by users and by devices. A device must be in scope *and* the user must be in scope for enforcement. Use Entra ID groups: `[TBD] DLP-Pilot-Users`, `[TBD] DLP-Ring1-Users`, `[TBD] DLP-All-Users`, and Defender for Endpoint device groups for device scoping.

---

## 8. Implementation plan

Durations are indicative for a single tenant with up to a few thousand devices. They stretch if labeling is not yet in place.

### Phase 0: Prerequisites and discovery (2 to 4 weeks)

| # | Task | Owner | Exit criterion |
| --- | --- | --- | --- |
| 0.1 | Confirm licensing for all in-scope users (M365 E5 / E5 Compliance / E5 IP&G; Defender for Cloud Apps) | Licensing / `[TBD]` | License report attached |
| 0.2 | Confirm device onboarding: all Windows/macOS devices appear in Purview → Settings → Device onboarding, status healthy; turn on device monitoring | Endpoint team | ≥ 98 % of in-scope devices onboarded |
| 0.3 | Verify Windows build and Defender platform version meet the KB prerequisites for network share groups, network share coverage, and paste to browser | Endpoint team | Compliance report from Intune |
| 0.4 | Deploy the Microsoft Purview extension for Chrome and Firefox on Windows via Intune/GPO, force-installed and non-removable; decide whether to list other browsers as unallowed | Endpoint team | Extension present on 100 % of pilot devices |
| 0.5 | Document the sensitivity label taxonomy and map labels to tiers (4.1) | Information protection owner | Table 4.1 complete |
| 0.6 | Measure labeling coverage (Content explorer, Activity explorer): what share of Office/PDF files on endpoints carry a label | Information protection owner | Coverage figure recorded; default-label and auto-label gaps listed |
| 0.7 | Inventory NAS devices: hostname, IP, shares, protocols (SMB, HTTP(S), FTP/SFTP, WebDAV), owner, and sanction decision. Use Defender for Endpoint device discovery and advanced hunting (SMB and HTTP connections to RFC1918 addresses), network team records, and physical walk-through | Network team + security | Tables 4.3 and 4.4 complete |
| 0.8 | Inventory cloud storage use: enable Defender for Cloud Apps Cloud Discovery fed by Defender for Endpoint; list discovered storage apps with user counts | Security | Shadow IT report; sanction/unsanction decisions recorded |
| 0.9 | Inventory desktop sync clients (Defender for Endpoint software inventory) | Endpoint team | Table 4.5 complete |
| 0.10 | Define the sensitive information types for UC-08 and the optional unlabeled-content rule | Information protection owner | SIT list agreed |
| 0.11 | Agree override policy, justification options, exception process, and who reviews overrides | Security + HR/legal | Written process |
| 0.12 | Agree evidence collection, retention, and privacy notice | Legal | Decision recorded |

### Phase 1: Design sign-off (1 week)

- Review this document with all `[TBD]` fields filled.
- Confirm tier actions (4.1), the Allow-mode decision for service domains, and the optional extra activities (section 6).
- Confirm pilot group (10 to 30 users across departments that actually use the NAS devices, including at least two Mac users) and rollout rings.
- Sign-off by `[TBD]` security owner and `[TBD]` business owner.

### Phase 2: Build (1 to 2 weeks)

1. Configure all Endpoint DLP settings in 7.1.
2. Create policies EDLP-01 to EDLP-05 in 7.2, scoped to the pilot group, state **Keep it off**.
3. Build the test pack from section 9 on two Windows and one macOS pilot device.
4. Configure alert routing: DLP alerts to the SOC queue; optional Sentinel connector.
5. Write the end-user notice and the policy tip text (short, says what was blocked and where sanctioned storage is).

### Phase 3: Simulation (2 to 3 weeks)

1. Switch EDLP-01 to EDLP-05 to **Run the policy in simulation mode** (without policy tips for the first week, with policy tips for the second).
2. Run the full test pack; every expected block must appear as a simulated match.
3. Review the simulation dashboard and Activity explorer daily. Classify every match as true positive, business-needed (candidate allow-list entry), or false positive (tune condition).
4. Add missing sanctioned shares, NAS web UIs, and M365 hostnames discovered in simulation.
5. Exit criterion: zero unexplained matches for three consecutive working days; all test pack cases produce the expected simulated verdict.

Note: for the Devices location, simulation evaluates only items that are new or changed during the simulation window, so make sure pilot users actively work with labeled files.

### Phase 4: Block-with-override pilot (2 to 3 weeks)

1. Switch EDLP-02, EDLP-03, EDLP-04 to **Turn it on**. Temporarily set EDLP-01 actions to Block with override as well.
2. Keep the pilot group. Hold a weekly review of overrides and justifications.
3. Enable just-in-time protection for the pilot group, fallback Audit.
4. Exit criterion: override volume understood and acceptable (`[TBD]` threshold, e.g., fewer than 2 overrides per user per week after tuning); no helpdesk escalations unresolved.

### Phase 5: Enforce and roll out (4 to 8 weeks)

1. Set EDLP-01 to Block. Set JIT fallback to Block.
2. Expand scope in rings: Ring 1 (`[TBD]` ~10 % of users, 1 week), Ring 2 (~50 %, 2 weeks), Ring 3 (all). Hold at each ring for one week of clean telemetry.
3. Enable Defender for Cloud Apps unsanctioned app blocking (section 11.1) in parallel, starting with "Monitor", then "Block" for storage apps judged unsanctioned.
4. Communicate to users at each ring: what changes, where sanctioned storage is, how to request an exception.

### Phase 6: Operate

| Activity | Cadence | Owner |
| --- | --- | --- |
| Review DLP alerts and overrides; escalate Tier 3 overrides | Daily (SOC), weekly summary | SOC / `[TBD]` |
| Review new NAS, browsers, and sync clients from Defender inventory; update allow lists and restricted app groups | Monthly | Endpoint team |
| Review Cloud Discovery for new storage apps; sanction or unsanction | Monthly | Security |
| Re-test the full test pack after Defender platform updates or Windows feature updates | Quarterly | Endpoint team |
| Review label taxonomy and tier mapping; review labeling coverage | Quarterly | Information protection owner |
| Review this document and Microsoft Learn for capability changes (features in preview in this document) | Quarterly | Security |

---

## 9. Test pack and acceptance criteria

Every case is run on Windows (Edge, Chrome with extension) and macOS (Edge, Safari) unless marked. Pass = the "Expected" column.

| ID | Steps | Expected (Tier 3) | Expected (Tier 2) | Expected (unlabeled) |
| --- | --- | --- | --- | --- |
| T01 | Copy labeled file to unsanctioned UNC path in Explorer/Finder | Blocked, alert | Override prompt, justification logged | Allowed, audited |
| T02 | Save As from Word to unsanctioned UNC path | Blocked | Override prompt | Allowed |
| T03 | Copy labeled file to sanctioned UNC path and to mapped drive of same share | Allowed, no alert | Allowed | Allowed |
| T04 | Upload labeled file to NAS web UI by IP (Windows) | Blocked | Override prompt | Allowed |
| T05 | Upload labeled file to NAS web UI by hostname (Windows and macOS) | Blocked | Override prompt | Allowed |
| T06 | Upload labeled file to sanctioned NAS web UI | Allowed | Allowed | Allowed |
| T07 | Upload labeled file to three unsanctioned cloud storage sites | Blocked | Override prompt | Allowed |
| T08 | Upload labeled file to SharePoint, OneDrive for Business, Teams web, Outlook on the web | Allowed | Allowed | Allowed |
| T09 | Open labeled file in an unallowed browser | Blocked, redirect to Edge | Blocked, redirect | Allowed |
| T10 | Place labeled file in Dropbox (or other unsanctioned client) sync folder | Quarantined, placeholder, one notification | Quarantined | Synced |
| T11 | Place labeled file in OneDrive sync folder | Synced | Synced | Synced |
| T12 | Copy text from labeled file, paste in same file | Allowed | Allowed | Allowed |
| T13 | Copy text from labeled file, paste in another document / Notepad | Copy blocked | Override prompt | Allowed |
| T14 | Paste text containing a test SIT match (≥ 30 chars) into an unsanctioned website | Blocked or override per group | same | same (SIT-based) |
| T15 | Paste the same text into SharePoint | Allowed | Allowed | Allowed |
| T16 | Upload labeled file via FTP client to NAS (Windows) | Blocked | Override prompt | Allowed |
| T17 | Password-protected zip of labeled file to unsanctioned share | Override prompt (unscannable) | Override prompt | Override prompt |
| T18 | Create, label, and immediately copy to unsanctioned share | Held by JIT, then blocked | Held, then override | Held, then allowed |
| T19 | All of the above appear in Activity explorer with destination; Tier 3 events carry evidence file | Yes | Yes | Audit only |
| T20 | Device offline (Windows): T01 still blocked | Blocked | Override prompt | Allowed |

Acceptance: 100 % of Tier 3 cases pass on Windows; all documented macOS-supported cases pass on macOS; every macOS gap is listed in the residual risk register with a compensating control.

---

## 10. Known limitations and residual risks

| # | Limitation | Impact | Compensating control |
| --- | --- | --- | --- |
| L1 | Enforcement depends on the label. Unlabeled sensitive files are not caught by label rules. | Medium to high depending on labeling coverage | Default labels, auto-labeling, the optional SIT + "not labeled" rule, EDLP-03 for unscannable files |
| L2 | Paste to browser is SIT-based, not label-based, ignores text under 30 characters, and inspects the first 4 MB only. | Small snippets copied from labeled files can be pasted into websites unless the copy itself is blocked (UC-07). | Copy to clipboard = Block for Tier 3; Edge for Business Protected Clipboard (section 11.3) |
| L3 | Clipboard blocking is at copy time and blocks copying from all files in the same app while a blocked file is open. | User friction | Keep Tier 3 small; Tier 2 uses override |
| L4 | IP-based upload blocking is Windows only. | Mac users could upload to a NAS web UI reached by raw IP if the Allow-mode default somehow does not apply. In Allow mode unlisted sites are restricted regardless, so the practical gap is limited to allow-listing a sanctioned NAS by IP for Macs. | Use DNS names for sanctioned NAS; validate in T04/T05 |
| L5 | Chrome and Firefox control on Windows requires the Purview extension; on macOS the extension is unavailable. Users can run portable browsers. | Bypass via unsupported browser | Unallowed browsers list; application control (AppLocker / Intune) for browser installs; monthly software inventory review |
| L6 | Service domains Allow list is capped at 50 entries. | Enough for Microsoft 365 plus a handful of SaaS. Not enough if many sanctioned SaaS apps appear. | Move SaaS allow entries into sensitive service domain groups (100 sites × 150 groups) assigned Allow |
| L7 | FTP/SFTP control is new (GA October 2026) and documented for Windows only. | macOS FTP gap | Block outbound FTP/SFTP to NAS at the firewall for Macs; or disable FTP on NAS devices |
| L8 | WebDAV behavior not documented. | Unknown | Lab test in Phase 3; disable WebDAV on NAS where possible |
| L9 | Linux, mobile, BYOD, and personal devices are not covered. | Any sensitive file that reaches such a device is uncontrolled | Conditional Access: require compliant device for Microsoft 365; Defender for Cloud Apps session policies to block downloads to unmanaged devices (section 11.2) |
| L10 | Screenshots, photos, reading aloud, and retyping cannot be blocked. | Low-volume, deliberate exfiltration | Edge screen capture protection for browser content; Insider Risk Management for behavior analytics; accept residual risk |
| L11 | Labels from another tenant are not detected. | Files received from partners | Auto-labeling on ingest; out of scope here |
| L12 | Block with override permits the action for 1 minute on Windows after override. | A user can move several files in that window | Alert on every override; review |
| L13 | Policy changes take up to about 1 hour to sync; authorization group changes up to 24 hours. | New allow-list entries are not instant | Plan changes; communicate lead times |
| L14 | Files never saved locally (e.g., Word Save As directly to USB or share from an unsaved document) cannot be scanned. | Edge case | JIT fallback = Block; EDLP-03 |
| L15 | Encrypted archives cannot be inspected. | Deliberate bypass | EDLP-03 Block with override; alert on pattern |
| L16 | Windows Server endpoints do not classify new files after the relevant KBs. | Only if servers are in scope | Keep servers out of scope for this phase |

---

## 11. Complementary controls (recommended, not required for the core use cases)

### 11.1 Microsoft Defender for Cloud Apps: discover and block unsanctioned cloud storage

Cloud Discovery, fed by Defender for Endpoint telemetry, lists every cloud app users reach, with risk scores. Tagging an app as **Unsanctioned** pushes its domains to Defender for Endpoint network protection, which blocks access to the app entirely on onboarded devices within about three hours, regardless of file labels and regardless of browser. This is the right tool for "nobody should use Dropbox at all". Endpoint DLP is the right tool for "nobody should put *labeled* files anywhere but Microsoft 365". Use both. Prerequisites: Defender for Endpoint cloud protection and network protection on, custom network indicators enabled, Defender browser protection add-on in non-Microsoft browsers. Full-path URLs are not supported; domains are. A "warn and educate" mode exists for a softer start.

### 11.2 Defender for Cloud Apps session policies (Conditional Access App Control)

For sanctioned SaaS apps federated with Entra ID, session policies can block upload of unlabeled files, block download of labeled files to unmanaged devices, and block cut/copy/print in the browser session. This covers the BYOD gap (L9) for Microsoft 365 itself. It does not see LAN NAS traffic.

### 11.3 Microsoft Edge for Business data protection

Protected Clipboard (preview) and screen capture protection in Edge for Business restrict copy/paste out of the managed browser profile and block screenshots of protected pages. Useful against L2 and L10 for content viewed in Microsoft 365 web apps.

### 11.4 Purview Network Data Security (Microsoft Entra Global Secure Access integration, GA September 2026)

Extends DLP inspection to the network layer for traffic from managed devices, including non-Microsoft browsers, native apps, and APIs. Candidate for a later phase to close the unsupported-browser and native-app gaps (L5). Requires Global Secure Access licensing and client deployment. Not verified in depth for this document; confidence on fit: medium.

### 11.5 Network-layer hygiene

Independently of DLP: block SMB (TCP 445), FTP (21/22), and NAS web UI ports from the user VLAN to any device that is not on the sanctioned NAS list, using the LAN firewall or switch ACLs. This is coarse but it does not depend on labels or on the endpoint agent, and it covers Linux and BYOD on the LAN.

### 11.6 Insider Risk Management

Correlates DLP events with HR signals (resignation, performance) to surface sequences such as "downloaded many Tier 3 files, then attempted NAS copy, then overrode". Recommended once Phase 5 is complete and event volume is understood.

---

## 12. Open items and information needed

| # | Item | Needed for | Owner | Due |
| --- | --- | --- | --- | --- |
| O1 | Confirm the target is Defender for Cloud *Apps*, not Defender for Cloud | Section 2.3, 11 | `[TBD]` | Phase 1 |
| O2 | Sensitivity label names and tier mapping (4.1) | EDLP-01, 02, 05 | Information protection owner | Phase 0 |
| O3 | Current labeling coverage figure | Risk L1 decision | Information protection owner | Phase 0 |
| O4 | Exact Microsoft 365 hostnames to allow-list (4.2); any other sanctioned SaaS | Service domains Allow list | M365 admin | Phase 0 |
| O5 | Sanctioned NAS devices: hostnames, IPs, UNC share prefixes, web UI addresses, protocols enabled (4.3, 4.4) | Network share group, SSD group | Network team | Phase 0 |
| O6 | Unsanctioned LAN ranges (4.5) | SSD group | Network team | Phase 0 |
| O7 | Desktop sync clients present on devices (4.5) | Restricted app group | Endpoint team | Phase 0 |
| O8 | Browsers in use; decision on Chrome/Firefox extension vs. unallowed | 4.6 | Endpoint team | Phase 0 |
| O9 | Sensitive information types for paste-to-browser and the optional unlabeled rule | EDLP-04 | Information protection owner | Phase 0 |
| O10 | Override justification options, exception process, override reviewers | EDLP-02 | Security + HR/legal | Phase 0 |
| O11 | Evidence collection storage choice, retention, privacy notice | UC-12 | Legal | Phase 0 |
| O12 | Pilot users and ring membership; Entra groups | 7.3 | Security | Phase 1 |
| O13 | Whether USB, print, RDP, Bluetooth restrictions are adopted now | Section 6 | Security owner | Phase 1 |
| O14 | Firewall/ACL feasibility for 11.5 | L7, L9 | Network team | Phase 1 |
| O15 | macOS fleet size and whether macOS-specific gaps (L4, L7) are acceptable | Risk acceptance | Security owner | Phase 1 |

---

## 13. References (Microsoft Learn, accessed 2026-10-23)

- Learn about Endpoint data loss prevention: https://learn.microsoft.com/purview/endpoint-dlp-learn-about
- Configure endpoint data loss prevention settings (service domains, sensitive service domain groups, network share groups, restricted apps, auto-quarantine, unallowed browsers, VPN, network share coverage): https://learn.microsoft.com/purview/dlp-configure-endpoint-settings
- Data Loss Prevention policy reference (device actions, paste-to-browser limitations): https://learn.microsoft.com/purview/dlp-policy-reference
- Help prevent sharing of sensitive items with unauthorized cloud apps and services: https://learn.microsoft.com/purview/endpoint-dlp-create-policy-unauthorized-cloud-apps-services
- Help prevent risky user activity by monitoring or restricting access to sensitive service domains: https://learn.microsoft.com/purview/endpoint-dlp-create-policy-restrict-access-to-domains
- Help prevent leakage of sensitive content by restricting paste actions into browsers: https://learn.microsoft.com/purview/endpoint-dlp-create-policy-restrict-paste-in-browsers
- Help prevent exposure of sensitive files by configuring auto-quarantine for OneDrive sync: https://learn.microsoft.com/purview/endpoint-dlp-create-policy-auto-quarantine-for-onedrive
- Help protect files that Endpoint DLP doesn't scan: https://learn.microsoft.com/purview/dlp-create-policy-files-edlp-doesnt-scan
- Protect FTP and SFTP transfers with Endpoint DLP: https://learn.microsoft.com/purview/endpoint-dlp-ftp-sftp-short
- Just-in-time protection: https://learn.microsoft.com/purview/endpoint-dlp-learn-about-jit and https://learn.microsoft.com/purview/endpoint-dlp-get-started-jit
- Network exceptions (VPN settings): https://learn.microsoft.com/purview/endpoint-dlp-create-policy-file-activities-using-network-exceptions
- DLP simulation mode: https://learn.microsoft.com/purview/dlp-simulation-mode-learn
- Create and deploy DLP policies: https://learn.microsoft.com/purview/dlp-create-deploy-policy
- Evidence collection for file activities on devices: https://learn.microsoft.com/purview/dlp-copy-matched-items-get-started
- Onboard macOS devices into Microsoft Purview: https://learn.microsoft.com/purview/device-onboarding-macos-overview
- Endpoint DLP changes in macOS 27: https://learn.microsoft.com/purview/endpoint-dlp-macos-27-changes
- Defender for Cloud Apps, govern discovered apps using Defender for Endpoint: https://learn.microsoft.com/defender-cloud-apps/mde-govern and https://learn.microsoft.com/defender-cloud-apps/governance-discovery
- Defender for Cloud Apps session policies: https://learn.microsoft.com/defender-cloud-apps/session-policy-aad
- Edge for Business Protected Clipboard: https://learn.microsoft.com/deployedge/microsoft-edge-management-protected-clipboard
- Purview Network Data Security: https://learn.microsoft.com/purview/dlp-network-data-security-learn
- Diagnose Paste to supported browsers issues (licensing and prerequisites): https://learn.microsoft.com/troubleshoot/microsoft-365/purview/data-loss-prevention/diagnose-paste-to-supported-browser-issues
