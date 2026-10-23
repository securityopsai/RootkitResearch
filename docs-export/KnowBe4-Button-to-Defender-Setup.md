---
title: "KnowBe4 Button to Defender Setup"
subtitle: "Routing Phish Alert Button reports into Microsoft Defender for Office 365"
date: "23 October 2026"
---

This guide makes the KnowBe4 Phish Alert Button deliver every user report into Microsoft Defender for Office 365, so each report appears on the Submissions page, raises an alert, and starts an automated investigation. Users keep the button they know, KnowBe4 keeps its simulation statistics, and nothing is installed or removed. Expect about half a day of admin work plus a day of waiting for test results.

# 1. How it works

A report travels through five stops. If any stop is misconfigured the report disappears without an error, which is why "KnowBe4 is not pushing to Defender" usually means one setting, not a broken product.

1. **User clicks the Phish Alert Button** in Outlook. The add-in packages the original mail as an .eml attachment and sends it from the user's own mailbox.
2. **The report lands in your reporting mailbox**, an ordinary Exchange Online mailbox you choose. Defender must be told not to filter this mailbox, or the attached phish gets quarantined on the way in.
3. **Defender reads the mailbox** and lists the report on the Submissions page under User reported. For this to happen, Defender's User reported settings must say "non-Microsoft add-in button" and name that exact mailbox, and the report must be in the format Defender expects.
4. **The alert "Email reported by user as malware or phish" fires.** The alert policy must be on and not auto-resolved by a tuning rule.
5. **An automated investigation starts** (Defender for Office 365 Plan 2 only). It clusters similar mails, checks who else got them, and proposes actions for the SOC to approve. Defender can email the reporter the verdict.

**The four things that must line up**

| What | Where it is set | Must be |
| --- | --- | --- |
| Button type and mailbox | Defender portal > User reported settings | Non-Microsoft add-in button, your mailbox, destination "Microsoft and my reporting mailbox" |
| Mailbox protection | Defender portal > Advanced delivery > SecOps mailbox | Your mailbox listed |
| What KnowBe4 sends | KSAT console > Account Integrations > Phish Alert | Defender integration on, EML format, same mailbox address, sent directly (not via PhishER) |
| Alert | Defender portal > Alert policy and Alert tuning | Policy on, not replaced by a custom policy, not auto-resolved unless you choose that |

KnowBe4 simulations are a special case: when a user reports a simulated phish, the button tells KnowBe4 and does **not** forward the mail. So simulations never reach Defender and never create alerts, and KnowBe4 keeps its "reported" statistics. This is a feature of this setup, not a fault.

# 2. Before you start

**Licences.** Defender for Office 365 Plan 2 (in Microsoft 365 E5 or as an add-on) for automated investigation and the feedback mail. With Plan 1 or Exchange Online Protection only, reports still show on the Submissions page and raise the alert, but nothing investigates them automatically.

**Roles.** Security Administrator in the Defender portal plus Organization Management in Exchange Online for the mailbox and PowerShell steps. An admin login to the KnowBe4 KSAT console.

**Facts to collect first.** Fill this in before changing anything, so you can see mismatches and roll back.

| Fact | Where to find it | Value |
| --- | --- | --- |
| Mailbox Defender currently expects reports in | https://security.microsoft.com/securitysettings/userSubmission, box "Add an Exchange Online mailbox to Send reported items to" | |
| Which button option Defender has selected | Same page, "Select an Outlook report button configuration" | |
| Address in KnowBe4 "Send Non-Simulated Emails to" | KSAT > Account Settings > Account Integrations > Phish Alert > your PAB instance | |
| Address in KnowBe4 "Submit Reported Emails to" and whether the Defender toggle is on | Same place | |
| KnowBe4 Email Format | Same place | EML or MSG |
| Is PhishER in use and does it forward anywhere | KSAT left menu > PhishER > Settings | |
| Is the mailbox a SecOps mailbox | https://security.microsoft.com/advanceddelivery, SecOps mailbox tab | |
| Alert policy state | https://security.microsoft.com/alertpoliciesv2, search "Email reported by user" | On / Off |
| Alert tuning rules for that alert | https://security.microsoft.com/alerttuning | |

The most common finding at this stage is three different mailbox addresses across these rows. Pick one mailbox and make every row match it in the steps below.

# 3. Step 1, Defender: make the reporting mailbox safe

**1a. Choose the mailbox.** Reuse the mailbox KnowBe4 already sends to if it is an Exchange Online mailbox in your tenant. Otherwise create a shared mailbox in the Exchange admin center at https://admin.exchange.microsoft.com under **Recipients > Mailboxes > Add a shared mailbox**, for example `phishreports@yourdomain.com`. Not allowed: a distribution group, a Microsoft 365 Group, an on-premises mailbox, or an address outside the tenant.

**1b. Mark it as a SecOps mailbox.** This stops Defender from filtering, quarantining or rewriting the phish that arrive attached to reports.

1. Open https://security.microsoft.com/advanceddelivery
2. Select the **SecOps mailbox** tab.
3. Select **Add** (or **Edit** if there are already entries).
4. Click in the box, type the mailbox address, choose it from the list.
5. Select **Add**, then **Close**. The mailbox now appears in the list.

**1c. Exclude it from data loss prevention.** Only if you have Exchange DLP policies. In https://purview.microsoft.com go to **Data loss prevention > Policies**, edit each policy that covers Exchange, and add the mailbox under the Exchange location's **Exclude** list.

**1d. Check nothing on the mailbox interferes.** In Exchange Online PowerShell:

```powershell
Connect-ExchangeOnline
Get-InboxRule -Mailbox phishreports@yourdomain.com
Get-Mailbox phishreports@yourdomain.com | Format-List ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
```

There should be no inbox rules and no forwarding. If there are, remove them; a rule that moves or deletes the reports hides them from Defender.

**Done when** the mailbox is on the SecOps mailbox tab and PowerShell shows no rules or forwarding.

# 4. Step 2, Defender: point User reported settings at the KnowBe4 button

This is the single page that decides whether Defender treats mail in your mailbox as user reports.

1. Open https://security.microsoft.com/securitysettings/userSubmission (Settings > Email & collaboration > User reported settings).
2. Tick **Monitor reported messages in Outlook**. If this is unticked, KnowBe4 reports still arrive in the mailbox but never appear on the Submissions page. This is the most common cause of "not pushing to Defender".
3. Under **Select an Outlook report button configuration**, select **Use a non-Microsoft add-in button**. This also hides Microsoft's own Report button so users see only KnowBe4's.
4. Under **Reported item destinations**, set **Send reported items to** = **Microsoft and my reporting mailbox**. "My reporting mailbox only" also works, but then Microsoft does not analyse the mail and the Submissions page shows "Not Submitted to Microsoft" until an admin submits it by hand.
5. In **Add an Exchange Online mailbox to Send reported items to**, remove any old address with the x, click in the box, wait for the list to load, and pick the mailbox from Step 1.
6. Under **Email notifications**, turn on the results email to users and choose which verdicts send it (phishing, junk, no threats found). Optional, but it is what makes users trust the button.
7. Select **Save**. Reload the page and confirm the values stuck.

**Prove it with PowerShell.** The portal hides the fact that there are two objects, a policy and a rule. Both must name the mailbox.

```powershell
Get-ReportSubmissionPolicy | Format-List EnableReportToMicrosoft, EnableThirdPartyAddress, ThirdPartyReportAddresses, ReportJunkAddresses, ReportPhishAddresses, ReportNotJunkAddresses, EnableUserEmailNotification
Get-ReportSubmissionRule | Format-List Name, SentTo, State
```

| Field | Expected |
| --- | --- |
| EnableThirdPartyAddress | True |
| ThirdPartyReportAddresses, ReportJunkAddresses, ReportPhishAddresses, ReportNotJunkAddresses | All the same: your mailbox |
| EnableReportToMicrosoft | True (False if you chose mailbox only) |
| Rule SentTo | Your mailbox |
| Rule State | Enabled |

If the rule is missing, the portal never saved a mailbox. Go back to item 5 and save again. If the addresses differ from each other, fix them in the portal, not in PowerShell, so the two objects stay in sync.

**Done when** the table above matches.

# 5. Step 3, Defender: alert policy and alert tuning

**3a. The alert policy must be on.**

1. Open https://security.microsoft.com/alertpoliciesv2
2. Search for **Email reported by user as malware or phish**.
3. Status must be **On**. If not, open it and switch it on.
4. Check there is no custom policy with a similar name that someone created to replace it. Only the built-in policy starts automated investigations; a custom copy does not.

**3b. Decide on alert tuning.** Open https://security.microsoft.com/alerttuning. Microsoft ships a rule named **Auto-Resolve - Email reported by user as malware or phish**.

| Situation | Setting |
| --- | --- |
| You want to see every user report as an open alert in the queue | Disable the rule |
| You want a quiet queue and trust the investigation verdict | Leave it enabled. Investigations still run; only the alert is closed automatically |
| You use the Security Copilot Phishing Triage Agent | Disable the rule and any custom rule for this alert. Microsoft requires this for the agent to see the alerts |

**Done when** the policy shows On and you have made a conscious choice on the tuning rule.

# 6. Step 4, KnowBe4 console

The labels below come from KnowBe4's published guidance for its Defender integration. Your console may show slightly different wording; look for the same meaning.

1. Sign in to the KSAT console and go to **Account Settings > Account Integrations > Phish Alert**.
2. Each Phish Alert Button instance is listed. Expand the one your users have with the **+** icon. If you have several instances (for example one per region), repeat for each.
3. Set **Email Format** to **EML**. Defender accepts both EML and MSG in theory, but KnowBe4 documents EML as the format for the Defender integration, and EML is also what other downstream tools expect.
4. Turn on the **Microsoft 365 Defender Integration** toggle.
5. In **Submit Reported Emails to**, enter the mailbox from Step 1, exactly as it appears in Defender.
6. **Send Non-Simulated Emails to** can keep pointing at your SOC mailbox or at the same address. Avoid sending the same report to two different mailboxes that Defender watches; one Defender mailbox is enough.
7. Select **Save Phish Alert Settings**.

**Two rules that are easy to break.**

- **The report must come from the user, not a relay.** Defender only accepts a report sent by the mailbox that received the original mail. The Phish Alert Button does this itself. If reports instead flow Button to PhishER to Defender mailbox, Defender ignores them because PhishER is the sender. Keep PhishER as a copy recipient if you like, but the Defender address must be fed directly by the button.
- **Only one report button at a time.** With the non-Microsoft option chosen in Step 2, Microsoft's own Report button is hidden, so users cannot double-report. Do not also deploy Microsoft's old Report Message or Report Phishing add-ins.

**Done when** the toggle is on, the address matches Step 2 character for character, and the format is EML.

# 7. Step 5, test the whole chain

Use your own mailbox and one pilot user. Report a real, harmless external mail such as a newsletter. Do **not** test with a KnowBe4 simulation: the button deliberately does not forward simulations, so the test would prove nothing.

| # | Check | Where to look | Expect within |
| --- | --- | --- | --- |
| 1 | Click the Phish Alert Button on the test mail | Outlook | Immediately: KnowBe4's thank-you message, mail removed from Inbox |
| 2 | Report arrived in the reporting mailbox | Open the mailbox in Outlook on the web | 5 minutes: a new mail with exactly one .eml attachment |
| 3 | Report is on the Submissions page | https://security.microsoft.com/reportsubmission?viewid=user | 15 minutes: a row with the reporting user and the original subject |
| 4 | Alert raised | https://security.microsoft.com/alerts, filter policy "Email reported by user as malware or phish" | 30 minutes |
| 5 | Investigation started | https://security.microsoft.com/airinvestigation, filter Investigation type = User-reported messages | 30 to 60 minutes: Running, then a verdict |
| 6 | Reporter received the results mail | Reporter's Inbox | After the investigation ends, up to a few hours |

If all six pass for both testers, the integration works. Ask three or four ordinary users to report something during the first week and watch the Submissions page fill.

For each check that fails, go to the row with that number in section 8.

# 8. Troubleshooting

Work from the first failed check in section 7. Each row names the usual cause and the fix.

| Failed check | Symptom | Likely cause | Fix |
| --- | --- | --- | --- |
| 2 | Nothing arrives in the mailbox at all | KnowBe4 toggle off, wrong address, or settings not saved | Step 4. Compare the address letter by letter with Step 2 |
| 2 | Nothing arrives, but only for simulations | By design: the button does not forward simulations | Not a fault. Test with a real external mail |
| 2 | Message trace shows the report as Quarantined or Filtered | Mailbox is not a SecOps mailbox | Step 1b. Release the quarantined test report afterwards at https://security.microsoft.com/quarantine |
| 2 | Trace shows Delivered but the mail is not in the Inbox | Inbox rule or forwarding on the mailbox | Step 1d |
| 3 | Report is in the mailbox but not on the Submissions page | "Monitor reported messages in Outlook" unticked, or the mailbox in Defender differs from the one KnowBe4 sends to | Step 2 items 2 and 5, then the PowerShell table |
| 3 | Same, PowerShell looks right | Report format rejected: forwarded body instead of attachment, two or more attached messages, or MSG where EML was expected | Step 4 item 3. Open one report: it needs exactly one .eml attachment that still has its original headers |
| 3 | Same, format looks right | Report sent by a service account or PhishER rather than by the user | Step 4, first rule. Point the button directly at the Defender mailbox |
| 3 | Report shows but as Phishing when the user chose junk | Subject line prefix missing; Defender treats any report without the `1\|`, `2\|` or `3\|` prefix as phishing | Cosmetic. KnowBe4 controls the prefix; raise it with KnowBe4 support if it matters |
| 4 | Row on Submissions page, no alert | Alert policy off, replaced by a custom policy, or auto-resolved by a tuning rule | Step 3 |
| 5 | Alert but no investigation | No Defender for Office 365 Plan 2 licence, or investigation throttled | Check licences at https://admin.microsoft.com/#/licenses. Throttled investigations can be started by hand from Threat Explorer |
| 6 | Investigation finished, user got no mail | Results email not enabled, or that verdict is not selected | Step 2 item 6 |

**Useful command for check 2.** Run after a test report; it shows whether the report ever reached Exchange Online and what happened to it.

```powershell
Get-MessageTrace -RecipientAddress phishreports@yourdomain.com -StartDate (Get-Date).AddHours(-2) -EndDate (Get-Date) | Format-Table Received, SenderAddress, Subject, Status
```

The SenderAddress must be the reporting user. If it is a KnowBe4 or PhishER address, you have found the cause.

# 9. Day-to-day operation

**What the SOC sees.** Every real report becomes a row on the Submissions page, an alert, and an investigation under Email & collaboration > Investigations. Investigations propose actions such as soft-deleting all copies of the mail across the tenant. Nothing is deleted automatically; every action waits for approval in the Action center at https://security.microsoft.com/action-center. Multiple users reporting the same mail are grouped into one incident.

**What users get.** KnowBe4's own thank-you pop-up straight away, and if you enabled it in Step 2, a Defender results mail once the investigation closes. The results mail is customisable in the User reported settings page, including your logo.

**What happens with KnowBe4 simulations.** Reporting a simulation records a success in KnowBe4 and sends nothing to Defender. Your KnowBe4 reporting metrics continue unchanged. Keep KnowBe4's sending domains and IP addresses listed on the **Phishing simulation** tab of https://security.microsoft.com/advanceddelivery so the simulations are delivered and are not treated as attacks; take the current values from KnowBe4's whitelisting article, since they change.

**Monthly check.** Compare the number of reports in the KnowBe4 console with the number of rows on the Submissions page for the same month, excluding simulations. A growing gap means reports are being lost again; go to section 8.

**If you later want Microsoft's built-in Report button instead.** Everything on the Defender side stays. Only Step 2 item 3 changes to "Use the built-in Report button in Outlook", and the KnowBe4 add-in is removed from Integrated apps. The companion document "Outlook Report Button Migration Plan" covers that path.

# 10. Rollback

Nothing in this guide removes or installs software, so rollback is only settings.

1. **Defender:** on https://security.microsoft.com/securitysettings/userSubmission, put the previous mailbox back (or clear it) and save. Five minutes.
2. **KnowBe4:** turn off the **Microsoft 365 Defender Integration** toggle and restore the previous addresses. Save. Five minutes.
3. **Advanced delivery:** leave the SecOps mailbox entry in place; it does no harm.

There is no user-visible change in either direction, so no communication is needed for a rollback.

# 11. Sources

Microsoft pages were read in full on 23 October 2026. KnowBe4's support site blocks automated reading, so the KnowBe4 console labels come from KnowBe4's published article summaries and should be checked against your console.

- [User reported settings](https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox): non-Microsoft button option, reporting mailbox requirements, message format rules, PowerShell cmdlets, Phishing Triage Agent prerequisites
- [Defender for Office 365 Security Operations Guide: integrate non-Microsoft reporting tools](https://learn.microsoft.com/defender-office-365/mdo-sec-ops-guide): how third-party buttons feed alerts and investigations
- [Advanced delivery policy](https://learn.microsoft.com/defender-office-365/advanced-delivery-policy-configure): SecOps mailbox and phishing simulation entries
- [Alert policies in the Microsoft Defender portal](https://learn.microsoft.com/defender-xdr/alert-policies): the "Email reported by user as malware or phish" policy and which policies start investigations
- [Automated investigation and response in Defender for Office 365 Plan 2](https://learn.microsoft.com/defender-office-365/air-about): what starts an investigation and the approval model
- [Automatic user notifications for user reported phishing results](https://learn.microsoft.com/defender-office-365/air-user-automatic-feedback-response): the results email
- [Considerations for integrating non-Microsoft security services](https://learn.microsoft.com/defender-office-365/mdo-integrate-security-service): Microsoft's position on third-party report buttons
- [KnowBe4: Integrate Microsoft Defender for Office 365 with the Phish Alert Button](https://support.knowbe4.com/hc/en-us/articles/17538935276051-Integrate-Microsoft-Defender-for-Office-365-with-the-Phish-Alert-Button-PAB): the Defender integration toggle and address field
- [KnowBe4: Phish Alert Button Product Manual](https://support.knowbe4.com/hc/en-us/articles/208969608-Phish-Alert-Button-PAB-Product-Manual): simulated reports are not forwarded, Email Format setting
