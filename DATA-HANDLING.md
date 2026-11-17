# How net-audit handles data

This describes what the web dashboard stores, for how long, and who can see
it, as the code in `frontends/web` works today. It is a technical
description, not a privacy policy or a contract: an operator who offers the
dashboard to others still needs their own terms and privacy policy.

The command-line auditor stores nothing. It reads the files it is given and
writes a report to standard output or to the file named with `--output`.

## What is never stored

| Data | What happens to it |
|---|---|
| Uploaded configuration files | Written to a scratch folder, audited, and deleted as soon as the audit finishes, whether it worked or not (`api_audit` in `app.py`). |
| Configurations fetched from a source (Git, Oxidized, folder) | Cloned or copied into a scratch folder, audited, and deleted when the run ends (`run_source` in `intake.py`). The original files of a "folder" source are never changed. |
| Passwords | Only a salted hash is stored (Werkzeug `generate_password_hash`). |
| API tokens | Only a SHA-256 hash is stored. The token is shown once, when it is created. |
| Password-reset and invitation links | Only a SHA-256 hash of the link's token is stored, with an expiry time. |
| Full custom SNMP community strings | The auditor reduces any community that is not a well-known default to its first two characters before it reaches a report. |

## What is stored

Everything below is kept in MongoDB when `MONGODB_URI` is set, otherwise in
one SQLite file (`net-audit.db`) in the data directory. Every record except
a user's own account carries the id of the organization it belongs to.

| Record | Contents | Kept until |
|---|---|---|
| Organization | Name; integration settings (see below) | No delete function yet |
| User | Email, name, role, password hash, last sign-in time, failed sign-in count | Deactivated by an admin; no delete function yet |
| Audit | The report: device host names, vendor, OS version, score, findings (rule, severity, the section of the config concerned, a line number, description, remediation); the names of the uploaded files; who ran it and when | An admin deletes it |
| Device | Host name, vendor, OS version, site, owner, notes, current score and counts, time of the last audit | An admin removes the device |
| Score history | One score and set of counts per device per audit | The device is removed |
| Finding | Rule, severity, section, description, remediation, state, assignee, risk-acceptance reason and expiry, ticket key and link, a history of who did what | The device is removed |
| Drift alert | Device, what changed, when, who acknowledged it | The device is removed |
| Source | Name, kind, address or path, branch, schedule, last result, and the **credential as entered** (access token or password) | An admin removes the source |
| API token | Name, role, hash, creator, time of last use | An admin revokes it |
| Audit log | Time, user, action, target, short detail, source IP address | No delete function yet |

Finding text can quote small parts of a configuration: interface names, ACL
names, an NTP server address, the first two characters of an SNMP community.
It does not contain passwords, keys or whole configuration lines.

### Secrets stored as entered

These are kept in the database in readable form, because the dashboard has
to send them to another system. They are never sent back to a browser or
returned by the API; forms show only whether one is saved.

* A source's access token or password (Git, Oxidized)
* The Slack webhook address
* The Jira API token and the ServiceNow password

Protect the database accordingly: limit who can read the `/data` volume or
the MongoDB database, and give integrations accounts with the least access
they need.

## Who can see what

* A signed-in user, or an API token, reads and writes only the records of
  its own organization. Every route checks this on the server.
* Within an organization, **viewers** can read everything except user
  management, tokens, integration settings and the audit log; **auditors**
  can also run audits and change findings and devices; **admins** can do
  everything, including deleting audits and devices.
* Whoever operates the server or the database can read everything in it.
* The audit log records sign-ins, audits run, reports viewed and exported,
  deletions, and changes to users, tokens, sources, integrations and
  findings.

## What leaves the server

Only what an administrator configures:

| Destination | What is sent |
|---|---|
| Git host, Oxidized server | A request for the configurations, with the saved credential |
| Slack webhook, alert email addresses | Drift alerts: organization name, device host name, score change or rule ids |
| Jira, ServiceNow | For a ticket: device host name, rule, severity, section, description, remediation, control ids |
| Report email addresses | The executive PDF |
| SMTP server | Invitation and password-reset links, and the messages above |
| Browser | Pages load two web fonts from Google Fonts unless `NET_AUDIT_OFFLINE=1` |

The dashboard sends no usage data or telemetry anywhere.

## Gaps to close before offering this to customers

* There is no function to delete an organization, a user, or audit-log
  entries, and no retention period that removes old audits by itself.
* Integration credentials are not encrypted in the database.
* Sessions are signed cookies valid for 12 hours; there is no multi-factor
  sign-in or single sign-on.
* Terms of service and a privacy policy do not exist yet.
