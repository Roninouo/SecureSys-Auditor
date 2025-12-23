# ✅ UX Wireframes (Text-Based, Figma-Ready)

> These wireframes are **implementation-ready** and map directly to the API.

---

## 1. Login Screen

```
+------------------------------------+
| SecureSys Auditor                   |
|------------------------------------|
| Email                               |
| [____________________]              |
| Password                            |
| [____________________]              |
|                                    |
| [ Login ]                           |
+------------------------------------+
```

**UX Notes**

* Inline validation
* Clear error states
* Password visibility toggle

---

## 2. Main Dashboard

```
+------------------------------------------------+
| Logo | Systems | Reports | Settings | User ⌄  |
+------------------------------------------------+
| Overall Risk Score: 78 (High)                   |
| Maturity Level: Managed                        |
|------------------------------------------------|
| Systems Overview                               |
|------------------------------------------------|
| Hostname      OS        Risk   Last Scan       |
| srv-prod-01   Ubuntu    82     Today           |
| srv-dev-02    Windows   45     Yesterday       |
+------------------------------------------------+
```

**UX Best Practices**

* Color-coded risk
* Scan freshness indicators
* Clickable rows

---

## 3. System Detail View

```
+-----------------------------------------------+
| System: srv-prod-01                            |
| OS: Ubuntu 22.04 | Env: Production             |
|-----------------------------------------------|
| Risk Score: 82                                 |
| Maturity: Managed                              |
|-----------------------------------------------|
| [ Run New Scan ]                               |
+-----------------------------------------------+
```

---

## 4. Scan Results

```
+------------------------------------------------+
| Scan Results – Jan 02, 2025                     |
|------------------------------------------------|
| Severity Summary                                |
| High: 3 | Medium: 5 | Low: 7                   |
|------------------------------------------------|
| Findings                                       |
|------------------------------------------------|
| HIGH   Root SSH access enabled   [ View ]      |
| MED    Outdated packages         [ View ]      |
+------------------------------------------------+
```

---

## 5. Finding Detail

```
+-----------------------------------------------+
| Finding: Root SSH Access Enabled               |
| Severity: High                                 |
|-----------------------------------------------|
| Evidence                                      |
| /etc/ssh/sshd_config                          |
| PermitRootLogin yes                           |
|-----------------------------------------------|
| Recommended Actions                           |
| - Disable root login                          |
| - Restart SSH                                 |
+-----------------------------------------------+
```

---

## 6. Report Generation

```
+-----------------------------------------------+
| Generate Report                                |
|-----------------------------------------------|
| Scan: Jan 02, 2025                             |
| Type: (•) Executive ( ) Technical              |
| Format: PDF                                   |
|-----------------------------------------------|
| [ Generate ]                                  |
+-----------------------------------------------+
```

---

## 7. UX Principles Applied

✅ Minimal cognitive load
✅ Progressive disclosure
✅ Consistent layout
✅ Clear system status
✅ Accessibility-ready
✅ Mobile-friendly structure

---
