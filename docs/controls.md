# Controls mapping

This mapping is a starting point for an organisation's own compliance assessment, not legal or audit advice. Control wording below was checked against the sources listed, except where noted. Whether these checks satisfy a control in a given organisation is a judgement for its compliance function.

The report's "Expectation" column paraphrases these controls in a few words. The text here is what they rest on.

## DORA Article 12(2)

Regulation (EU) 2022/2554, Article 12 (Backup policies and procedures, restoration and recovery procedures and methods), paragraph 2.

> "Testing of the backup procedures and restoration and recovery procedures and methods shall be undertaken periodically."

Source: [EUR-Lex, Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj). The quotation was read from a [public reproduction of Article 12](https://www.digital-operational-resilience-act.com/Article_12.html), because EUR-Lex could not be fetched automatically. Confirm it against EUR-Lex.

Supported by: `restore.completes`, `recovery.wal_continuity`, `recovery.pitr_target`, `server.starts`, `schema.fingerprint`.

## ISO/IEC 27001:2022 Annex A 8.13

Information backup. The standard is copyrighted and was not available to check, so its text is not quoted here. Compare the report's summary, "Backup copies maintained and regularly tested", with your licensed copy.

Source: [ISO/IEC 27001:2022](https://www.iso.org/standard/27001).

Supported by: `backup.freshness`, `backup.integrity`, `restore.completes`, `schema.fingerprint`, `data.row_counts`, `data.assertions`, `integrity.amcheck`.

## SOC 2 A1.3

AICPA Trust Services Criteria, Availability category, criterion A1.3. The criteria are copyrighted and were not available to check, so the text is not quoted here. Compare the report's summary, "Recovery plan procedures are tested", with your licensed copy.

Source: [AICPA Trust Services Criteria](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services).

Supported by: `restore.completes`, `rto.within_target`.

## NIS2 Article 21(2)(c)

Directive (EU) 2022/2555, Article 21 (Cybersecurity risk-management measures), paragraph 2, point (c).

> "business continuity, such as backup management and disaster recovery, and crisis management;"

Source: [EUR-Lex, Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj). The quotation was read from a [public reproduction of Article 21](https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html), because EUR-Lex could not be fetched automatically. Confirm it against EUR-Lex.

Supported by: all twelve checks.

## How a report decides a control's status

| Status | Meaning |
|---|---|
| Evidenced | The backup was restored and the server started, at least one supporting check passed, and none failed or warned |
| Partly evidenced | As above, but at least one supporting check gave a warning |
| Not evidenced | The restore was not proven, a supporting check failed, or none of them passed |

A skipped check adds nothing either way. Every control here is about being able to restore, so a drill that did not restore evidences none of them, even when the checks that ran before it failed had passed. The mapping lives in each check's `Controls()` method in `internal/checks`.

## What the evidence covers

A report is evidence of one drill: one backup, restored once, at a stated time. Periodicity comes from the sequence of signed records in the evidence log, which shows that drills actually ran and when. These controls also expect things this tool does not cover, such as policy, roles, off-site copies and business continuity planning.
