<h1 align="center">
  <br> WAFefficacy
</h1>

<h4 align="center">Measure how well your Web Application Firewall (WAF) works</h4>

---

## Overview

Web applications are constantly under attack, so keeping them up
to date is crucial to avoid vulnerabilities.

But according to security standards like
[PCI DSS 4.0](https://www.fastly.com/resources/datasheets/security/addressing-pci-dss-4-0-and-requirement-6-4-2),
that's not enough by itself; PCI now requires Web Application Firewalls (WAFs)
as an additional layer of defense.

Which raises the question: how well does your WAF (or the ones you're considering) work?

The answer is often expressed as
"[balanced accuracy](https://en.wikipedia.org/wiki/Precision_and_recall#Imbalanced_data),"
a number between 0% and 100%.  The higher the balanced accuracy,
the closer a WAF is to the ideal of blocking bad requests while
letting good requests through.  (A waf that always blocks, or
never blocks, would score 50%.  It's hard to score below 50%, but it does happen.)

One quick way to estimate balanced accuracy is by running Fastly's
open source WAFefficacy tool.  WAFefficacy probes the WAF using
thousands of simulated malicious requests, then displays the WAF's
balanced accuracy and a list of the individual mistakes it made.

The payloads supplied with WAFefficacy cover four attack types from OWASP's [Top 10 list](https://owasp.org/Top10/):

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html) CMDEXE (OS command injection)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) SQLI (SQL injection)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html) TRAVERSAL (using OS paths to access sensitive information)
- [CWE-79](https://cwe.mitre.org/data/definitions/89.html) XSS (Cross-site scripting)

as well as the infamous log4shell from CISA.GOV's Known Exploited Vulnerablities catalog:
- [CWE-917](https://cwe.mitre.org/data/definitions/917.html) [CVE-2021-44228](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=cve-2021-44228)

You can add more attacks or attack types if you like; see the Appendix below.

## Quick Start

Let's say you have installed a test version of a WAF on your Linux box, protecting http://localhost:8080, and want to measure how well it handles attacks.

First, configure the WAF you’re testing to block attacks.
(WAFefficacy checks the HTTP status of the response, and by default it considers 403 or 406 to mean the WAF blocked the request.)

Then verify that Go 1.24 or higher is installed:
```
$ go version
go version go1.24.2 darwin/arm64
```
If no go is found, or an older version is installed, you'll need to install or update, e.g. by downloading from https://go.dev.

Then build WAFefficacy:

```
$ git clone https://github.com/fastly/wafefficacy
$ cd wafefficacy
$ go build
```

Finally, run WAFefficacy against your WAF:
```
$ ./wafefficacy -u http://localhost:8080
```

To provide a progress indicator, WAFefficacy will periodically show
how many attacks it has sent so far in the lower left corner of the window;
after about 6,300 attacks (about one minute for a local WAF), it will output sorted results.

Here's what results might look like for a hypothetical near-ideal WAF:

```
WAFefficacy results for http://localhost:8080/

overall balanced accuracy: 99.99%

                                   blocked            not blocked
CMDEXE    attacks:    true positives: 1480  false negatives:   20
CMDEXE    innocent:  false positives:    1   true negatives:  149
CMDEXE    balanced accuracy 99.9%

                                   blocked            not blocked
SQLI      attacks:    true positives:  140  false negatives:    0
SQLI      innocent:  false positives:    0   true negatives:   70
SQLI      balanced accuracy 100.0%

                                   blocked            not blocked
TRAVERSAL attacks:    true positives: 5000  false negatives:    0
TRAVERSAL innocent:  false positives:    0   true negatives:  150
TRAVERSAL balanced accuracy 100.0%

                                   blocked            not blocked
XSS       attacks:    true positives:  500  false negatives:    0
XSS       innocent:  false positives:    0   true negatives:   34
XSS       balanced accuracy 100.0%

1 innocent requests were blocked (aka false positives) (shown using go's %q):
   1  CMDEXE         GET  "&gt;Nice UI"

20 malicious requests were not blocked (aka false negatives) (shown using go's %q):
   1  CMDEXE         GET  "foo;id -A"
...
```

To get even more information, add ```-j log.json``` to write a
detailed log in json format.

To extract curl commands from the json log, use the command
```
$ jq -r '.E[]."curl-command"' log.json
```

## Options

WAFefficacy's help message lists the options it understands.  Most
users won't need anything more than -u and maybe -j.

If you're testing a remote WAF, and it's taking a long time, try -c 10.

```bash
$ ./wafefficacy run --help

Run WAF Efficacy Tests

Usage:
  wafefficacy run [flags]

Flags:
      --attacks strings       which attack types to run (default [cmdexe,sqli,traversal,xss])
  -c, --concurrency int       concurrency (default 1)
  -H, --headers strings       Add a header
  -h, --help                  help for run
      --nodates               replace Date headers in json output with Jan 1, 1970
  -n, --nonum                 don't number detailed results
  -o, --report string         where to write text report; - for stdout (default "-")
  -j, --reportJson string     where to write json report; - for stdout
  -r, --response strings      WAF responses for blocked requests (default [403,406])
      --suffix string         extra get/post params, e.g. --suffix '&Submit=Submit'
  -t, --template-dir string   path to the nuclei template directory (default "nuclei-templates")
  -u, --url string            target URL to scan
  -v, --verbose               verbose
```

```--nonum``` is handy if you want to diff two log files.

```--nodates -H "User-Agent: wafefficacy"``` is handy if you want to diff two json files.


## Scoring

WAFefficacy examines the response status code to determine whether
the WAF correctly identified a request as malicious or not. By
default, it treats 403 and 406 response codes as 'blocked'.

For payloads in nuclei-templates/*/true-positives.txt, if the request is blocked,
it's counted as a true positive; else it's counted as a false negative.

For payloads in nuclei-templates/*/false-positives.txt.encoded, if the request is blocked,
it's counted as a false positive; else it's counted as a true negative.

The results are combined as described in this 
[blog post](https://web.archive.org/web/20211214194720/https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf).
to provide balanced accuracy scores for each attack type.

The attack types' balanced accuracy scores are then averaged to form
a final overall score.

## Note about comparing results with those of other WAF benchmarking tools

The balanced accuracy reported by any WAF benchmark tool depends
strongly on the attacks and normal traffic it generates, and how
it calculates its overall score.
It's possible for the same WAF to get very different scores from
different benchmark tools.

So... don't compare scores from different WAF benchmarks.
Instead, compare how they rank WAFs.  One would hope
that benchmarks X, Y, and Z would rank WAFs similarly;
if they don't, that's interesting, and worth investigating.

## Benign Payloads

WAFs process both parseable and unparseable payloads.

To model parseable benign payloads, this benchmark uses the first 6KB
(without embedded quoted messages) of each the first 1000 messages from
https://archive.org/details/FULL-USENET-BACKUP-2020-Oct-rec.arts.books.tolkien.104589.mbox.7z
and omits any that every WAF tested passed through unblocked.

Because log4shell is harder to trigger randomly than the other attack
types, we added eleven more interesting false positives, ranging from easy to hard.

To model unparseable benign payloads, this benchmark then adds at least
fifty 180-byte random ASCII strings.
If there were more than 50 plain text benign payloads, it adds
as many random benign payloads as there are plain text benign payloads.

## Malicious Payloads

The malicious, or true positive, payload files come from the
[mgm-sp/WAF-Payload-Collection](https://github.com/mgm-sp/WAF-Payload-Collection),
whose authors graciously collected MIT- and GNU-licensed payloads from
across the web and formatted them for use with WAFefficacy.
(This collection is well known to WAF vendors, see e.g. https://github.com/coreruleset/coreruleset/issues/3383 )

In the interest of keeping runtimes against local vulnerable servers
short, we shortened sleep times in the attacks to one second.

We omitted or fixed payloads that did not successfully exploit
a very very vulnerable server running on a Linux box using a variety of DMBS servers
(including [MS SQL](https://learn.microsoft.com/en-us/sql/linux/sql-server-linux-setup)).

We also added a few true positives found by running SQLI attack tools
[sqlmap](https://github.com/sqlmapproject/sqlmap) and
[ghauri](https://github.com/r0oth3x49/ghauri) against DVWA (see Appendix 3),
as well as a couple true positive log4shell cases
from https://www.mdpi.com/2079-9292/12/14/3177
and https://securitylabs.datadoghq.com/articles/the-gift-that-keeps-on-giving-a-new-opportunistic-log4j-campaign.

## How it works

This project uses the [Nuclei](https://nuclei.projectdiscovery.io/)
Go library to execute the attacks in the nuclei-templates directory,
which contains one directory per attack type.

In each attack type directory, there are two yaml files:
- ```true-positive.yaml``` (which tests whether evil payloads are blocked)
- ```false-positive.yaml``` (which tests whether innocent payloads are allowed through).

There are also two text files:
- ```true-positives.txt``` (evil payloads, plain text, one per line; will be urelencoded when sent)
- ```false-positives.encoded``` (innocent payloads, already urlencoded, one per line)

Each payload is injected into the payload positions of requests as
defined in the templates. All requests can be recorded and logged in
JSON format. The logs include request/response pairs and additional
metadata.

## Limitations

The current version of WAFefficacy has some known limitations:

- Payloads are always sent as application/x-www-form-urlencoded POST bodies
- Only five attack types are included: cmdexe log4shell sqli traversal xss
- Powershell attacks are absent from cmdexe/true-positives.txt
- True positive payloads mostly date from 2023 or earlier
- Does not support nuclei config files.

## Improvements

We welcome bug reports and pull requests via the Github repository, https://github.com/fastly/wafefficacy

## Release History

WAFefficacy was first released in December, 2021; see [original blog post](https://web.archive.org/web/20211214194720/https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf).

It was overhauled in May 2025 to simplify installation and include a more useful set of attack vectors ready to run.

## Appendix 1: Adding your own payloads

Just add the new payloads to the appropriate true-positives.txt and false-positives.txt files, one payload per line.

Each line in those files is URL-encoded before being sent in a GET or url-encoded POST request.
(Remember to edit them with a plain-text editor, not a word processor like Office.)

## Appendix 2: Adding a New Attack Type

To add a new attack type, first create a subdirectory with the abbreviated attack name under `nuclei-templates`.

For instance, to include tests for Server-side request forgery (SSRF), add `ssrf` as a sub directory.

```
$ mkdir nuclei-templates/ssrf
```
Then create and populate two lists of attack payloads, one for true positives and false positives:

```
$ touch nuclei-templates/ssrf/true-positives.txt
$ touch nuclei-templates/ssrf/false-positives.txt
```

and two nuclei templates, one for true positives and false positives; it's probably easiest to copy existing ones and edit them slightly, e.g.

```
$ sed 's/cmdexe/ssrv/g' < nuclei-templates/cmdexe/true-positive.yaml > nuclei-templates/ssrf/true-positive.yaml
$ sed 's/cmdexe/ssrv/g' < nuclei-templates/cmdexe/false-positive.yaml > nuclei-templates/ssrf/false-positive.yaml
```

Then edit the new templates and add the correct long names and authors.

Note that our templates are a little odd because they "match" every
request; usually Nuclei templates only match interesting requests.
(The WAF benchmarking use case isn't quite what Nuclei's authors
had in mind.)  Hence the strange negative matcher with a status
code of 1 in our templates; responses never have a status code of
1, so all responses will "match" and be delivered to our script.

For more information on the template language, see https://docs.projectdiscovery.io/templates/introduction

## Appendix 3: Testing with DVWA

One good way to test a WAF is to use it to protect a real but very
vulnerable server, then see if attack tools like SQLmap can bypass the WAF.

One popular very vulnerable server is [DVWA](https://github.com/digininja/DVWA).

To make comparisons with attack tools easier, WAFefficacy is set up to be compatible with DVWA.
(That's why the URLs in the templates have /vulnerabilities in them; those are DVWA urls.)

Setting up DVWA is easiest with the docker compose method.
(Note: we had to use a year-old version because DVWA's own recent docker images seem to be broken.)

DVWA uses cookies for authentication.  To get a cookie:

```
$ curl -sS -c dvwa.cookie http://localhost:4280/login.php -L > /dev/null
$ CSRF=$(curl -b dvwa.cookie http://localhost:4280/login.php | awk -F value= '/user_token/ {print $2}' | sed "s/^'//" | sed "s/'.*//")
$ curl -sS -b dvwa.cookie -c dvwa.cookie -d "username=admin&password=password&user_token=${CSRF}&Login=Login" "http://localhost:4280/login.php" -L > /dev/null
$ sed -i.bak 's/impossible/low/' dvwa.cookie
$ PHPSESSID=$(awk '/PHPSESSID/{print $7}' < dvwa.cookie)
$ COOKIE="security=low;PHPSESSID=$PHPSESSID"
```

Here are examples of running WAFefficacy and other tools mentioned here against DVWA with a cookie.
(Note: use caution when running these tools, and only run them against your own service or one you have permission to scan.)
```
$ curl -sS -H "Cookie:$COOKIE" "http://localhost:4280/vulnerabilities/exec/" -d "Submit=Submit&ip=127.0.0.1%3bcat+/etc/passwd" | grep root:
$ ./wafefficacy run -H "Cookie:$COOKIE" -u http://localhost:4280/ --suffix="&Submit=Submit" -j dvwa.json
$ python commix.py --cookie="$COOKIE" --url="http://localhost:4280/vulnerabilities/exec/#" --data="ip=127.0.0.1&Submit=submit"
$ sqlmap -H "Cookie:$COOKIE" -u "http://localhost:4280/vulnerabilities/sqli/?id=1&Submit=Submit" -p id --risk=3 --level=5
```

