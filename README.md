<h1 align="center">
  <br> WAFefficacy
</h1>

<h4 align="center">Measure how well your Web Application Firewall (WAF) repels attackers!</h4>

---

## Overview

Web applications are constantly under attack, so keeping them up
to date is crucial to avoid vulnerabilities.

But according to security standards like
[PCI DSS 4.0](https://www.fastly.com/resources/datasheets/security/addressing-pci-dss-4-0-and-requirement-6-4-2),
that's not enough by itself; Web Application Firewalls (WAFs) are
now required by PCI as an additional layer of defense.

When comparing WAFs, it's good to have an objective benchmark test that measures how well they work.

That's usually expressed as "[balanced efficacy](https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf)," a number between 0% and 100%.
The higher the balanced efficacy, the closer a WAF is to the ideal of blocking
bad requests while letting good requests through.

Fastly's open source WAFefficacy tool gives a quick estimate of a
WAF's efficacy by sending a barrage of simulated malicious requests
along with simulated normal traffic, then displaying the WAF's
efficacy and a list of the individual mistakes it made.

WAFefficacy now comes preloaded with a reasonable set of simulated
requests, and you can add your own attacks if you like by simply
editing a text file.

The source code is under 500 lines of Go, and should be easy to fix, extend, or audit.

## Supported Attacks

The simulated requests supplied with WAFefficacy cover these four attack types:

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html) CMDEXE (OS command injection)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) SQLI (SQL injection)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html) TRAVERSAL (using OS paths to access sensitive information)
- [CWE-79](https://cwe.mitre.org/data/definitions/89.html) XSS (Cross-site scripting)

These are all part of OWASP's [Top 10 list](https://owasp.org/Top10/).

## Quick Start

Let's say you've installed a test version of a WAF on your Linux box, protecting http://localhost:8080, and you want to measure how well it handles attacks.

First, configure the WAF you’re testing to block attacks.
(WAFefficacy checks the HTTP status of the response, and by default it considers 403 or 406 to mean the WAF blocked the request.)

If you don't have the Go language compiler installed, run, don't walk, to https://go.dev and install a copy.

Then build WAFefficacy and run it like this:

```
$ git clone https://github.com/fastly/wafefficacy
$ cd wafefficacy
$ go build
$ ./wafefficacy -u http://localhost:8080
```

To provide a progress indicator, WAFefficacy will periodically show
how many attacks it has sent so far in the lower left corner of the window.
A full run currently consists of about 14500 attacks.

After two minutes or so, you'll see the results:

```
Fastly wafefficacy results for http://localhost:8080

Overall efficacy: 80.016%

CMDEXE    efficacy 79.804%
CMDEXE      attacks:   true positives:  374  false negatives:   38
CMDEXE     innocent:  false positives:   48   true negatives:  106

SQLI      efficacy 77.143%
SQLI        attacks:   true positives:  138  false negatives:    0
SQLI       innocent:  false positives:   32   true negatives:   38

TRAVERSAL efficacy 77.957%
TRAVERSAL   attacks:   true positives: 5068  false negatives:  120
TRAVERSAL  innocent:  false positives:   66   true negatives:   92

XSS       efficacy 85.161%
XSS         attacks:   true positives: 1496  false negatives:    4
XSS        innocent:  false positives:   10   true negatives:   24

156 innocent requests were blocked (aka false positives):
   1  CMDEXE         GET  &gt;Nice UI
...
 156  XSS           POST  Германия. 23. Реквием / Автор сценария С.

162 malicious requests were not blocked (aka false negatives):
   1  CMDEXE         GET  ;id
...
 162  XSS           POST  alert.apply(null, [1])
```

Voila!  80% isn't too bad, but you may need to tune the WAF to get that number up.  You might also want to check more WAFs to see how they compare.

To get even more information (including curl commands to reproduce those problem cases), try adding ```-j log.json``` to write a detailed log in json format.

## Options

WAFefficacy's help message lists the options it understands.  Most users won't need anything more than -u and maybe -j.

```bash
Usage:
  wafefficacy run [flags]

Flags:
      --attacks strings       which attack types to run (default [cmdexe,sqli,traversal,xss])
  -c, --concurrency int       concurrency (default 1)
  -H, --headers strings       Add a header
  -h, --help                  help for run
  -o, --report string         where to write text report; - for stdout (default "-")
  -j, --reportJson string     where to write json report; - for stdout
  -r, --response strings      WAF responses for blocked requests (default [403,406])
      --suffix string         extra get/post params, e.g. --suffix '&Submit=Submit'
  -t, --template-dir string   path to the nuclei template directory (default "nuclei-templates")
  -u, --url string            target URL to scan
  -v, --verbose               verbose
```

## How it works

This project uses the [Nuclei](https://nuclei.projectdiscovery.io/)
Go library to execute the attacks in the nuclei-templates directory,
which contains one directory per attack type.

In each attack type directory, there are two yaml files:
- ```true-positive.yaml``` (which tests whether evil payloads are blocked)
- ```false-positive.yaml``` (which tests whether good payloads are allowed through).

There are also two text files:
- ```true-positives.txt``` (which contains evil payloads, one per line)
- ```true-negatives.txt``` (which contains normal payloads that are sometimes confused with attacks, one per line).

Each payload is injected into the payload positions of requests as
defined in the templates. All requests are recorded and logged in
JSON format. The logs include request/response pairs and additional
metadata.

In order to determine whether the WAF correctly identified a request
as malicious or not, we key off of the response status code. It
defaults to look for the receipt of "406 Not Acceptable" when a
request is blocked.

In the case of a true positive test, if a 406 response is received,
that is counted as a true positive. If the response doesn't contain
a 406 response then it's counted as a false negative.

In the case of a false positive test, if a 406 response is received,
that is counted as a false positive. If the response doesn't contain
a 406 response then it's counted as a true negative.

The results are then combined to provide balanced efficacy scores
for each attack type, and then those scores are averaged to get an
overall score.

## Adding your own payloads

If you have had problems with WAFs in the past, and want to see how
new WAFs do on those payloads, you can simply add them to the
appropriate true-positives.txt and false-positives.txt files.
Each line in those files is URL-encoded before being sent in a GET
or url-encoded POST request.
(Remember to use a plain-text editor and not a
word processor like Office to edit them.)

## Adding a New Attack Type

If you would like to add a new attack type to the testing framework you can start by creating a new subdirectory with the abbreviated attack name under `nuclei-templates`.

For instance, if you want to include tests for Server-side request forgery (SSRF) you'd add `ssrf` as a sub directory.

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
$ sed 's/cmdexe/ssrv/g' < nuclei-templates/cmdexe/true-positives.yaml > nuclei-templates/ssrf/true-positives.yaml
$ sed 's/cmdexe/ssrv/g' < nuclei-templates/cmdexe/false-positives.yaml > nuclei-templates/ssrf/false-positives.yaml
```

Then edit the new templates and add the correct long names and authors.

Note that our templates are a little odd because they "match" every
request; usually Nuclei templates only match interesting requests.
(The WAF benchmarking use case isn't quite what Nuclei's authors
had in mind.)  Hence the strange negative matcher with a status
code of 1 in our templates; responses never have a status code of
1, so all responses will "match" and be delivered to our script.

For more information on the template language, see https://docs.projectdiscovery.io/templates/introduction

## Using as a torture test for a vulnerable origin server

Using WAFefficacy against an origin server isn't really very useful,
but during development, we occasionally used WAFefficacy on a real
vulnerable server, [DVWA](https://github.com/digininja/DVWA), just
for fun.
(That's why the URLs in the templates have /vulnerabilities in them; those are DVWA urls.)

Setting up DVWA is easiest if you use the docker compose method.
(Note: we had to use a year-old version because DVWA's own recent docker images seem to be broken.)

DVWA has several security levels; we set it to the lowest level for maximum carnage.
We also disable authentication as described in [the DVWA doc](https://github.com/digininja/DVWA?tab=readme-ov-file#disable-authentication).

A command to throw everything at dvwa, all at once, looks like this:
```
./wafefficacy run -u http://localhost:4280/ --suffix="&Submit=Submit" -c 10
```
A command to run just one section of the tests, and save output to a json file, looks like this:
```
./wafefficacy run -u http://localhost:4280/ --suffix="&Submit=Submit" --attack cmdexe -j cmdexe.json
```
It's fun to look through the log file cmdexe.json and see it successfully retrieving /etc/passwd :-)

## Note about comparing results with those of other WAF benchmarking tools

The efficacy reported by a WAF benchmark tool like WAFefficacy
depends strongly on the attacks and normal traffic it generates.
It's possible for the same WAF to get very different scores from
different benchmark tools.

So... don't compare scores from different WAF benchmarks.
Instead, compare how they rank WAFs.  One would hope
that benchmarks X, Y, and Z would rank WAFs similarly;
if they don't, that's interesting, and you probably
want to look into what's different about the benchmarks.

For instance, WAFefficacy does not yet inject payloads
into HTTP headers; this is a significant limitation.
(A future version should fix this.)

Conversely, another popular WAF efficacy benchmark tool only includes
a very small number of attacks, which is also a significant limitation.
Happily, WAFefficacy doesn't suffer much from this (though it could
still certainly use more SQLI attacks).

## Provenance of test data

The true positive payload files mostly come from the fabulous
[mgm-sp/WAF-Payload-Collection](https://github.com/mgm-sp/WAF-Payload-Collection),
which graciously collected MIT- and GNU-licensed payloads from
across the web and formatted them for use with WAFefficacy.
(That means the payload files are under an mix of licenses;
a future release may sort them out into separate files by license.)
We also ran [sqlmap](https://github.com/sqlmapproject/sqlmap) and
[ghauri](https://github.com/r0oth3x49/ghauri) against DVWA, and
added the few working payloads they found.

In the interests of keeping test runs to around two minutes,
we only used payloads that seemed to work when sent to an internal
very very vulnerable server running on a Linux box using a variety
of DMBS servers (including MS SQL!), and we shortened sleep times
in the attacks to one second.

The false positive payload files also came from that collection,
augmented with a few tests from the [OWASP CRS project](https://coreruleset.org)
test suite and bug tracker, plus a few phrases from
[ancient reddit posts](https://www.reddit.com/r/datasets/comments/3bxlg7/i_have_every_publicly_available_reddit_comment/)
that look kinda like attacks if you squint at them.

The aforementioned curation of test data was done without attempting
to bias the results towards or away from any one WAF, though some
bias may have snuck in accidentally; caveat emptor.

## Improvements

Later versions of WAFefficacy will likely:
- add more attack types (or you can add your own now as described above, and submit them as a pull request)
- inject attacks into HTTP headers
- inject attacks into JSON bodies
- expand the true-positives.txt and false-positives.txt test sets
etc. etc.

We welcome bug reports and pull requests via the Github repository, https://github.com/fastly/wafefficacy

## Release History

WAFefficacy was first released in Decmeber, 2021; see [original blog post](https://web.archive.org/web/20211214194720/https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf).

It was overhauled in May 2025 to simplify installation and have a useful set of attack vectors ready to run.
