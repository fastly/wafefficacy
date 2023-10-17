<h1 align="center">
  <br> WAF Efficacy Framework
</h1>

<h4 align="center">Measures the effectiveness of your Web Application Firewall (WAF)</h4>

---
The WAF efficacy framework provides a standardized way to measure the effectiveness of a WAF’s detection capabilities. It provides the ability to perform continuous assessments of simulated attacks to test different attack types and distills the results into an overall score that can be used for point in time knowledge or trends of effectiveness. This project contains some initial code and templates to get started.

## Prerequisites

Before performing an efficacy test you’ll need to ensure the WAF you’re testing against is configured to block attacks and a response status code is set that is used for blocked requests. By default, it checks for the receipt of “406 Not Acceptable” when a request is blocked. 

## Dependencies

* [Nuclei](https://nuclei.projectdiscovery.io/)
* [Go](https://go.dev/doc/install)

## Usage

Build the project using the go build command. This command will compile your Go code into an executable binary.

```bash
go build
```

```bash
Usage:
  wafefficacy run [flags]

Flags:
      --attacks strings       list of attack types (default [cmdexe,sqli,traversal,xss])
  -c, --config string         path to the nuclei configuration file (default "config.yaml")
  -h, --help                  help for run
  -r, --response string       WAF response for blocked requests (default "406 Not Acceptable")
  -u, --target string         target URL/host to scan
  -t, --template-dir string   path to the nuclei template directory (default "nuclei-templates")
  -v, --verbose               verbose
```

## How it works

This project utilizes [Nuclei](https://nuclei.projectdiscovery.io/) to augment the manual, repetitive process of simulating attacks through the use of YAML-based templates. We've included boilerplate examples for Command Execution `cmdexe`, SQL Injection `sqli`, Traversal `traversal`, and Cross-Site Scripting `xss`. 

The project contains a directory called `nuclei` that has two subdirectories. One for `payloads` and one for `templates`. For each attack type we define two templates and two sets of payloads. One template and corresponding payload list for **true positives** and another template and corresponding payload list for **false positives**. 
* A **true positive** test will test if a legitimate attack was correctly identified as malicious.
* A **false positive** test will test if an acceptable payload is incorrectly identified as malicious. 


<h3 align="center">
  <img src="static/wafefficacy-flow.png" alt="wafefficacy-flow" width="700px"></a>
</h3>

Each payload is injected into the payload positions of requests as defined in the templates. All requests are recorded and logged in JSON format. The logs include request/response pairs and additional metadata. 

In order to determine whether the WAF correctly identified a request as malicious or not, we key off of the response status code. It defaults to look for the receipt of "406 Not Acceptable" when a request is blocked.

In the case of a true positive test, if a 406 response is received, that is counted as a true positive. If the response doesn't contain a 406 response then it's counted as a false negative. 

In the case of a false positive test, if a 406 response is received, that is counted as a false positive. If the response doesn't contain a 406 response then it's counted as a true negative.

The results are then calculated to provide efficacy scores for each attack type and overall. 

## Adding a New Attack Type

If you would like to add a new attack type to the testing framework you can start by creating new subdirectory with the abbreviated attack name under `nuclei-templates/http` and `nuclei-templates/helpers/payloads`. 

For instance if you want to include tests for Server-side request forgery (SSRF) you'll add `ssrf` as a sub directory.

```
mkdir nuclei-templates/http/ssrf && mkdir nuclei-templates/helpers/payloads/ssrf
```
Then create and populate two lists of attack payloads, one for true positives and false positives.

```
touch nuclei-templates/helpers/payloads/ssrf/true-positives.txt && touch nuclei-templates/helpers/payloads/ssrf/false-positives.txt
```

Then create two nuclei templates, one for true positives and false positives.

```
touch nuclei-templates/http/ssrf/true-positives.yaml && touch nuclei-templates/http/ssrf/false-positives.yaml
```

Each template has a template ID which is a unique ID used to specify the template name for a request type. We use the naming convention of attack type followed by the name of the test type. In our case we define a SSRF true positive template id as followed:

```yaml
id: ssrf-true-positive
```

The next piece of information of the template is the info block. The info block supports dynamic fields, so you can define N number of key: value blocks to provide more useful information about the template. For our purposes we only provide name, author, severity, and tags. **author** and **severity** are required fields. If they’re not specified you’ll encounter issues running your tests.

 ```yaml
id: ssrf-true-positive

info:
  name: Server-side request forgery (SSRF)
  author: wafefficacy
  severity: info
  tags: ssrf,true-positive
```
Payloads are defined under the payloads field beneath the info block and the actual requests are placed below. Each template can contain multiple requests that test payloads in various ways. Let’s build out our template a bit more using this information: 

```yaml
id: ssrf-true-positive

info:
  name: Server-side request forgery (SSRF)
  author: wafefficacy
  severity: info
  tags: ssrf,true-positive

http:
  - raw:
      - |
        GET /anything?p={{url_encode(ssrf)}} HTTP/1.1
        Host: {{Hostname}}
        Connection: close

      - |
        POST /anything HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Connection: close

        p={{url_encode(ssrf)}}
    
    payloads:
      ssrf: helpers/payloads/ssrf/true-positives.txt
```
In order to validate tests, Nuclei makes use of something called matchers. Matchers allow for flexible comparison of responses that determine whether a test passed or failed. However, for our purposes we want to match everything. This is because the Nuclei logs include request/response pairs and additional metadata. So in our use case, we’ll match every request that doesn’t contain a status code of 1. Since 1 is not a valid server response code we’ll never receive that response, and as a result match every request. 

The complete template will be as followed:

```yaml
id: ssrf-true-positive

info:
  name: Server-side request forgery (SSRF)
  author: wafefficacy
  severity: info
  tags: ssrf,true-positive

http:
  - raw:
      - |
        GET /anything?p={{url_encode(ssrf)}} HTTP/1.1
        Host: {{Hostname}}
        Connection: close

      - |
        POST /anything HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Connection: close

        p={{url_encode(ssrf)}}

    payloads:
      ssrf: helpers/payloads/ssrf/true-positives.txt

    matchers:
      - type: status
        status:
          - 1
        negative: true
```

## Using as regression test

To see if future runs of your efficacy test regress, use e.g. -o efficacy.json
to save the current efficacy percentages to a json file.

Then pass that file to future runs with the -i parameter, e.g. -i assertions.json,
to abort if efficacy for any attack type (or overall) falls below that in the file.

Example file:

```json
{"cmdexe": 60, "sqli": 70, "traversal": 80, "xss": 90, "overall": 75}
```


## Improvements & Considerations

For historical comparisons and insights we recommend exporting the results to a backend of your choice.
