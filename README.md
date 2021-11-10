<h1 align="center">
  <br> WAF Efficacy Framework
</h1>

<h4 align="center">Measures the effectiveness of your Web Application Firewall (WAF)</h4>

---
The WAF efficacy framework provides a standardized way to measure the effectiveness of a WAF’s detection capabilities. It provides the ability to perform continuous assessments of simulated attacks to test different attack types and distills the results into an overall score that can be used for point in time knowledge or trends of effectiveness. This project contains some initial code and templates to get started.

## Dependencies

Before performing an efficacy test you’ll need to ensure the WAF you’re testing against is configured to block attacks and a response status code set that is used for blocked requests. By default, it checks for the receipt of “406 Not Acceptable” when a request is blocked. 

* [Nuclei 2.5.3](https://nuclei.projectdiscovery.io/)
* [python3](https://www.python.org/downloads/)

## Usage

A shell script is available and it’s ready to run once you've installed the dependencies. 

The shell script takes a few command line arguments:

```yaml
-t  (required) url/host to scan
-p  (optional) report directory, defaults to ./reports
-c  (optional) nuclei config, defaults to nuclei/config.yaml
-w  (optional) waf version, used for reporting
-b  (optional) google cloud storage bucket name
-r  (optional) custom waf response, defaults to 406 Not Acceptable
```
Only `-t`  is required which is the url/host to test against. 

```sh
./run.sh -t <url/host>
```

This project tracks the payload version, waf version, and nuclei version used during an assessment. The underlying dependencies can also affect score results so it's import to track them to help provide context as to why a score might have increased or decreased.

`payload version` - This corresponds to the release version of this repository, defaults to 0 if not set. We suggest creating a new release version every time you add or remove test payloads.

`waf version` - This corresponds to vendor versioning and/or when changes have been made to your WAF. This is a user supplied argument (cli argument -w) and is specific to your setup. We recommend tracking this in which ever way best suits your needs.   

`nuclei version` - This corresponds to the version of nuclei used when the test is performed. 

## How it works

This project utilizes [Nuclei](https://nuclei.projectdiscovery.io/) to augment the manual, repetitive process of simulating attacks through the use of YAML-based templates. 

The project contains a directory called `nuclei` that has two subdirectories. One for `payloads` and one for `templates`. For each attack type we define two templates and two sets of payloads. One template and corresponding payload list for **true positives** and another template and corresponding payload list for **false positives**. A true positive template will test if a legitimate attack was correctly identified as malicious and a false positive template will test if an acceptable payload is incorrectly identified as malicious. 

The project provides examples for Command Execution `cmdexe`, SQL Injection `sqli`, Traversal `traversal`, and Cross-Site Scripting `xss`. 

Each payload is injected into the payload positions of requests as defined in the templates. All requests are recorded and logged in JSON format. The logs include request/response pairs and additional metadata. 

In order to determine whether the WAF correctly identified a request as malicious or not, we key off of the response code. Most WAF solutions should be able to support creating a custom response code for blocked requests. If you’re unable to create a custom response code you can key off of the vendor provided response code. However, within the context of our framework we currently look for the receipt of "406 Not Acceptable" when a request is blocked.

In the case of a true positive test, if a 406 response is received, that is counted as a true positive. If the response doesn't contain a 406 response then it's counted as a false negative. 

In the case of a false positive test, if a 406 response is received, that is counted as a false positive. If the response doesn't contain a 406 response then it's counted as a true negative.

The results are then calculated to provide efficacy scores for each attack type and overall. 

## Adding a New Attack Type

If you would like to add a new attack types to the testing framework you can start by creating new subdirectory with the abbreviated attack name under `nuclei/templates` and `nuclei/payloads`. 

For instance if you want to include tests for Server-side request forgery (SSRF) you'll add `ssrf` as a sub directory.

```
mkdir nuclei/templates/ssrf && mkdir nuclei/payloads/ssrf
```
Then create and populate two lists of attack payloads, one for true positives and false positives.

```
touch nuclei/payloads/ssrf/true-positives.txt && touch nuclei/payloads/ssrf/false-positives.txt
```

Then create two nuclei templates, one for true positives and false positives.

```
touch nuclei/templates/ssrf/true-positives.yaml && touch nuclei/templates/ssrf/false-positives.yaml
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

requests:
  - payloads:
      ssrf: nuclei/payloads/ssrf/true-positives.txt

    raw:
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

requests:
  - payloads:
      ssrf: nuclei/payloads/ssrf/true-positives.txt

    raw:
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

    matchers:
      - type: status
        status:
          - 1
        negative: true
```

## Improvements & Considerations

For historical comparisons and insights we recommend exporting the results to a backend of your choice. We've included a command line argument to upload your results to a Google Cloud Storage (GCS) bucket. Results can be uploaded and a table can be created in BigQuery. You can then connect your dataset to Data Studio and generate informative dashboards and reports. If you'd like to learn more you can follow the documentation on [visualizing BigQuery data using Data Studio](https://cloud.google.com/bigquery/docs/visualize-data-studio). 
