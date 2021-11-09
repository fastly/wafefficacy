<h1 align="center">
  <br> WAF Efficacy Framework
</h1>

<h4 align="center">Measures the effectiveness of your Web Application Firewall (WAF)</h4>

---
The WAF efficacy framework provides a standardized way to measure the effectiveness of a WAF’s detection capabilities. It provides the ability to perform continuous assessments of simulated attacks to test different attack types and distills the results into an overall score that can be used for point in time knowledge or trends of effectiveness. This project contains some initial code and templates to get started.

## Dependencies

* [Nuclei](https://nuclei.projectdiscovery.io/)
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

This project defines two Nuclei templates for each attack type, one template for **true positives** and the other template for **false positives**. A true positive template will test if a legitimate attack was correctly identified as malicious and a false positive template will test if an acceptable payload is incorrectly identified as malicious. 

All requests recorded are logged in JSON format and include request/response pairs and additional metdata. A score is then calculated or each attack type and an overall score.

For historical comparisons and insights we recommend exporting the results to a backend of your choice. This project makes use of Google Cloud Storage (GCS). The results are uploaded to GCS, a table is created from the dataset, then is connected to data studio to generate informative dashboards and reports. If you'd like to learn more about how to set this up you can follow the documentation on [visualizing BigQuery data using Data Studio](https://cloud.google.com/bigquery/docs/visualize-data-studio)  
