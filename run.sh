#!/bin/bash

while getopts ht:b:c:i:k:o:p:r:w:v flag
do
    case "${flag}" in
        h)
            echo "Usage: $0
            -t  (required) url/host to test against
            -b  (optional) google cloud storage bucket name
            -c  (optional) nuclei config, defaults to nuclei/config.yaml
            -i  (optional) input json file with efficacy assertions for each attack type
            -k  (optional) number of decimal places in percentages
            -o  (optional) output json file with efficacy scores
            -p  (optional) report directory, defaults to ./reports
            -r  (optional) custom waf response, defaults to 406 Not Acceptable
            -w  (optional) waf version, used for reporting
            -v  (optional) verbose output, shows current test"
            exit 0;;
        t) target=${OPTARG};;
        b) bucket=${OPTARG};;
        c) config=${OPTARG};;
        i) assertions=${OPTARG};;
        k) precision=${OPTARG};;
        o) outfile=${OPTARG};;
        p) reportPath=${OPTARG};;
        r) wafResponse=${OPTARG};;
        w) wafVersion=${OPTARG};;
        v) verbose='-v';;
        *) exit 1;;
    esac
done

if [ -z "$target" ]
then
    echo "-t <url/host> is required"
    exit 1
fi

# sets the precision of percentages in output (default: 1)
precision=${precision:-1}

SRCDIR="$(cd "$(dirname $0)"; pwd)"

# sets the payload version which corresponds to the release version of the repository, defaults to 0 if not set. 
git describe --abbrev=0 || true
payloadVersion=0
if git describe --abbrev=0 2>/dev/null | sed s'/v//' > payloadVersion.tmp
then
	payloadVersion=$(cat payloadVersion.tmp)
	rm payloadVersion.tmp
fi

# sets the nuclei version
nuclei -version
nucleiVersion=$(nuclei -version 2>&1 | sed -n -e 's/^.*Version: //p')

# sets the nuclei config, defaults to nuclei/config.yaml
config=${config:=nuclei/config.yaml}

# sets the report directory, defaults to ./reports
reportPath=${reportPath:=reports}

# set default for wafVersion is not specific by user
wafVersion=${wafVersion:="0"}

wafResponse=${wafResponse:="406 Not Acceptable"}

if test $assertions
then
  assertionsOpt="-i $assertions"
fi

if test $outfile
then
    outfileOpt="-o $outfile"
fi

# create the report directory
if ! test -d $reportPath; then
    mkdir -p $reportPath
fi

# add timestamp to filename
filename="$reportPath/report_$(date +%s).json"

nuclei -no-interactsh -disable-update-check -stats -config $config -u $target -irr -jsonl $verbose > $filename

# check if using GNU sed, if not then -i requires passing an empty extension
if sed v < /dev/null 2> /dev/null;  then
    sed -i "s/}$/,\"wafVersion\":\"${wafVersion}\",\"nucleiVersion\":\"${nucleiVersion}\",\"payloadVersion\":\"${payloadVersion:=\"0\"}\"}/g" $filename
else
    sed -i '' "s/}$/,\"wafVersion\":\"${wafVersion}\",\"nucleiVersion\":\"${nucleiVersion}\",\"payloadVersion\":\"${payloadVersion:=\"0\"}\"}/g" $filename
fi

if ! python3 "${SRCDIR}"/score.py -f $filename -k $precision -r "$wafResponse" $assertionsOpt $outfileOpt
then
    exit 1
fi

# upload to GCS
if [ $bucket ]; then
    gzip $report --force
    gsutil cp $filename".gz" gs://$bucket
fi
