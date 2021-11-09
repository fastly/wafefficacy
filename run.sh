#!/bin/sh

while getopts ht:p:c:w:b: flag
do
    case "${flag}" in
        h)
            echo """Usage: $0
            -t  (required) url/host to scan
            -p  (optional) report directory, defaults to ./reports
            -c  (optional) nuclei config, defaults to nuclei/config.yaml
            -w  (optional) waf version, used for reporting
            -b  (optional) google cloud storage bucket name"""
            exit 0;;
        t) target=${OPTARG};;
        p) reportPath=${OPTARG};;
        c) config=${OPTARG};;
        w) wafVersion=${OPTARG};;
        b) bucket=${OPTARG};;
    esac
done

if [ -z "$target" ]
then
    echo "-t <url/host> is required"
    exit 1
fi

# sets the payload version which corresponds to the release version of the repository, defaults to 0 if not set. 
payloadVersion=`git describe --abbrev=0 2>/dev/null | sed s'/v//'`
payloadVersion=${payloadVersion:="0"}

# sets the nuclei version
nucleiVersion=`nuclei -version 2>&1 | sed -n -e 's/^.*Version: //p'`
nucleiVersion=${nucleiVersion:="0"}

# sets the nuclei config, defaults to nuclei/config.yaml
config=${config:=nuclei/config.yaml}

# sets the report directory, defaults to ./reports
reportPath=${reportPath:=reports}

# set default for wafVersion is not specific by user
wafVersion=${wafVersion:"0"}

# create the report directory
directory=${reportPath%/*}
if [[ ! -e $directory ]]; then
    mkdir -p $directory
fi

# add timestamp to filename
filename=$directory"/report_$(date +%s).json"

nuclei -no-interactsh -no-update-templates -config $config -u $target -irr -json > $filename
sed -i '' 's/}$/,"wafVersion":"'${wafVersion}'","nucleiVersion":"'${nucleiVersion}'","payloadVersion":"'${payloadVersion:="0"}'"}/g' $filename
python3 score.py -f $filename -a xss sqli traversal cmdexe

# upload to GCS
if [ $bucket ]; then
    gzip $report --force
    gsutil cp $filename".gz" gs://$bucket
fi
