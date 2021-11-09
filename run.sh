#!/bin/sh

while getopts t:p:c:v:b: flag
do
    case "${flag}" in
        t) target=${OPTARG};;
        p) reportPath=${OPTARG};;
        c) config=${OPTARG};;
        v) wafVersion=${OPTARG};;
        b) bucket=${OPTARG};;
    esac
done

if [ -z "$target" ]
then
    echo "-t <url/host> is required"
    exit 1
fi

# sets the payload version which corresponds to the release version of the reposiroty, defaults to 0 in not set. 
payloadVersion=`git describe --abbrev=0 2>/dev/null | sed s'/v//'`
# sets the nuclei version
nucleiVersion=`nuclei -version 2>&1 | sed -n -e 's/^.*Version: //p'`
# sets the nuclei config, defaults to nuclei/config.yaml
config=${config:=nuclei/config.yaml}
# sets the report directory, defaults to /reports
reportPath=${reportPath:=reports}
# create the report directory
directory=${reportPath%/*}
if [[ ! -e $directory ]]; then
    mkdir -p $directory
fi

# add timestamp to filename
filename=$directory"/report_$(date +%s).json"

nuclei -no-interactsh -no-update-templates -config $config -u $target -irr -json > $filename
sed -i '' 's/}$/,"wafVersion":"'${wafVersion:="0"}'","nucleiVersion":"'${nucleiVersion:="0"}'","payloadVersion":"'${payloadVersion:="0"}'"}/g' $filename
report=$directory"/report_$(date +%s).json"
jq -s '.' $filename > $report
rm $filename
python3 score.py -f $report -a xss sqli traversal cmdexe

# upload to GCS
if [ $bucket ]; then
    gzip $report --force
    gsutil cp $filename".gz" gs://$bucket
fi
