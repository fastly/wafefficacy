#!/bin/bash
set -x

while getopts ht:k:o:m:p:c:w:b:r: flag
do
    case "${flag}" in
        h)
            echo """Usage: $0
            -t  (required) url/host to test against
            -k  (optional) number of decimal places in percentages
            -p  (optional) report directory, defaults to ./reports
            -c  (optional) nuclei config, defaults to nuclei/config.yaml
            -w  (optional) waf version, used for reporting
            -b  (optional) google cloud storage bucket name
            -m  (optional) input file for minimum efficacy for each attack type
            -o  (optional) output file for efficacy for each attack type
            -r  (optional) custom waf response, defaults to 406 Not Acceptable"""
            exit 0;;
        t) target=${OPTARG};;
        k) precision=${OPTARG};;
        p) reportPath=${OPTARG};;
        c) config=${OPTARG};;
        w) wafVersion=${OPTARG};;
        b) bucket=${OPTARG};;
        o) outputPath=${OPTARG};;
        m) minimaPath=${OPTARG};;
        r) wafResponse=${OPTARG};;
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
payloadVersion=`git describe --abbrev=0 2>/dev/null | sed s'/v//'`
payloadVersion=${payloadVersion:="0"}

# sets the nuclei version
nucleiVersion=`nuclei -version 2>&1 | sed -n -e 's/^.*Version: //p'`
nucleiVersion=${nucleiVersion:="0"}

# sets the nuclei config, defaults to nuclei/config.yaml
config=${config:=nuclei/config.yaml}

# sets the report directory, defaults to ./reports
reportPath=${reportPath:=reports}

# sets the short report filename, if any
if test "$outputPath"
then
    outputPathOpt="-o$outputPath"
fi

# sets the minima input filename, if any
if test "$minimaPath"
then
    minimaPathOpt="-m$minimaPath"
fi

# set default for wafVersion is not specific by user
wafVersion=${wafVersion:"0"}

# create the report directory
directory=${reportPath%/*}
if [[ ! -e $directory ]]; then
    mkdir -p $directory
fi

# add timestamp to filename
filename=$directory"/report_$(date +%s).json"

nuclei -no-interactsh -disable-update-check -config $config -u $target -irr -json > $filename

# check if using GNU sed, if not then -i requires passing an empty extension
if sed v < /dev/null 2> /dev/null;  then
    sed -i 's/}$/,"wafVersion":"'${wafVersion}'","nucleiVersion":"'${nucleiVersion}'","payloadVersion":"'${payloadVersion:="0"}'"}/g' $filename
else
    sed -i '' 's/}$/,"wafVersion":"'${wafVersion}'","nucleiVersion":"'${nucleiVersion}'","payloadVersion":"'${payloadVersion:="0"}'"}/g' $filename
fi

if [ "$wafResponse" ]; then
    python3 "${SRCDIR}"/score.py -f $filename -k $precision $outputPathOpt $minimaPathOpt -r "$wafResponse"
else
    python3 "${SRCDIR}"/score.py -f $filename -k $precision $outputPathOpt $minimaPathOpt
fi

# upload to GCS
if [ $bucket ]; then
    gzip $report --force
    gsutil cp $filename".gz" gs://$bucket
fi
