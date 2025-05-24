#!/sh
# Run wafefficacy on all the wafs in parallel
set -ex

if false
then
	colima stop || true
	colima start --memory 24

	# Must come before others
	(cd ~/src/fastly/sigsci-edge; make stop || true; make start)
	(cd ~/src/signalsciences/vuln-workbench/nginx-php; make stop||true; make up)

	oasec stop||true; for a in crs3 crs3pl2 crs4 crs4pl2; do crs stop $a||true; done;
	oasec clean
	oasec init
	oasec start; for a in crs3 crs3pl2 crs4 crs4pl2; do crs start $a; done;
fi

./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o aws.log -j aws.json -u https://d2yryd2n8yl339.cloudfront.net -c 40 &
./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o crs3.log -j crs3.json -u http://localhost:9003 -c 2 &
./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o crs3pl2.log -j crs3pl2.json -u http://localhost:9004 -c 2 &
./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o crs4.log -j crs4.json -u http://localhost:9006 -c 2 &
./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o crs4pl2.log -j crs4pl2.json -u http://localhost:9007 -c 2 &
./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o cf.log -j cf.json -u https://kegel.com/ -c 5 &
./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o oasec.log -j oasec.json -u http://localhost:9009 -c 2 &
./wafefficacy run -H "User-Agent: wafefficacy" --nodates --nonum -o se.log -j se.json -u http://localhost:9002 -c 2 &
wait
