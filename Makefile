wafefficacy: main.go wafefficacy.go lib/objects.go
	go build

install:
	go install

clean:
	rm -f wafefficacy
