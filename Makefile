build:
	go build ./cmd/bridge/main.go

upload:
	scp main v-central.bigb.es:bridge-root/bridge
	scp configs/example.yaml v-central.bigb.es:bridge-root/configs/example.yaml

logs:
	scp v-central.bigb.es:bridge-root/output.log ./

logs-pbcopy:
	cat output.log | pbcopy
