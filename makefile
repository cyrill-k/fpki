# relevant paths
trillian ?= $(GOPATH)/src/github.com/cyrill-k/trillian
trustflex ?= $(GOPATH)/src/github.com/cyrill-k/trustflex
coredns ?= $(GOPATH)/src/github.com/cyrill-k/coredns
webext=$(trustflex)/webext

corednsconfig=$(trustflex)/dns/coredns

TRILLIAN_BIN_PATH ?= $(trillian)
TRUSTFLEX_BIN_PATH ?= $(trustflex)
COREDNS_BIN_PATH ?= $(coredns)

MYSQL_HOST ?= 127.0.0.1
mysqluri="test:zaphod@tcp($(MYSQL_HOST):3306)/test"

LOG_SERVER_HOST ?= localhost
ladmin=$(LOG_SERVER_HOST):8090
lclient=$(LOG_SERVER_HOST):8091

SIG_SERVER_HOST ?= localhost
sadmin=$(SIG_SERVER_HOST):8093
sclient=$(SIG_SERVER_HOST):8092

MAP_SERVER_HOST ?= localhost
madmin=$(MAP_SERVER_HOST):8094
mclient=$(MAP_SERVER_HOST):8095

BASE_CMD ?= cd $(TRUSTFLEX_BIN_PATH) && ./main.go
cmd=$(BASE_CMD) --log_addr=$(ladmin) --map_addr=$(madmin) --max_receive_message_size=1073741824

configdir ?= /mnt/config
debug ?= false
mapid ?= mapid1
mappk ?= mappk1
logid ?= logid1
logpk ?= logpk1
# read certs from stdin by default
certfile ?= -
# variables using := are evaluated once
logidpath := $(configdir)/$(logid)
mapidpath := $(configdir)/$(mapid)
logpkpath := $(configdir)/$(logpk).pem
mappkpath := $(configdir)/$(mappk).pem
# these variables are evaluated everytime they are called since the file content might change during make
logidvalue = $(shell cat $(configdir)/$(logid))
mapidvalue = $(shell cat $(configdir)/$(mapid))
lastidxpath = "$(configdir)/lastIdx"

# Build relevant Trillian files
build:: build_ca build_tmain build_trillian build_coredns build_webextensions
build_ca::
	cd $(trustflex) && \
	go build ca/main.go

build_tmain::
	cd $(trustflex) && \
	go build trillian/tmain/main.go

build_trillian::
	cd $(trillian) && \
	go build ./server/trillian_log_server && \
	go build ./server/trillian_log_signer && \
	go build ./server/trillian_map_server && \
	go build ./cmd/createtree && \
	go build ./cmd/deletetree && \
	go build ./cmd/get_tree_public_key

pre_build_coredns::
	cd $(coredns) && make gen

build_coredns::
	cd $(coredns) && make

build_webextensions::
	cd $(webext)/verifier && \
	go build . && ./install.sh ~/.mozilla/native-messaging-hosts && \
	cd $(webext)/txtfetcher && \
	go build . && ./install.sh ~/.mozilla/native-messaging-hosts && \
	cd $(webext)/perflogger && \
	go build . && ./install.sh ~/.mozilla/native-messaging-hosts && \
	cd $(webext)/filegenerator && \
	go build . && ./install.sh ~/.mozilla/native-messaging-hosts && \
	cd $(webext)/policyfetcher && \
	go build . && ./install.sh ~/.mozilla/native-messaging-hosts && \
	cd $(trustflex) && \
	go build trillian/verifier/verifier.go

change_netplan::
	sudo cp $(corednsconfig)/01-network-manager-all.yaml /etc/netplan/ && \
	sudo netplan --debug generate && \
	sudo netplan apply

# TRILLIAN SERVER INSTANCES
# starts a Trillian Log Server
tlserver::
	cd $(TRILLIAN_BIN_PATH) && ./trillian_log_server --rpc_endpoint=$(ladmin) --http_endpoint=$(lclient) --logtostderr --max_receive_message_size=1073741824 --mysql_uri=$(mysqluri)

# starts a Trillian Log Signer
tlsigner::
	cd $(TRILLIAN_BIN_PATH) && ./trillian_log_signer --logtostderr --force_master --rpc_endpoint=$(sadmin) --http_endpoint=$(sclient) --batch_size=2048 --mysql_uri=$(mysqluri)

# starts a Trillian Map Server
tmserver::
	cd $(TRILLIAN_BIN_PATH) && ./trillian_map_server --logtostderr --rpc_endpoint=$(madmin) --http_endpoint=$(mclient) --max_receive_message_size=1073741824 --mysql_uri=$(mysqluri)

map_dns_server::
	cd $(COREDNS_BIN_PATH) && ./coredns -conf $(configdir)/Corefile

# TREE MANAGEMENT
list_trees::
	$(cmd) --cmd=list_trees

delete_all_trees::
	$(cmd) --cmd=delete_all_trees

# creates a tree in Log mode, storing the log id and log pk in a file
createtree::
	cd $(TRILLIAN_BIN_PATH) && ./createtree --admin_server=$(ladmin) > $(logidpath) && ./get_tree_public_key --admin_server=$(ladmin) --log_id=`cat $(logidpath)` > $(logpkpath)

# creates a tree in Log mode, storing the log id and log pk in a file if the log does not exist
createtree_if_necessary::
ifeq ("$(wildcard $(lodidpath))","")
	cd $(TRILLIAN_BIN_PATH) && ./createtree --admin_server=$(ladmin) > $(logidpath) && ./get_tree_public_key --admin_server=$(ladmin) --log_id=`cat $(logidpath)` > $(logpkpath)
endif

# deletes the tree and the log-related files
deletetree::
	cd $(TRILLIAN_BIN_PATH) && ./deletetree --admin_server=$(ladmin) --log_id=`cat $(logidpath)`
	rm -f $(logidpath)
	rm -f $(logpkpath)

# creates a tree in Map mode, storing the map id and map pk in a file
createmap::
	cd $(TRILLIAN_BIN_PATH) && ./createtree --admin_server=$(madmin) --tree_type=MAP --hash_strategy=TEST_MAP_HASHER > $(mapidpath) && ./get_tree_public_key --admin_server=$(madmin) --log_id=`cat $(mapidpath)` > $(mappkpath)

# creates a tree in Map mode, storing the map id and map pk in a file if the map does not exists
createmap_if_necessary::
ifeq ("$(wildcard $(mapidpath))","")
	cd $(TRILLIAN_BIN_PATH) && ./createtree --admin_server=$(madmin) --tree_type=MAP --hash_strategy=TEST_MAP_HASHER > $(mapidpath) && ./get_tree_public_key --admin_server=$(madmin) --log_id=`cat $(mapidpath)` > $(mappkpath)
endif

# deletes the map and map-related files
deletemap::
	cd $(TRILLIAN_BIN_PATH) && ./deletetree --admin_server=$(madmin) --log_id=`cat $(logidpath)`
	rm -f $(mapidpath)
	rm -f $(mappkpath)
	rm -f $(lastidxpath)



# LOG SERVER
# adds a certificate to the Log
log_add::
	$(cmd) --cmd=log_add --log_id=`cat $(logidpath)` --log_pk=$(logpkpath) --cert_file="$(certfile)"

# retrieves Log entries
log_retrieve_all::
	$(cmd) --cmd=log_retrieve_all --log_id=`cat $(logidpath)` --log_pk=$(logpkpath)



# MAP SERVER
# maps the content of the Log to the Map
map::
	$(cmd) --cmd=map --log_id=`cat $(logidpath)` --map_id=`cat $(mapidpath)` --log_pk=$(logpkpath) --map_pk=$(mappkpath) --first=false

map_initial::
	$(cmd) --cmd=map --log_id=`cat $(logidpath)` --map_id=`cat $(mapidpath)` --log_pk=$(logpkpath) --map_pk=$(mappkpath) --first=true

ct_map::
	$(cmd) --cmd=ct_map --ct_log_addr=$(ctlogaddr) --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath) --map_elements=$(map_elements) --first=false --debug=$(debug)

ct_map_initial::
	$(cmd) --cmd=ct_map --ct_log_addr=$(ctlogaddr) --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath) --first=true

# retrieves Map entries
map_retrieve::
	$(cmd) --cmd=map_retrieve --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath) --domain=$(domain) --proof_output=$(proofoutput)

# retrieves Map entries
map_retrieve_all::
	$(cmd) --cmd=map_retrieve_all --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath)

# retrieves all map entries and collects performance information
map_retrieve_all_log_performance::
	$(cmd) --cmd=get_proof_stats_all --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath)

# retrieves a map entry and collects performance information
map_retrieve_log_performance::
	$(cmd) --cmd=get_proof_stats --domain=$(domain) --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath) --ppi_file=-

# sanitize map entries for domain
map_sanitize::
	$(cmd) --cmd=sanitize_proof --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath) --domain=$(domain)

# sanitize map entries for all domain
map_sanitize::
	$(cmd) --cmd=sanitize_proof_all --map_id=`cat $(mapidpath)` --map_pk=$(mappkpath)
