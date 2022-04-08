# End-to-end experiments

## Set `GOPATH`
```shell
export GOPATH=/home/cyrill/go
```

## Setup web extension and prepare firefox
- Install web-ext using npm (7.10):
  ```shell
  sudo npm install --global web-ext
  ```
- Build native applications for web extension:
  ```shell
  cd <trustflex repo>
  make build_webextensions
  ```

## Fetch test certificates
Scrape the alexa top 1k domains for their TLS certificate:

```shell
cd <trustflex repo>/tls
curl -s http://s3.amazonaws.com/alexa-static/top-1m.csv.zip | funzip | head -n 1000 >top-1k.domains
cp top-1k.domains top-1k-filtered.domains
# manually remove invalid/problematic domains in top-1k-filtered.domains
./scrape.py
```

## Run DNS experiments

Fetch alexa top 1k websites with and without (local) dns caching.

- Change webextension to use dns approach [here](./webext/app/background.js):
  ```js
  const useStaplingApproach = false
  ```
- Update map id and map public key [here](./webext/app/background.js):
  ```js
  const mapServers = [{
    MapIDPath: 'path/to/digitalocean_vm_config/mapid1',
    MapPKPath: 'path/to/digitalocean_vm_config/mappk1.pem',
    ...
  ```
- Generate required experiment files
  ```shell
  cd <trustflex repo>/tls
  ./generate.py experiment-input-dns >experiment-domains
  ```
- Clone coredns repo:
  ```shell
  git clone --single-branch --branch trustflex-plugin --depth=1 git@github.com:cyrill-k/coredns
  ```
- Build coredns repo (for go1.16, there is a bug which results in a build error [stackoverflow](https://stackoverflow.com/questions/66469396/go-module-is-found-and-replaced-but-not-required) which can be solved by running `go mod tidy` in the coredns repo before `make build_coredns`):
  ```shell
  cd <trustflex repo>
  make pre_build_coredns
  make build_coredns
  ```
- **In a separate window**: Create Corefile for local resolver and run coredns. Make sure to adjust the address of the remote (digitalocean) map server to fetch proofs. Also, to disable local DNS caching, make sure that the expire option in the forward plugin is set to a low value (e.g., `expire 1ns`):
  ```shell
  mkdir tls/local-resolver
  cp dns/coredns/cachingresolver-corefile tls/local-resolver/Corefile
  make map_dns_server configdir=`realpath tls/local-resolver` coredns=<coredns repo>
  ```
- Update local recursive DNS resolver:
  ```shell
  make change_netplan
  ```
- Make sure that the new DNS servers are actually used ([askubuntu](https://askubuntu.com/questions/1237685/changing-the-dns-servers-ubuntu-server-20-04-arm64-raspi)), otherwise fix resolv.conf link:
  ```shell
  sudo rm /etc/resolv.conf
  sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
  sudo netplan apply
  ```
- Run experiment:
  ```shell
  for x in {1..2002}; do web-ext run -f /usr/bin/firefox --keep-profile-changes; done
  ```


## Run TLS Stapling experiments

Simulate TLS stapling by adding proofs in the form of X509 extensions.

- Change webextension to use stapling approach [here](./webext/app/background.js):
  ```js
  const useStaplingApproach = true
  ```
- Update map id and map public key [here](./webext/app/background.js):
  ```js
  const mapServers = [{
    MapIDPath: 'path/to/config/mapid1',
    MapPKPath: 'path/to/config/mappk1.pem',
    ...
  ```
- Modify scraped certificates with self-signed root:
  ```shell
  ./create_self_signed_certs_with_stapling_extension.py --action generate-initial-certs certchains/*
  ```
- In a second terminal, in the trustflex-docker folder, start containers:
  ```shell
  cd <trustflex-docker repository>
  docker-compose up
  ```
- Create log MHT:
  ```shell
  docker exec experiment make createtree
  ```
- Add certificates to trustflex log server:
  ```shell
  for x in output/servercerts/*; do cat "$x" | docker exec -i experiment make log_add; done
  ```
- Perform initial mapping from the log server to the map server:
  ```shell
  docker exec experiment mkdir data
  docker exec experiment mkdir trillian
  docker exec experiment make map_initial
  ```
- Fetch proofs:
  ```shell
  mkdir output/proofs
  for x in $(./generate.py --cert-folder output/servercerts domains); do docker exec -i experiment make -s map_retrieve domain="$x" >output/proofs/$x; done
  # this does not work for some reason...
  # ./generate.py --cert-folder output/servercerts domains | while read x; do docker exec -i experiment make map_retrieve domain="$x" >output/proofs/$x; done
  ```
- Generate new certificates with proofs as extensions:
  ```shell
  ./rename_proofs.py
  ./create_self_signed_certs_with_stapling_extension.py --action add-proof-extension
  ```
- Install and configure nginx and hosts file:
  ```shell
  sudo apt install -y nginx
  mkdir www
  echo "<html><body><a href="www.ethz.ch">ethz</a></body></html>" >www/index.html
  ./generate.py nginx-config >nginx-trustflex-config
  sudo cp nginx-trustflex-config /etc/nginx/sites-available/trustflex
  sudo ln -s /etc/nginx/sites-available/trustflex /etc/nginx/sites-enabled/trustflex
  ./generate.py hosts-file >hosts_file
  cat hosts_file | sudo tee -a /etc/hosts
  sudo systemctl restart nginx
  ```
- Generate required experiment files
  ```shell
  ./generate_experiment_input.py >experiment-domains
  ```
- Locate firefox profile folder (Help -> More Troubleshoot Information -> Profile Directory)
- Add [root cert](./output/rootcerts/cert-trustflex.pem) to Firefox trusted CA store. (Preferences -> Privacy & Security -> View Certificates... -> Import)
- Run experiment:
  ```shell
  for x in {1..2002}; do web-ext run -p path/to/firefox/profile -f /usr/bin/firefox --keep-profile-changes; done
  ```
