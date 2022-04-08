Tried on Ubuntu 20.04.1 LTS (Focal Fossa)

# Setup

## Dependencies

go 1.13
(https://golang.org/)

DNS go library:
`go get github.com/cyrill-k/dns`

Trillian:
`go get github.com/cyrill-k/trillian`

## TLS
Navigate to the TLS folder and execute:
`python3 scrape.py`

This will generate the `tls/certchains` folder needed by the system. Make sure the generated files in this folder are non-empty. 

## Starting up the whole backend system
Follow the instructions found in the README at https://github.com/cyrill-k/fpki-docker/.

## Webextension

Change the paths in the *replace* directives in the `go.mod` file at the **root** of this repo to point to the local installation folders of the repos fetched in the **Dependencies** section. 
Go get usually installs stuff into the first path found in $GOPATH. If this is not set, a typical place to look would be `~/go/src/`.

### Changing the hardcoded filepaths

In the webextension, the path to the fpki repo are hardcoded. You can change them by executing the following sed command from the **webext** folder after substituting the correct local path to the root of this repo:
```
find . -type f -readable -writable -exec sed -i 's:/home/cyrill/go/src/github.com/cyrill-k/fpki/:/your/path/to/fpki/:' {} +
```
After this step there are still two paths that need adjusting in the file *app/background.js*. When we use the docker repo to start the background services, the files *mapid1* and *mappk1.pem* are found in the config folder of the fpki-docker repo (instead of the path ending in *fpki/resolver*). Change the paths accordingly. 

### Building the webextension

In the root folder execute:
```
make fpki=`pwd` build_webextensions
``` 
If the following messages appear on your terminal, the building of the extension has succeeded:
```
Native messaging host ch.ethz.netsec.fpki.verifier has been installed.
Native messaging host ch.ethz.netsec.fpki.txtfetcher has been installed.
Native messaging host ch.ethz.netsec.fpki.perflogger has been installed.
Native messaging host ch.ethz.netsec.fpki.filegenerator has been installed.
Native messaging host ch.ethz.netsec.fpki.policyfetcher has been installed.
```

### Load the Webextension with Firefox
- visit about:debugging
- Click on *This Firefox* then *Load Temporary Add-on*
- select `manifest.json` (in the **app** folder)

[//]: # "## Chrome"
[//]: # "- visit chrome://extensions/"
[//]: # "- enable debug mode"
[//]: # "- Click on *Load Unpacked*"
[//]: # "- select the `app` folder"

https://www.freecodecamp.org/news/how-to-make-a-cross-browser-extension-using-javascript-and-browser-apis-355c001cebba/

**TODO:** still fails to load policy for e.g. google.com (first entry in the top 100 filtered certs.) => investigate.
