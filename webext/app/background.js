'use strict'

const cancelUrl = chrome.runtime.getURL('/pages/blocked.html')

let mapserverDnsRequestsById = {
    '': null
}
let mapserverDnsResponsesById = {
    '': null
}
let startTimesById = {
    '': null
}
let cachedUrls = {
    '': null
}
cachedUrls.true = {
    '': null
}
cachedUrls.false = {
    '': null
}
const tabIsActive = {
    '': null
}
const tabRank = {
    '': null
}
const tabStarted = {
    '': null
}
let experimentActive = false
const autoExperimentRun = false
const useStaplingApproach = false

const mapServers = [{
    MapIDPath: '/home/cyrill/go/src/github.com/cyrill-k/fpki/tls/digitalocean_vm_config/mapid1',
    MapPKPath: '/home/cyrill/go/src/github.com/cyrill-k/fpki/tls/digitalocean_vm_config/mappk1.pem',
    MapResolverDomain: 'mapserver1.com'
}]

const initialTrustedCAs = ['0F80611C823161D52F28E78D4638B42CE1C6D9E2',
                           'B095235C31EA98A14051088B5A26675524E26045249C48BB351F98ED998B412E',
                           '5BC1069445E253E9A178482B6795535764BDB2359E8EFDEF04910A7594123AF3'
                          ]


browser.tabs.create({
    url: 'https://ethz.ch'
})

function fillArray(value, len) {
    const arr = []
    for (let i = 0; i < len; i++) {
        arr.push(value)
    }
    return arr
}

async function autoPerformOneExperimentRun() {
    const backgroundWindow = await browser.runtime.getBackgroundPage()
    if (backgroundWindow.autoExperimentRun) {
        console.log('autoPerformOneExperimentRunhandleStartup already run')
    } else {
        console.log('autoPerformOneExperimentRunhandleStartup')
        backgroundWindow.autoExperimentRun = true
        backgroundWindow.tabIsActive = {
            '': null
        }
        backgroundWindow.tabRank = {
            '': null
        }
        backgroundWindow.tabStarted = {
            '': null
        }
        const filegenerator = browser.runtime.sendNativeMessage('ch.ethz.netsec.fpki.filegenerator', {})
        let rank
        let domain
        await filegenerator.then((resp) => {
            rank = resp.Rank;
            domain = resp.Domain
        })
        console.log(`rank = ${rank}, domain = ${domain}`)
        const expList = fillArray(rank + ',' + domain, 5)
        setTimeout(runExperiment(expList), 1000)
        // runExperiment([rank+","+domain])
    }
}

async function oneExperimentRun(rankedUrl) {
    const backgroundWindow = await browser.runtime.getBackgroundPage()
    console.log(`experiment run for ${rankedUrl}`)
    clearCache()
    const s = rankedUrl.split(',')
    const createTab = browser.tabs.create({
        url: 'https://' + s[1]
    })
    let tab
    await createTab.then((resp) => {
        tab = resp;
        console.log(`tab created ${resp.id}`)
    })
    backgroundWindow.tabIsActive[tab.id] = true
    backgroundWindow.tabRank[tab.id] = s[0]
    backgroundWindow.tabStarted[tab.id] = new Date()
    return tab
}

async function runExperiment(urls) {
    if (experimentActive) {
        console.log('Error: experiment is already running')
    } else {
        experimentActive = true
        // var urls = ["https://example.com", "https://test.com"]
        let i = 0
        let tab = await oneExperimentRun(urls[i]);
        (async function loop() {
            setTimeout(async function() {
                console.log(`testtab: ${tabIsActive}`)
                if (tabIsActive[tab.id]) {
                    if (new Date() - tabStarted[tab.id] > 10000) {
                        console.log(`Timeout for ${urls[i]}`)
                        const perflogger = browser.runtime.sendNativeMessage('ch.ethz.netsec.fpki.perflogger', {
                            Id: parseInt(tabRank[tab.id]),
                            Domain: urls[i].split(',')[1],
                            TimeToHeadersReceived: 0,
                            TimeToRetrieveProof: 0,
                            TimeToValidate: 0,
                            TimeToValidationFinished: 0,
                            TotalTime: 0,
                            ProofSize: 0,
                            NCertificates: "",
                            NWildcardCertificates: "",
                            Blocked: false
                        })

                        // await perflogger.then((resp)=>{console.log("Hello perflogger")})
                        await perflogger.then((resp) => {
                            console.log(`perflogger returned: domain=${resp.Domain}, logged=${resp.Logged}, error=${resp.Error}`)
                        })
                        tabIsActive[tab.id] = false
                        loop()
                    } else {
                        console.log(`loop tab[${tab.id}] is active, i=${i} ${new Date() - tabStarted[tab.id]}`)
                        loop()
                    }
                } else {
                    i = i + 1
                    if (i < urls.length) {
                        console.log(`loop tab[${tab.id}] is inactive, i=${i}, remove tab and start experiment run`)
                        await browser.tabs.remove(tab.id).then(console.log(`Removed tab ${tab.id}`), (err) => console.log(`failed to remove tab: ${err}`))
                        tab = await oneExperimentRun(urls[i])
                        loop()
                    } else {
                        console.log(`loop tab[${tab.id}] is inactive, remove tab`)
                        await browser.tabs.remove(tab.id).then(console.log(`Removed tab ${tab.id}`), (err) => console.log(`failed to remove tab: ${err}`))
                        experimentActive = false
                        console.log('runExperiment finished')
                        const windowId = (await browser.windows.getCurrent()).id
                        await browser.windows.remove(windowId)
                    }
                }
            }, 1000)
        })()
    }
}

async function getTrustedCAs() {
    return await browser.storage.local.get('trustedCAs')
        .then(ret => {
            if (ret.trustedCAs === undefined) {
                return initialTrustedCAs
            } else {
                return ret.trustedCAs
            }
        },
              error => {
                  console.log('failure');
                  initialTrustedCAs
              })
}

function newCancelUrl(originURL, reason) {
    return cancelUrl + '?originURL=' + encodeURI(originURL) + '&reason=' + encodeURI(reason)
}

function clearCache() {
    mapserverDnsRequestsById = {
        '': null
    }
    mapserverDnsResponsesById = {
        '': null
    }
    startTimesById = {
        '': null
    }
    cachedUrls = {
        '': null
    }
    cachedUrls.true = {
        '': null
    }
    cachedUrls.false = {
        '': null
    }
}

function normalise(url) {
    const uri = new URL(url)

    // Normalise hosts with tailing dots, e.g. "www.example.com."
    while (uri.hostname[uri.hostname.length - 1] === '.' && uri.hostname !== '.') {
        uri.hostname = uri.hostname.slice(0, -1)
    }

    return uri
}

function normalisedHostname(url) {
    return normalise(url).hostname
}

async function onHeadersReceived(details) {
    console.log(`onHeadersReceived ${new URL(details.url).origin}, ${details.type}, tabId=${details.tabId}, requestId=${details.requestId}, frameId=${details.frameId}, frameAncestor=${details.frameAncestor}, frameAncestors=${details.frameAncestors}, status=${details.statusCode}`);

    // could make this more efficient by directly accepting already verified hosts, e.g., hosts in cachedUrls
    return new Promise(async (resolve, reject) => {
        const sinfo = await browser.webRequest.getSecurityInfo(details.requestId, {
            certificateChain: true,
            rawDER: true
        })
        const isHttps = sinfo.state == 'secure'
        const hostname = normalisedHostname(details.url)
        const endTime = new Date()
        const timeToHeadersReceived = endTime - startTimesById[details.requestId]
        let timeToRetrieveProof = 0
        let timeToValidate = 0
        let timeToValidationFinished = 0
        let totalTime = 0
        let proofSize = 0
        let nCertificates = ""
        let nWildcardCertificates = ""
        let blocked = false
        let retVal = {}
        // console.log(`sinfo = ${sinfo}`)

        if (hostname in cachedUrls[isHttps] && cachedUrls[isHttps][hostname] === true) {
            // already cached and verified
            // console.log(`onHeadersReceived(${new URL(details.url).origin}, ${details.type}) Hostname verification already cached`)
            // console.log({ Domain: hostname, TimeToHeadersReceived: Math.round(timeToHeadersReceived), TimeToRetrieveProof: Math.round(timeToRetrieveProof), TimeToValidate: Math.round(timeToValidate), TimeToValidationFinished: Math.round(timeToValidationFinished), Blocked: blocked})

            const backgroundWindow = await browser.runtime.getBackgroundPage()
            const rank = parseInt(backgroundWindow.tabRank[details.tabId])
            // console.log(`rank = ${rank}`)
            if (backgroundWindow.tabIsActive[details.tabId]) {
                const perflogger = browser.runtime.sendNativeMessage('ch.ethz.netsec.fpki.perflogger', {
                    Id: rank,
                    Domain: hostname,
                    TimeToHeadersReceived: Math.round(timeToHeadersReceived),
                    TimeToRetrieveProof: Math.round(timeToRetrieveProof),
                    TimeToValidate: Math.round(timeToValidate),
                    TimeToValidationFinished: Math.round(timeToValidationFinished),
                    TotalTime: Math.round(totalTime),
                    ProofSize: proofSize,
                    NCertificates: nCertificates,
                    NWildcardCertificates: nWildcardCertificates,
                    Blocked: blocked
                })

                await perflogger.then((resp) => {
                    // console.log(`perflogger returned: domain=${resp.Domain}, logged=${resp.Logged}, error=${resp.Error}`)
                })
                backgroundWindow.tabIsActive[details.tabId] = false
            } else {
                // console.log(`tab[${details.tabId}] not active`)
            }
            resolve(retVal)
        } else {
            // not yet cached or cached but unverified
            console.log(`onHeadersReceived(${new URL(details.url).origin}, ${details.type}) awaiting mapserver response for ${details.requestId}...`)
            if (useStaplingApproach) {
                const requestBody = {
                    Domain: hostname,
                    Certificate: sinfo.certificates[0].rawDER,
                    MapserverDomain: mapServers[0].MapResolverDomain,
                    ResolverAddress: '142.93.162.114:12345',
                    MapID: mapServers[0].MapIDPath,
                    MapPK: mapServers[0].MapPKPath,
                    TrustedCAs: await getTrustedCAs(),
                    Compressed: true
                }
                const jsonBody = JSON.stringify(requestBody)
                const policyResolverAddress = 'http://localhost:8096'
                console.log(`onBeforeRequest(${new URL(details.url).origin}) Fetching mapserver proof for ${details.requestId}`)
                console.log(`sinfo = ${sinfo}, certificates = ${sinfo.certificates}, ${sinfo.certificates[0].rawDER}`)
                mapserverDnsRequestsById[details.requestId] = fetchUsingFetchAPI(policyResolverAddress, jsonBody)
            }
            mapserverDnsRequestsById[details.requestId].then(async (resp) => {
                console.log(`onHeadersReceived(${new URL(details.url).origin}, ${details.type}) policyverifier replied with json: ${JSON.stringify(resp)}`);
                const valid = resp.Valid
                const error = resp.Error
                const allowHTTP = resp.AllowHTTP
                const hasUniquePublicKey = resp.HasUniquePublicKey
                const uniquePublicKey = resp.UniquePublicKey
                timeToRetrieveProof = resp.TimeToRetrieveProof
                timeToValidate = resp.TimeToValidate
                totalTime = resp.TotalTime
                proofSize = resp.ProofSize
                nCertificates = resp.NCertificates
                nWildcardCertificates = resp.NWildcardCertificates

                let errorUrl
                if (errorUrl !== undefined) {
                    retVal = errorUrl
                    blocked = true
                } else {
                    // proof retrieval/validation failed
                    if (!valid) {
                        blocked = true
                        retVal = {
                            redirectUrl: newCancelUrl(normalise(details.url), `Couldn\'t verify map server proof: ${error}`)
                        }
                    } else {
                        if (!isHttps) {
                            // HTTP downgrade attack
                            if (!allowHTTP) {
                                blocked = true
                                retVal = {
                                    redirectUrl: newCancelUrl(normalise(details.url), 'HTTP downgrade attack detected')
                                }
                            }
                        } else {
                            // HTTPS
                            if (hasUniquePublicKey) {
                                // Check public key uniqueness
                                // console.log(`digest from proof: ${uniquePublicKey}`)
                                // console.log(`digest from TLS: ${sinfo.certificates[0].subjectPublicKeyInfoDigest.sha256}`)
                                if (uniquePublicKey !== sinfo.certificates[0].subjectPublicKeyInfoDigest.sha256) {
                                    blocked = true
                                    retVal = {
                                        redirectUrl: newCancelUrl(normalise(details.url), 'Public Key uniqueness property violated')
                                    }
                                }
                            }
                        }
                    }
                }
                if (blocked) {
                    // console.log(`onHeadersReceived(${new URL(details.url).origin}, ${details.type}) block`);
                    cachedUrls[isHttps][hostname] = false
                } else {
                    // console.log(`onHeadersReceived(${new URL(details.url).origin}, ${details.type}) allow`);
                    cachedUrls[isHttps][hostname] = true
                }
                timeToValidationFinished = new Date() - startTimesById[details.requestId]
                // console.log({ Domain: hostname, TimeToHeadersReceived: Math.round(timeToHeadersReceived), TimeToRetrieveProof: Math.round(timeToRetrieveProof), TimeToValidate: Math.round(timeToValidate), TimeToValidationFinished: Math.round(timeToValidationFinished), Blocked: blocked})

                const backgroundWindow = await browser.runtime.getBackgroundPage()
                const rank = parseInt(backgroundWindow.tabRank[details.tabId])
                // console.log(`rank = ${rank}`)
                console.log(`tab is active: ${details.tabId}, ${backgroundWindow.tabIsActive} ${backgroundWindow.tabIsActive[details.tabId]}`)
                if (backgroundWindow.tabIsActive[details.tabId]) {
                    const perflogger = browser.runtime.sendNativeMessage('ch.ethz.netsec.fpki.perflogger', {
                        Id: rank,
                        Domain: hostname,
                        TimeToHeadersReceived: Math.round(timeToHeadersReceived),
                        TimeToRetrieveProof: Math.round(timeToRetrieveProof),
                        TimeToValidate: Math.round(timeToValidate),
                        TimeToValidationFinished: Math.round(timeToValidationFinished),
                        TotalTime: Math.round(totalTime),
                        ProofSize: proofSize,
                        NCertificates: nCertificates,
                        NWildcardCertificates: nWildcardCertificates,
                        Blocked: blocked
                    })

                    await perflogger.then((resp) => {
                        // console.log(`perflogger returned: domain=${resp.Domain}, logged=${resp.Logged}, error=${resp.Error}`);
                    })
                    backgroundWindow.tabIsActive[details.tabId] = false
                } else {
                    // console.log(`tab[${details.tabId}] not active`)
                }
                resolve(retVal)
            }).catch((err) => {
                // console.log(`error (${err}) waiting for ${isHttps} ${hostname}: failed to query fpki dns mapserver`);
                retVal = {
                    redirectUrl: newCancelUrl(normalise(details.url), `Failed to query fpki dns mapserver: ${err}`)
                }
                resolve(retVal)
            })
        }
    })
}

async function onBeforeRequest(details) {
    // console.log(`onBeforeRequest ${new URL(details.url).origin}, ${details.type}, tabId=${details.tabId}, requestId=${details.requestId}, frameId=${details.frameId}, frameAncestor=${details.frameAncestor}, frameAncestors=${details.frameAncestors}`);
    const hostname = normalisedHostname(details.url)
    console.log(`onbeforerequest: hostname = ${hostname}`)
    if (hostname == 'ethz.ch') {
        autoPerformOneExperimentRun()
        return {
            cancel: true
        }
    }
    startTimesById[details.requestId] = new Date()
    const isHttps = details.url.startsWith('https://')
    if (hostname in cachedUrls[isHttps] && cachedUrls[isHttps][hostname] === true) {
        // console.log(`onBeforeRequest(${new URL(details.url).origin}, ${details.type}) Hostname verification already cached`)
        return
    }
    if (!useStaplingApproach) {
        const requestBody = {
            Domain: hostname,
            Certificate: [],
            MapserverDomain: mapServers[0].MapResolverDomain,
            ResolverAddress: '142.93.162.114:12345',
            MapID: mapServers[0].MapIDPath,
            MapPK: mapServers[0].MapPKPath,
            TrustedCAs: await getTrustedCAs(),
            Compressed: true
        }
        const jsonBody = JSON.stringify(requestBody)
        const policyResolverAddress = 'http://localhost:8096'
        console.log(`onBeforeRequest(${new URL(details.url).origin}) Fetching mapserver proof for ${details.requestId}`)
        mapserverDnsRequestsById[details.requestId] = fetchUsingFetchAPI(policyResolverAddress, jsonBody)
    }
    // mapserverDnsRequestsById[details.requestId] = fetchUsingXMLHttpRequest(policyResolverAddress, jsonBody);
    // await mapserverDnsRequestsById[details.requestId];
}

async function fetchUsingXMLHttpRequest(address, requestBody) {
    return new Promise(function(resolve, reject) {
        const xhr = new XMLHttpRequest()
        xhr.onload = function() {
            try {
                const d = JSON.parse(this.responseText)
                resolve(d)
            } catch (err) {
                reject(err)
            }
        }
        xhr.onerror = reject
        xhr.open('POST', address)
        xhr.send(requestBody)
    })
}

async function fetchUsingFetchAPI(address, requestBody) {
    return new Promise(async (resolve, reject) => {
        await fetch(new Request(address, {
            method: 'POST',
            body: requestBody
        }))
            .then(resp => {
                // console.log(`received policy for ${requestBody}; extracting json from body...`);
                resp.json()
                    .then(jsonObject => {
                        // console.log(`extracted json policy for ${requestBody}`);
                        resolve(jsonObject)
                    })
                    .catch(() => {
                        console.log('failed to extract object from json body')
                        reject()
                    })
            })
            .catch(() => {
                console.log(`failed to receive policy for ${requestBody}`)
                reject()
            })
    })
}

async function onErrorOccurred(details) {
    const backgroundWindow = await browser.runtime.getBackgroundPage()
    if (backgroundWindow.tabIsActive[details.tabId]) {
        console.log(`onErrorOccurred(${new URL(details.url).origin}): closing tab[${details.tabId}]`)
        const hostname = normalisedHostname(details.url)
        const rank = parseInt(backgroundWindow.tabRank[details.tabId])
        const perflogger = browser.runtime.sendNativeMessage('ch.ethz.netsec.fpki.perflogger', {
            Id: rank,
            Domain: hostname,
            TimeToHeadersReceived: 0,
            TimeToRetrieveProof: 0,
            TimeToValidate: 0,
            TimeToValidationFinished: 0,
            TotalTime: 0,
            ProofSize: 0,
            NCertificates: "",
            NWildcardCertificates: "",
            Blocked: false
        })

        // await perflogger.then((resp)=>{console.log("Hello perflogger")})
        await perflogger.then((resp) => {
            console.log(`perflogger returned: domain=${resp.Domain}, logged=${resp.Logged}, error=${resp.Error}`)
        })
        backgroundWindow.tabIsActive[details.tabId] = false
    } else {
        console.log(`onErrorOccurred(${new URL(details.url).origin}): tab[${details.tabId}] not active`)
    }
}

async function onCompleted(details) {
    // console.log(`onCompleted(${new URL(details.url).origin})`)
}

// Registers the handler for requests (incomplete list for testing only
const interceptedUrls = ['*://*.com/*', '*://*.net/*', '*://*.org/*', '*://*.goog/*', '*://*.ms/*', '*://*.tv/*', '*://*.io/*', '*://*.co/*', '*://*.in/*', '*://*.vn/*', '*://*.fi/*', '*://*.news/*', '*://*.ly/*', '*://*.ru/*', '*://*.st/*', '*://*.sa/*', '*://*.ch/*', '*://*.local/*']
browser.webRequest.onBeforeRequest.addListener(
    onBeforeRequest, {
        urls: interceptedUrls
    },
    ['blocking'])
browser.webRequest.onHeadersReceived.addListener(
    onHeadersReceived, {
        urls: interceptedUrls
    },
    ['blocking'])
browser.webRequest.onErrorOccurred.addListener(
    onErrorOccurred, {
        urls: interceptedUrls
    })
browser.webRequest.onCompleted.addListener(
    onCompleted, {
        urls: interceptedUrls
    })






