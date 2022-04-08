var resetButton = document.getElementById("resetbutton")
var getCacheButton = document.getElementById("getcachebutton")
var readTrustedCAsButton = document.getElementById("readTrustedCAsButton")
var writeTrustedCAsButton = document.getElementById("writeTrustedCAsButton")
var resetTrustedCAsButton = document.getElementById("resetTrustedCAsButton")
var trustedCAsArea = document.getElementById("trustedCAs")
var runExperimentButton = document.getElementById("runExperimentButton")

resetButton.addEventListener("click", resetCache);
async function resetCache() {
    console.log("clear")
    
    let backgroundWindow  = await browser.runtime.getBackgroundPage();
    backgroundWindow.clearCache()
    // console.log(backgroundWindow.cachedUrls)
    // output.innerHTML = "test";
}


getCacheButton.addEventListener("click", getCache);
async function getCache() {
    let backgroundWindow  = await browser.runtime.getBackgroundPage();
    console.log(backgroundWindow.cachedUrls)
    // output.innerHTML = "test";
}


readTrustedCAsButton.addEventListener("click", readTrustedCAs);
async function readTrustedCAs() {
    browser.runtime.getBackgroundPage().
        then(bgWindow => bgWindow.getTrustedCAs()).
        then(t => {
            console.log(`read trusted CAs: ${t}`)
            trustedCAsArea.value = t.join("\n")})
}

writeTrustedCAsButton.addEventListener("click", writeTrustedCAs);
async function writeTrustedCAs() {
    await browser.storage.local.set({"trustedCAs": trustedCAsArea.value.split("\n")}).then(
        console.log(`write trusted CAs`))
}

resetTrustedCAsButton.addEventListener("click", resetTrustedCAs);
async function resetTrustedCAs() {
    await browser.storage.local.remove("trustedCAs").
        then(()=>{console.log("reset trusted CAs"); readTrustedCAs()}).
        catch(() => console.log("Failed to reset trusted CAs"))
}



runExperimentButton.addEventListener("click", runExperimentButtonAction);
async function runExperimentButtonAction() {
    let backgroundWindow  = await browser.runtime.getBackgroundPage();
    await backgroundWindow.runExperiment(trustedCAsArea.value.split("\n"))
}
