'use strict';

var myPort = chrome.runtime.connect({name:"port-from-cs"});

var page = (new URL(window.location.href)).searchParams.get("originURL")

myPort.postMessage({greeting: "SCION EEPKI WebExt - background script pong: " + page});

myPort.onMessage.addListener(function(m) {
    if (m.greeting) {
        console.log("SCION EEPKI WebExt - background script ping");
        console.log(m.greeting);
    } else if (m.redirect) {
        window.location = m.redirect; 
    } else if (m.greenlight) {
        window.location = page;
    }
});

document.body.addEventListener("click", function() {
    myPort.postMessage({greeting: "SCION EEPKI WebExt - debug: page clicked"});
});

document.addEventListener("DOMContentLoaded", function() {
    myPort.postMessage({request: page});
});
