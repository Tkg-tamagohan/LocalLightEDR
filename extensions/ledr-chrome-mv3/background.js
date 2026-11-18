"use strict";

// Phase 0 stub for LocalEDR Browser Shield MV3 Service Worker.
// Phase 4 will wire chrome.downloads.onCreated / onChanged, NRD feed sync,
// and Native Messaging via ledr-bridge-nm.

const NATIVE_HOST_NAME = "com.localedr.bridge";

chrome.runtime.onInstalled.addListener(() => {
  void NATIVE_HOST_NAME;
});
