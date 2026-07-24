"use strict";

const indicator = document.querySelector("#indicator");
const title = document.querySelector("#title");
const statusText = document.querySelector("#status");
const openButton = document.querySelector("#openButton");

let destinationUrl = null;
let objectUrl = null;

function setStatus(kind, heading, message) {
  indicator.className = `spinner ${kind}`;
  title.textContent = heading;
  statusText.textContent = message;
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error("Der AES-256-Schlüssel muss aus genau 64 Hex-Zeichen bestehen.");
  }

  return Uint8Array.from(hex.match(/.{2}/g), byte => Number.parseInt(byte, 16));
}

function base64ToBytes(base64) {
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function readLockiPayload(value) {
  const match = /^\[LOCKI:v2:([A-Za-z0-9+/_=-]+)\]$/.exec(value.trim());

  if (!match) {
    throw new Error("Der verschlüsselte Wert hat kein gültiges LOCKI-v2-Format.");
  }

  const payload = base64ToBytes(match[1]);

  // LOCKI v2 stellt den zufälligen 12-Byte-IV dem AES-GCM-Ciphertext voran.
  if (payload.length <= 28) {
    throw new Error("Der LOCKI-v2-Wert ist unvollständig.");
  }

  return {
    iv: payload.slice(0, 12),
    ciphertext: payload.slice(12)
  };
}

async function decryptLocki(encryptedValue, hexKey) {
  const { iv, ciphertext } = readLockiPayload(encryptedValue);
  const key = await crypto.subtle.importKey(
    "raw",
    hexToBytes(hexKey),
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

function dataUriToObjectUrl(dataUri) {
  const commaIndex = dataUri.indexOf(",");
  if (commaIndex === -1 || !/^data:/i.test(dataUri)) {
    throw new Error("Der entschlüsselte Inhalt ist keine gültige Data-URI.");
  }

  const metadata = dataUri.slice(5, commaIndex);
  const data = dataUri.slice(commaIndex + 1);
  const parts = metadata.split(";");
  const mimeType = parts[0] || "application/octet-stream";
  const isBase64 = parts.some(part => part.toLowerCase() === "base64");
  const bytes = isBase64
    ? base64ToBytes(data.replace(/\s/g, ""))
    : percentEncodedDataToBytes(data);

  return URL.createObjectURL(new Blob([bytes], { type: mimeType }));
}

function percentEncodedDataToBytes(value) {
  const bytes = [];

  for (let index = 0; index < value.length;) {
    if (value[index] === "%") {
      const hex = value.slice(index + 1, index + 3);
      if (!/^[0-9a-f]{2}$/i.test(hex)) {
        throw new Error("Die Data-URI enthält eine ungültige Prozent-Kodierung.");
      }

      bytes.push(Number.parseInt(hex, 16));
      index += 3;
      continue;
    }

    const codePoint = value.codePointAt(index);
    const character = String.fromCodePoint(codePoint);
    bytes.push(...new TextEncoder().encode(character));
    index += character.length;
  }

  return Uint8Array.from(bytes);
}

function normalizeWebUrl(value) {
  let candidate = value;
  const hasHttpScheme = /^https?:\/\//i.test(candidate);
  const hasAnyScheme = /^[a-z][a-z0-9+.-]*:/i.test(candidate);
  const looksLikeBareHost = /^(?:localhost|\[[0-9a-f:]+\]|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z0-9-]+)(?::\d{1,5})?(?:[/?#]|$)/i.test(candidate);

  if (candidate.startsWith("//")) {
    candidate = `https:${candidate}`;
  } else if (!hasHttpScheme && (looksLikeBareHost || !hasAnyScheme)) {
    candidate = `https://${candidate}`;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(candidate);
  } catch {
    throw new Error("Der entschlüsselte Inhalt ist keine gültige URL oder Data-URI.");
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error(`Das URL-Protokoll „${parsedUrl.protocol}“ ist nicht erlaubt.`);
  }

  if (!parsedUrl.hostname) {
    throw new Error("Die entschlüsselte URL enthält keinen gültigen Hostnamen.");
  }

  if (parsedUrl.username || parsedUrl.password) {
    throw new Error("URLs mit eingebetteten Zugangsdaten sind nicht erlaubt.");
  }

  return parsedUrl.href;
}

function resolveDestination(plaintext) {
  const value = plaintext.trim();
  if (!value) {
    throw new Error("Der entschlüsselte Inhalt ist leer.");
  }

  if (/^data:/i.test(value)) {
    objectUrl = dataUriToObjectUrl(value);
    return objectUrl;
  }

  return normalizeWebUrl(value);
}

function tryOpenDestination() {
  if (!destinationUrl) return;

  const newTab = window.open("", "_blank");

  if (newTab) {
    newTab.opener = null;
    newTab.location.replace(destinationUrl);
    setStatus("done", "Inhalt geöffnet", "Du kannst diesen Tab jetzt schließen.");
    openButton.hidden = true;
  } else {
    setStatus("done", "Inhalt ist bereit", "Der Browser hat den neuen Tab blockiert. Klicke auf den Button.");
    openButton.hidden = false;
  }
}

async function start() {
  try {
    if (!window.crypto?.subtle) {
      throw new Error("Dieser Browser unterstützt die Web Crypto API nicht.");
    }

    const id = new URLSearchParams(window.location.search).get("id");
    if (!id || !/^[a-zA-Z0-9_-]{1,80}$/.test(id)) {
      throw new Error("In der URL fehlt eine gültige ID, zum Beispiel ?id=a22jd.");
    }

    const response = await fetch("./data.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error("data.json konnte nicht geladen werden.");
    }

    const entries = await response.json();
    const entry = entries[id];
    if (!entry) {
      throw new Error(`Für die ID „${id}“ wurde kein Eintrag gefunden.`);
    }

    const plaintext = await decryptLocki(entry.encrypted, entry.key);
    destinationUrl = resolveDestination(plaintext);
    tryOpenDestination();
  } catch (error) {
    console.error(error);
    setStatus("error", "Öffnen fehlgeschlagen", error.message || "Unbekannter Fehler.");
  }
}

openButton.addEventListener("click", tryOpenDestination);
window.addEventListener("pagehide", () => {
  if (objectUrl) URL.revokeObjectURL(objectUrl);
});

start();
