import { v4 } from "https://deno.land/std@0.78.0/uuid/mod.ts";
import { hmac } from "https://denopkg.com/chiefbiiko/hmac/mod.ts";
import { sha256 } from "https://denopkg.com/chiefbiiko/sha256/mod.ts";

type SignRequest = {
  body: string;
  method: string;
  headers: object;
  url: string;
  authHeader: string;
};

function signData(
  { body, method, headers, url, authHeader }: SignRequest,
): string {
  const { hostname, pathname, protocol, search } = new URL(url);

  const canonicalizeHeaders = (headers: object) =>
    Object.entries(headers)
      .map(([key, value]) =>
        `${key.toLowerCase()}:${String(value).trim().replace(/\s+/g, " ")}`
      )
      .join("\t");

  return [
    method.toUpperCase(),
    protocol.replace(":", ""),
    hostname.toLowerCase(),
    pathname + search,
    canonicalizeHeaders(headers),
    (method.toUpperCase() === "POST") ? sha256(body, "utf8", "base64") : "",
    authHeader,
  ].join("\t");
}

export type AkamaiAuthHeaderOptions = {
  clientToken: string;
  accessToken: string;
  clientSecret: string;
  body?: string;
  headers?: object;
  url: string;
  method?: string;
  nonce?: string;
};

function timestamp(): string {
  function pad(number: number): string {
    return (number < 10) ? "0" + number : number.toString();
  }

  const date = new Date();

  return date.getUTCFullYear() +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    "T" + pad(date.getUTCHours()) +
    ":" + pad(date.getUTCMinutes()) +
    ":" + pad(date.getUTCSeconds()) +
    "+0000";
}

export function akamaiAuthHeader(
  {
    clientToken,
    accessToken,
    clientSecret,
    body = "",
    headers = {},
    url,
    method = "GET",
    nonce = v4.generate(),
  }: AkamaiAuthHeaderOptions,
): string {
  if (body.length > 131072) {
    throw new RangeError("Body length is greater than maximum allowed.");
  }

  const tokens = {
    client_token: clientToken,
    access_token: accessToken,
    timestamp: timestamp(),
    nonce,
  };

  const concatenatedTokens = Object.entries(tokens)
    .map(([key, value]) => `${key}=${value};`)
    .join("");

  const authHeader = `EG1-HMAC-SHA256 ${concatenatedTokens}`;

  return `${authHeader}signature=${
    hmac(
      "sha256",
      hmac("sha256", clientSecret, tokens.timestamp, "utf8", "base64"),
      signData({ body, method, headers, url, authHeader }),
      "utf8",
      "base64",
    )
  }`;
}
