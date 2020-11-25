import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.78.0/testing/asserts.ts";
import { FakeTime } from "https://deno.land/x/mock@v0.9.2/time.ts";

import akamaiAuthHeader from "./akamai-authorization.ts";

Deno.test("akamaiAuthHeader for GET returns a valid header", () => {
  const time: FakeTime = new FakeTime("2020-11-22T10:00:00.12345Z");

  const header = akamaiAuthHeader({
    clientToken: "clientToken",
    accessToken: "accessToken",
    clientSecret: "clientSecret",
    url: "http://edge-api.akamai.net?startFrom=today",
    nonce: "d97b5be8-994f-4c5b-9a61-b47ca4d01337",
  });

  assertEquals(
    header,
    "EG1-HMAC-SHA256 client_token=clientToken;access_token=accessToken;timestamp=20201122T10:00:00+0000;nonce=d97b5be8-994f-4c5b-9a61-b47ca4d01337;signature=NlHR3oQNsEtsF-pYgwcjz5e-Cs2RkxVKvSC1tuJAmL4=",
  );

  time.restore();
});

Deno.test("akamaiAuthHeader for GET with headers returns a valid header", () => {
  const time: FakeTime = new FakeTime("2020-11-22T10:00:00.12345Z");

  const header = akamaiAuthHeader({
    clientToken: "clientToken",
    accessToken: "accessToken",
    clientSecret: "clientSecret",
    url: "http://edge-api.akamai.net",
    headers: {
      "x-test": true,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    nonce: "d97b5be8-994f-4c5b-9a61-b47ca4d01337",
  });

  assertEquals(
    header,
    "EG1-HMAC-SHA256 client_token=clientToken;access_token=accessToken;timestamp=20201122T10:00:00+0000;nonce=d97b5be8-994f-4c5b-9a61-b47ca4d01337;signature=oTC4Km5R5VIyDiFuasmDuxzBWlBaitEC5j08mkQrjG8=",
  );

  time.restore();
});

Deno.test("akamaiAuthHeader for POST returns a valid header", () => {
  const time: FakeTime = new FakeTime("2020-11-22T10:00:00.12345Z");

  const header = akamaiAuthHeader({
    clientToken: "clientToken",
    accessToken: "accessToken",
    clientSecret: "clientSecret",
    url: "http://edge-api.akamai.net",
    method: "post",
    body: "hello-world",
    nonce: "d97b5be8-994f-4c5b-9a61-b47ca4d01337",
  });

  assertEquals(
    header,
    "EG1-HMAC-SHA256 client_token=clientToken;access_token=accessToken;timestamp=20201122T10:00:00+0000;nonce=d97b5be8-994f-4c5b-9a61-b47ca4d01337;signature=OofwO5zZicv2Nchpr6lPPJub0UtjInyPZqppA_Yb0Zc=",
  );

  time.restore();
});

Deno.test("akamaiAuthHeader for POST returns an error when body is too large", () => {
  assertThrows(() =>
    akamaiAuthHeader({
      clientToken: "clientToken",
      accessToken: "accessToken",
      clientSecret: "clientSecret",
      url: "http://edge-api.akamai.net",
      method: "post",
      // @ts-ignore
      body: { length: 131073 },
      nonce: "d97b5be8-994f-4c5b-9a61-b47ca4d01337",
    }), RangeError);
});
