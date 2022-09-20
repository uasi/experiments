import { timingSafeEqual } from "https://deno.land/std@0.156.0/crypto/timing_safe_equal.ts";
import { encode as encodeBase64 } from "https://deno.land/std@0.156.0/encoding/base64.ts";
import { scryptSync } from "https://deno.land/std@0.156.0/node/crypto.ts?s=scryptSync";

type Buffer = ReturnType<typeof scryptSync>;

export function scrypt(password: string, salt: Uint8Array): string {
  // Default values in Node.js v16.
  // https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback
  const ln = 14;
  const r = 8;
  const p = 1;

  const buf = scryptSync(password, salt, 32, { N: 2 ** ln, r, p });

  // Compatible with passlib format.
  // https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html#format-algorithm
  return `$scrypt$ln=${ln},r=${r},p=${p}$${b64(salt)}$${b64(buf)}`;
}

export function scryptVerify(
  password: string,
  salt: Uint8Array,
  digest: string,
): boolean {
  const e = (s: string) => new TextEncoder().encode(s);
  return timingSafeEqual(e(scrypt(password, salt)), e(digest));
}

// The B64 encoding: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#b64
function b64(input: Uint8Array | Buffer): string {
  let encoded;

  if (input instanceof Uint8Array) {
    encoded = encodeBase64(input);
  } else {
    encoded = (input as Buffer).toString("base64");
  }

  return encoded.replace(/=+$/, "");
}

if (import.meta.main) {
  const [password, saltString, digest] = Deno.args;

  if (!password) {
    console.error(
      "usage: deno run scrypt.ts <password> [<salt>]        # generate",
    );
    console.error(
      "usage: deno run scrypt.ts <password> <salt> <digest> # verify",
    );
    Deno.exit(1);
  }

  let salt;

  if (saltString) {
    salt = new TextEncoder().encode(saltString);
  } else {
    salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
  }

  if (digest) {
    const matched = scryptVerify(password, salt, digest);
    console.log(matched);
    Deno.exit(matched ? 0 : 1);
  }

  console.log(scrypt(password, salt));
}
