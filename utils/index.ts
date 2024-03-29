import {
  CashAddressNetworkPrefix, encodeCashAddress, WalletImportFormatType, CashAddressType,
  hash160, sha256, binToHex, isHex, hexToBin, decodePrivateKeyWif, disassembleBytecodeBCH,
  secp256k1, TransactionCommon, importAuthenticationTemplate, TransactionTemplateFixed,
  authenticationTemplateP2pkhNonHd, authenticationTemplateToCompilerBCH,
  generateTransaction, encodeTransaction, lockingBytecodeToCashAddress
} from '@bitauth/libauth';
import { hash256 } from '@cashscript/utils';
import { createSighashPreimage } from 'cashscript/dist/utils.js';
import { LibauthOutput } from 'cashscript/dist/interfaces.js';
const SignatureTemplate = require('cashscript/dist/SignatureTemplate');

const bchaddr = require('bchaddrjs');
const wif = require('wif')
import { Buffer } from "Buffer"
import { decode, encode } from "algo-msgpack-with-bigint";

export function hexToWif(hexStr: string, network: CashAddressNetworkPrefix) {
  var privateKey = new Buffer(hexStr, 'hex')
  if (network == CashAddressNetworkPrefix.mainnet) {
    return wif.encode(128, privateKey, true)
  } else {
    return wif.encode(239, privateKey, true)
  }
}

export function cashAddrToLegacy(cashAddr: string): string {
  return bchaddr.toLegacyAddress(cashAddr);
}

export interface PrivateKeyI {
  privateKey: Uint8Array;
  type: WalletImportFormatType;
}

export function uint8ArrayToHex(arr: Uint8Array): string {
  return binToHex(arr);
}

export function hexSecretToHexPrivkey(text: string): string {
  if (!isHex(text)) {
    throw "Invalid Hex Secret";
  }
  const hashHex = binToHex(sha256.hash(hexToBin(text)));
  let n = BigInt("0x" + hashHex);
  const m = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
  n = n % m;
  return n.toString(16);
}

export function textToUtf8Hex(text: string): string {
  const encoder = new TextEncoder();
  return binToHex(encoder.encode(text));
}

export function wifToPrivateKey(secret: string): Uint8Array {
  let wifResult = decodePrivateKeyWif(secret);

  if (typeof wifResult === "string") {
    throw Error(wifResult as string);
  }
  let resultData: PrivateKeyI = wifResult as PrivateKeyI;
  return resultData.privateKey;
}

export function deriveCashaddr(
  privateKey: Uint8Array,
  networkPrefix: CashAddressNetworkPrefix,
  addrType: CashAddressType
): string {
  let publicKey = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof publicKey === "string") {
    throw new Error(publicKey);
  }
  let pkh = hash160(publicKey);
  return encodeCashAddress(networkPrefix, addrType, pkh);
}

export interface SourceOutput {
  valueSatoshis: bigint;
  cashAddress?: string;
  token?: {
    amount: bigint;
    category: Uint8Array;
    nft?: {
      capability: "none" | "mutable" | "minting";
      commitment: Uint8Array;
    };
  }
}

export function extractOutputs(
  tx: TransactionCommon,
  network: "bitcoincash" | "bchtest" | "bchreg"
): SourceOutput[] {
  let outputs: SourceOutput[] = [];
  for (const out of tx.outputs) {
    let result = lockingBytecodeToCashAddress(out.lockingBytecode, network);
    if (typeof result !== "string") {
      result = disassembleBytecodeBCH(out.lockingBytecode)
    }
    const entry: SourceOutput = {
      valueSatoshis: out.valueSatoshis,
      cashAddress: result as string,
      token: out.token,
    };
    outputs.push(entry);
  }
  return outputs;
}

export function signTransactionForArg(
  decoded: TransactionCommon,
  sourceOutputs: LibauthOutput[],
  i: number,
  bytecode: Uint8Array,
  signingKey: Uint8Array
): Uint8Array[] {
  const template = new SignatureTemplate(signingKey);

  const hashtype = template.getHashType();
  const preimage = createSighashPreimage(decoded, sourceOutputs, i, bytecode, hashtype);
  const sighash = hash256(preimage);

  const signature = template.generateSignature(sighash);
  return signature
}

export function signUnsignedTransaction(
  decoded: TransactionCommon,
  sourceOutputs: SourceOutput[],
  signingKey: Uint8Array
): Uint8Array {

  const template = importAuthenticationTemplate(
    authenticationTemplateP2pkhNonHd
  );
  if (typeof template === "string") {
    throw new Error("Transaction template error");
  }

  const compiler = authenticationTemplateToCompilerBCH(template);
  const transactionTemplate: Readonly<
    TransactionTemplateFixed<typeof compiler>
  > = { ...decoded };
  for (const [index, input] of decoded.inputs.entries()) {
    if (input.unlockingBytecode.byteLength > 0) {
      continue;
    }

    const sourceOutput = sourceOutputs[index];
    transactionTemplate.inputs[index] = {
      ...input,
      unlockingBytecode: {
        compiler,
        data: {
          keys: { privateKeys: { key: signingKey } },
        },
        valueSatoshis: sourceOutput.valueSatoshis,
        script: "unlock",
        token: sourceOutput.token,
      },
    };
  }

  const result = generateTransaction(transactionTemplate);
  if (!result.success) {
    throw result.errors;
  }

  return encodeTransaction(result.transaction);
}

export function pack(tx: any) {
  return base64EncodeURL(encode(tx))
}

export function unPack(tx: string) {
  const result = decode(base64DecodeURL(tx))
  return JSON.parse(JSON.stringify(result), function (key, value) {
    if (!!value && typeof value === "object") {
      const keys = Object.keys(value)
      const values = Object.values(value)

      const b = keys.every((v: any) => typeof Number(v) === "number") && values.every((v: any) => typeof v === "number")
      if (!b) {
        return value
      }
      return new Uint8Array(values as any);
    }
    if (["token", "nft"].includes(key) && value === null) {
      return undefined
    }
    if (["valueSatoshis", "amount"].includes(key)) {
      return BigInt(value)
    }
    return value;
  })
}
function base64EncodeURL(byteArray: Uint8Array) {
  return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
    return String.fromCharCode(val);
  }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
}

function base64DecodeURL(b64urlstring: string) {
  return new Uint8Array(atob(b64urlstring.replace(/-/g, '+').replace(/_/g, '/')).split('').map(val => {
    return val.charCodeAt(0);
  }));
}

