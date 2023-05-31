import {CashAddressNetworkPrefix, encodeCashAddress, WalletImportFormatType, CashAddressType,
	hash160, sha256, binToHex, isHex, hexToBin, decodePrivateKeyWif, 
	secp256k1, TransactionCommon, importAuthenticationTemplate, TransactionTemplateFixed,
	authenticationTemplateP2pkhNonHd, authenticationTemplateToCompilerBCH,
	generateTransaction, encodeTransaction} from '@bitauth/libauth';
  const bchaddr =require('bchaddrjs') ;
const wif = require('wif')
import {Buffer} from "Buffer"

export function hexToWif(hexStr: string, network: CashAddressNetworkPrefix) {
	var privateKey = new Buffer(hexStr, 'hex')
	if(network == CashAddressNetworkPrefix.mainnet) {
		return wif.encode(128, privateKey, true)
	} else {
		return wif.encode(239, privateKey, true)
	}
} 

export function cashAddrToLegacy(cashAddr: string) {
	return bchaddr.toLegacyAddress(cashAddr);
} 

export interface PrivateKeyI {
  privateKey: Uint8Array;
  type: WalletImportFormatType;
}

export function hexSecretToHexPrivkey(text: string): string {
	if(!isHex(text)) {
		throw "Invalid Hex Secret";
	}
	const hashHex = binToHex(sha256.hash(hexToBin(text)));
	let n = BigInt("0x"+hashHex);
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
    token?: {
        amount: bigint;
        category: Uint8Array;
        nft?: {
            capability: "none" | "mutable" | "minting";
            commitment: Uint8Array;
        };
    }
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

