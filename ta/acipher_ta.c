// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <inttypes.h>

#include <tee_internal_api.h>

#include <acipher_ta.h>

struct acipher {
	TEE_ObjectHandle key;
};

static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	
	void *outbuf;
	uint32_t outbuf_len;
	void *outmod;
	uint32_t outmod_len;
	outbuf = params[1].memref.buffer;
	outmod = params[2].memref.buffer;
	
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = params[0].value.a;

	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}

	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32,
		     key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}
	
	/* get the public value, as an octet string */
	
	IMSG("======== get the public value, as an octet string ========");
	
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_RSA_PUBLIC_EXPONENT, outbuf, &outbuf_len);
	if (res) {
		EMSG("TEE_GetObjectBufferAttribute with buffer: %#" PRIx32, res);
		return res;
	}
	
	params[1].memref.size = outbuf_len;
	IMSG("params[1].memref.size = %" PRId32, params[1].memref.size);
	IMSG("outbuf_len = %" PRId32, outbuf_len);
	
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_RSA_MODULUS, outmod, &outmod_len);
	if (res) {
		EMSG("TEE_GetObjectBufferAttribute with mod: %#" PRIx32, res);
		return res;
	}
	
	params[2].memref.size = outmod_len;
	IMSG("params[2].memref.size = %d", params[2].memref.size);
	IMSG("outmod_len = %" PRId32, outmod_len);
	
	IMSG("exp: %" PRIu8, (uint8_t *)outbuf);
	IMSG("explen = %" PRId32, outbuf_len);
	IMSG("mod: %" PRIu8, (uint8_t *)outmod);
	IMSG("modlen = %" PRId32, outmod_len);
	IMSG("params[1].memref.buffer: %" PRIu8, (uint8_t *)params[1].memref.buffer);
	IMSG("params[1].memref.buffer: %" PRIu8, (uint8_t *)params[2].memref.buffer);
	
	TEE_FreeTransientObject(state->key);
	state->key = key;
	return TEE_SUCCESS;
}

static TEE_Result cmd_hash(struct acipher *state, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	char *inbuf;
	uint32_t inbuf_len;
	char *hash;
	uint32_t hash_len;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;
		
	inbuf_len = params[0].memref.size;
	inbuf = TEE_Malloc(inbuf_len, 0);
	TEE_MemMove(inbuf, params[0].memref.buffer, inbuf_len);
	IMSG("inbuf: %s size = %" PRId32, inbuf, inbuf_len);
	
	hash_len = params[1].memref.size;
	hash = TEE_Malloc(hash_len, 0);
	IMSG("hash_len = %" PRId32, hash_len);
	
	/*
	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ, inbuf, inbuf_len);
	if (res) {
		EMSG("TEE_CheckMemoryAccessRights(TEE_ACCESS_READ): Not accessible!");
		return res;
	}
	IMSG("inbuf address: %p", inbuf);
	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE, hash, hash_len);
	if (res) {
		EMSG("TEE_CheckMemoryAccessRights(TEE_ACCESS_WRITE): Not accessible!");
		return res;
	}
	IMSG("hash address: %p", hash);
	*/
						
	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_DIGEST, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_ALG_SHA256, 0, res);
		return res;
	}
	
	DMSG("Start TEE_DigestDoFinal!");
	
	res = TEE_DigestDoFinal(op, inbuf, inbuf_len, hash, &hash_len);
	if (res) {
		EMSG("TEE_DigestDoFinal(output size: %" PRId32 "): %#" PRIx32, hash_len, res);
		return res;
	}
	
	DMSG("TEE_DigestDoFinal finish!");
	
	params[1].memref.size = hash_len;
	TEE_MemMove(params[1].memref.buffer, hash, hash_len);
	
	IMSG("hash: %s size = %" PRId32, hash, hash_len);
	
	TEE_FreeOperation(op);
	
	return res;
}

static TEE_Result cmd_sign(struct acipher *state, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	char *hash;
	uint32_t hash_len;
	char *sign;
	uint32_t sign_len;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;
	
	hash_len = params[0].memref.size;
	hash = TEE_Malloc(hash_len, 0);
	TEE_MemMove(hash, params[0].memref.buffer, hash_len);
	
	IMSG("hash: %s size = %" PRId32, hash, hash_len);
	
	sign_len = params[1].memref.size;
	sign = TEE_Malloc(sign_len, 0);
	
	IMSG("sign_len = %" PRId32, sign_len);
	
	res = TEE_GetObjectInfo1(state->key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}
	
	IMSG("keySize = %" PRId32, key_info.keySize);
	
	res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
					TEE_MODE_SIGN, key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_SIGN, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, 0, res);
		return res;
	}
	
	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}
	
	DMSG("Start TEE_AsymmetricSignDigest!");
	
	res = TEE_AsymmetricSignDigest(op, NULL, 0, hash, hash_len, sign, &sign_len);
	if (res) {
		EMSG("TEE_AsymmetricSignDigest(sign size = %" PRId32 "): %#" PRIx32, sign_len, res);
		return res;
	}
	
	DMSG("TEE_AsymmetricSignDigest finish!");
	
	IMSG("sign: %s size = %" PRId32, sign, sign_len);
	
	params[1].memref.size = sign_len;
	TEE_MemMove(params[1].memref.buffer, sign, sign_len);

out:
	TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_verify(struct acipher *state, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	char *sign;
	uint32_t sign_len;
	char *hash;
	uint32_t hash_len;
	TEE_OperationHandle op;
	TEE_ObjectHandle pub_key;
	uint32_t key_size = 1024;
	const uint32_t key_type = TEE_TYPE_RSA_PUBLIC_KEY;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;
	
	hash_len = params[0].memref.size;
	hash = TEE_Malloc(hash_len, 0);
	TEE_MemMove(hash, params[0].memref.buffer, hash_len);
	
	IMSG("hash: %s size = %" PRId32, hash, hash_len);
	
	sign_len = params[1].memref.size;
	sign = TEE_Malloc(sign_len, 0);
	TEE_MemMove(sign, params[1].memref.buffer, sign_len);
	
	IMSG("sign: %s size = %" PRId32, sign, sign_len);
	
	void *exp = params[2].memref.buffer;
	uint32_t explen = params[2].memref.size;
	void *mod = params[3].memref.buffer;
	uint32_t modlen = params[3].memref.size;
	
	IMSG("exp: %" PRIu8, (uint8_t *)exp);
	IMSG("explen = %" PRId32, explen);
	IMSG("mod: %" PRIu8, (uint8_t *)mod);
	IMSG("modlen = %" PRId32, modlen);
	
	TEE_Attribute attrs[2];
	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, mod, modlen);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, exp, explen);
	
	res = TEE_AllocateTransientObject(key_type, key_size, &pub_key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}
	
	res = TEE_PopulateTransientObject(pub_key, attrs, 2);
	if (res) {
		EMSG("TEE_PopulateTransientObject: %#" PRIx32, res);
		return res;
	}
	
	res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
					TEE_MODE_VERIFY, key_size);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_SIGN, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, 0, res);
		return res;
	}
	
	res = TEE_SetOperationKey(op, pub_key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}
	
	DMSG("Start TEE_AsymmetricVerifyDigest!");
	
	res = TEE_AsymmetricVerifyDigest(op, NULL, 0, hash, hash_len, sign, sign_len);
	if (res) {
		EMSG("TEE_AsymmetricSVerifyDigest(): %#" PRIx32, res);
		return res;
	} else { DMSG("TEE_AsymmetricSVerifyDigest Succeed!"); }
	
	DMSG("TEE_AsymmetricVerifyDigest finish!");

out:
	TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_enc(struct acipher *state, uint32_t pt,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *inbuf;
	uint32_t inbuf_len;
	void *outbuf;
	uint32_t outbuf_len;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT);
	
	TEE_ObjectHandle pub_key;
	uint32_t key_size = 1024;
	const uint32_t key_type = TEE_TYPE_RSA_PUBLIC_KEY;
	
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;

	/*res = TEE_GetObjectInfo1(state->key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}*/

	inbuf = params[0].memref.buffer;
	inbuf_len = params[0].memref.size;
	outbuf = params[1].memref.buffer;
	outbuf_len = params[1].memref.size;
	
	void *exp = params[2].memref.buffer;
	uint32_t explen = params[2].memref.size;
	void *mod = params[3].memref.buffer;
	uint32_t modlen = params[3].memref.size;
	
	IMSG("exp: %" PRIu8, (uint8_t *)exp);
	IMSG("explen = %" PRId32, explen);
	IMSG("mod: %" PRIu8, (uint8_t *)mod);
	IMSG("modlen = %" PRId32, modlen);
	
	/* Public Key */
	
	TEE_Attribute attrs[2];
	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, mod, modlen);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, exp, explen);
	
	res = TEE_AllocateTransientObject(key_type, key_size, &pub_key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}
	
	res = TEE_PopulateTransientObject(pub_key, attrs, 2);
	if (res) {
		EMSG("TEE_PopulateTransientObject: %#" PRIx32, res);
		return res;
	}
	
	/* === Public Key Operations Finish Line === */
	/*
	res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT,
				    key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.keySize, res);
		return res;
	}
	*/
	res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT,
				    key_size);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.keySize, res);
		return res;
	}
	
	res = TEE_SetOperationKey(op, pub_key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf,
				    &outbuf_len);
	if (res) {
		EMSG("TEE_AsymmetricEncrypt(%" PRId32 ", %" PRId32 "): %#" PRIx32, inbuf_len, params[1].memref.size, res);
	}
	
	params[1].memref.size = outbuf_len;
	

out:
	TEE_FreeOperation(op);
	return res;

}

static TEE_Result cmd_dec(struct acipher *state, uint32_t pt,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *inbuf;
	uint32_t inbuf_len;
	void *outbuf;
	uint32_t outbuf_len;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;

	res = TEE_GetObjectInfo1(state->key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

	inbuf = params[0].memref.buffer;
	inbuf_len = params[0].memref.size;
	outbuf = params[1].memref.buffer;
	outbuf_len = params[1].memref.size;

	res = TEE_AllocateOperation(&op, alg, TEE_MODE_DECRYPT,
				    key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_DECRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.keySize, res);
		return res;
	}

	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	res = TEE_AsymmetricDecrypt(op, NULL, 0, inbuf, inbuf_len, outbuf,
				    &outbuf_len);
	if (res) {
		EMSG("TEE_AsymmetricDecrypt(%" PRId32 ", %" PRId32 "): %#" PRIx32, inbuf_len, params[1].memref.size, res);
	}
	params[1].memref.size = outbuf_len;

out:
	TEE_FreeOperation(op);
	return res;

}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void **session)
{
	struct acipher *state;

	/*
	 * Allocate and init state for the session.
	 */
	state = TEE_Malloc(sizeof(*state), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->key = TEE_HANDLE_NULL;

	*session = state;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct acipher *state = session;

	TEE_FreeTransientObject(state->key);
	TEE_Free(state);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_ACIPHER_CMD_GEN_KEY:
		return cmd_gen_key(session, param_types, params);
	case TA_ACIPHER_CMD_HASH:
		return cmd_hash(session, param_types, params);
	case TA_ACIPHER_CMD_SIGN:
		return cmd_sign(session, param_types, params);
	case TA_ACIPHER_CMD_VERIFY:
		return cmd_verify(session, param_types, params);
	case TA_ACIPHER_CMD_ENCRYPT:
		return cmd_enc(session, param_types, params);
	case TA_ACIPHER_CMD_DECRYPT:
		return cmd_dec(session, param_types, params);
	default:
		EMSG("Command ID %#" PRIx32 " is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
