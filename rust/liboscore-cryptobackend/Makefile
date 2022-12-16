# Cargo-independent creation of cbindgen-created headers

c-headers/oscore_native/crypto_type.h:
	mkdir -p c-headers/oscore_native
	cbindgen -o $@
	sed -i $@ \
		-e 's/uintptr_t/size_t/g' \
		-e 's/typedef struct MaybeUninit_Algorithm MaybeUninit_Algorithm;/#define MaybeUninit_Algorithm oscore_crypto_aeadalg_t/g' \
		-e 's/typedef struct MaybeUninit_i32 MaybeUninit_i32;/#define MaybeUninit_i32 int32_t/g' \
		-e 's/typedef struct MaybeUninit_EncryptState MaybeUninit_EncryptState;/#define MaybeUninit_EncryptState oscore_crypto_aead_encryptstate_t/g' \
		-e 's/typedef struct MaybeUninit_DecryptState MaybeUninit_DecryptState;/#define MaybeUninit_DecryptState oscore_crypto_aead_decryptstate_t/g'

.PHONY: c-headers/oscore_native/crypto_type.h

clean:
	rm -rf c-headers/oscore_native/crypto_type.h
