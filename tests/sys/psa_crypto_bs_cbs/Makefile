include ../Makefile.sys_common

USEMODULE += ztimer
USEMODULE += ztimer_usec
USEMODULE += psa_crypto

USEMODULE += psa_asymmetric
USEMODULE += psa_asymmetric_bs_cbs
USEMODULE += psa_asymmetric_bs_cbs_backend_c25519
USEMODULE += psa_asymmetric_ecc_ed25519
USEMODULE += psa_asymmetric_ecc_ed25519_custom_backend
USEMODULE += psa_asymmetric_ecc_ed25519_backend_c25519

USEMODULE += psa_hash
USEMODULE += psa_hash_sha_512
USEMODULE += psa_hash_sha_512_custom_backend
USEMODULE += psa_hash_sha_512_backend_riot
USEMODULE += prng_sha256prng

CFLAGS += -DCONFIG_PSA_ASYMMETRIC_KEYPAIR_COUNT=1

include $(RIOTBASE)/Makefile.include