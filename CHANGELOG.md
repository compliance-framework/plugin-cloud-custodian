# Changelog

## [0.3.1](https://github.com/compliance-framework/plugin-cloud-custodian/compare/v0.3.0...v0.3.1) (2026-10-22)


### Bug Fixes

* **deps:** bump agent to v0.9.3, workflows to v1.7.0 ([#46](https://github.com/compliance-framework/plugin-cloud-custodian/issues/46)) ([927e8e2](https://github.com/compliance-framework/plugin-cloud-custodian/commit/927e8e2759b531a91dd6b69bb723f53bace347e3))
* **deps:** update all non-major dependencies ([#48](https://github.com/compliance-framework/plugin-cloud-custodian/issues/48)) ([6e36239](https://github.com/compliance-framework/plugin-cloud-custodian/commit/6e362393a47c79b8f5f6cac23a4971225fd5bc7e))

## [0.3.0](https://github.com/compliance-framework/plugin-cloud-custodian/compare/v0.2.8...v0.3.0) (2026-10-14)


### Features

* parse AWS account configuration ([#30](https://github.com/compliance-framework/plugin-cloud-custodian/issues/30)) ([04b356b](https://github.com/compliance-framework/plugin-cloud-custodian/commit/04b356bbea3de6256fe1d98ba01ecb7997480948))
* run Cloud Custodian across AWS accounts ([#33](https://github.com/compliance-framework/plugin-cloud-custodian/issues/33)) ([fc1e1ba](https://github.com/compliance-framework/plugin-cloud-custodian/commit/fc1e1ba5aa38e6e6e03dcab8d6cf620bdaa9387d))
* run Cloud Custodian with an assumed role per AWS account ([#31](https://github.com/compliance-framework/plugin-cloud-custodian/issues/31)) ([ffbce5b](https://github.com/compliance-framework/plugin-cloud-custodian/commit/ffbce5b31a2e2169bc1ad4850e9f8b00bf08addc))


### Bug Fixes

* bump compliance-framework/agent to v0.9.1 and pass policy_data to policies ([#23](https://github.com/compliance-framework/plugin-cloud-custodian/issues/23)) ([0a26b0c](https://github.com/compliance-framework/plugin-cloud-custodian/commit/0a26b0ca4ed0f6023ce53c188137018b36758cd9))
* default debug payload dir under os.TempDir ([#22](https://github.com/compliance-framework/plugin-cloud-custodian/issues/22)) ([edbbeee](https://github.com/compliance-framework/plugin-cloud-custodian/commit/edbbeeef5de9045db6f89f02f1548abacc61f4d8))
* **deps:** bump agent to v0.9.2 ([#45](https://github.com/compliance-framework/plugin-cloud-custodian/issues/45)) ([c004007](https://github.com/compliance-framework/plugin-cloud-custodian/commit/c0040079721c9dc85c3c1149efd7b8edd70ee390))
* **deps:** update module golang.org/x/crypto to v0.56.0 [security] ([#38](https://github.com/compliance-framework/plugin-cloud-custodian/issues/38)) ([5083b68](https://github.com/compliance-framework/plugin-cloud-custodian/commit/5083b68190036122dc3081ff7168080f43cb3475))
* **deps:** update security fixes (gomod) [security] ([#44](https://github.com/compliance-framework/plugin-cloud-custodian/issues/44)) ([637ee04](https://github.com/compliance-framework/plugin-cloud-custodian/commit/637ee04e7d05f8293c9a2ce4a2c0ccc640b5174a))
* evaluate resources from every region ([#27](https://github.com/compliance-framework/plugin-cloud-custodian/issues/27)) ([f3a5847](https://github.com/compliance-framework/plugin-cloud-custodian/commit/f3a5847393becfe252e218bcaaf83dbadf4dfa7c))
* register Cloud Custodian subject templates as components ([#25](https://github.com/compliance-framework/plugin-cloud-custodian/issues/25)) ([a86a154](https://github.com/compliance-framework/plugin-cloud-custodian/commit/a86a1545f43dbd9fdc70aa879d5abf2596e7e39b))
* use stable ARN-first resource identities ([#28](https://github.com/compliance-framework/plugin-cloud-custodian/issues/28)) ([be7e519](https://github.com/compliance-framework/plugin-cloud-custodian/commit/be7e5192e8767ef3fd2c4381ed1e7b5d5f1a0f91))
